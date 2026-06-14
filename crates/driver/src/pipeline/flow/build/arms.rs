use super::*;

impl ControlFlowBuilder {
    pub(super) fn lower_match_stmt(
        &mut self,
        current: CfgBlockId,
        scrutinee: &ast::Expr,
        arms: &[ast::MatchArm],
    ) -> Result<Option<CfgBlockId>> {
        let resolved_scrutinee = resolve_pattern_source_expr(
            scrutinee,
            &self.known_pattern_values,
            &self.pattern_source_functions,
            &self.variant_tags,
        )
        .unwrap_or_else(|| scrutinee.clone());
        if arms.is_empty() {
            self.terminate(current, ControlFlowTerminator::Unreachable)?;
            return Ok(None);
        }
        let scrutinee_name = self.next_temp_name("match");
        self.append_stmt(
            current,
            ast::Stmt::Let {
                name: scrutinee_name.clone(),
                mutable: false,
                ty: None,
                value: resolved_scrutinee.clone(),
            },
        )?;
        let all_returning = arms.iter().all(|arm| arm.returns);
        let end_block = if all_returning {
            None
        } else {
            Some(self.new_block())
        };
        let has_terminal_catchall = arms
            .last()
            .is_some_and(|arm| arm.guard.is_none() && pattern_is_catchall(&arm.pattern));
        let mut fallback_block = if let Some(end_block) = end_block {
            end_block
        } else if has_terminal_catchall {
            usize::MAX
        } else {
            let unreachable_block = self.new_block();
            self.terminate(unreachable_block, ControlFlowTerminator::Unreachable)?;
            unreachable_block
        };
        let mut switch_cases = Vec::<(i32, CfgBlockId)>::new();
        let mut switch_default = fallback_block;
        let mut switch_seen = HashSet::<i32>::new();
        let mut switch_viable = true;
        let mut arm_blocks = Vec::<CfgBlockId>::with_capacity(arms.len());
        for (index, arm) in arms.iter().enumerate() {
            let arm_block = self.new_block();
            arm_blocks.push(arm_block);
            if arm.guard.is_some() {
                switch_viable = false;
            } else if pattern_is_catchall(&arm.pattern) {
                if index + 1 != arms.len() || switch_default != fallback_block {
                    switch_viable = false;
                } else {
                    switch_default = arm_block;
                }
            } else if let Some(values) = pattern_switch_values(&arm.pattern, &self.variant_tags) {
                for value in values {
                    if !switch_seen.insert(value) {
                        switch_viable = false;
                        break;
                    }
                    switch_cases.push((value, arm_block));
                }
            } else {
                switch_viable = false;
            }
        }

        if switch_viable && !switch_cases.is_empty() {
            if switch_default == usize::MAX {
                let unreachable_block = self.new_block();
                self.terminate(unreachable_block, ControlFlowTerminator::Unreachable)?;
                switch_default = unreachable_block;
            }
            self.terminate(
                current,
                ControlFlowTerminator::Switch {
                    scrutinee: ast::Expr::Ident(scrutinee_name.clone()),
                    cases: switch_cases,
                    default_target: switch_default,
                },
            )?;
            for (arm, arm_block) in arms.iter().zip(arm_blocks.iter().copied()) {
                let binding_stmts = bindings_for_match_arm_pattern(
                    &arm.pattern,
                    &resolved_scrutinee,
                    &self.variant_tags,
                )?;
                for stmt in binding_stmts {
                    self.append_stmt(arm_block, stmt)?;
                }
                if arm.returns {
                    self.append_deferred_cleanup_from(arm_block, 0)?;
                    self.terminate(
                        arm_block,
                        ControlFlowTerminator::Return(Some(arm.value.clone())),
                    )?;
                } else {
                    let end_block = end_block.expect("non-returning match must have end block");
                    self.append_stmt(arm_block, ast::Stmt::Expr(arm.value.clone()))?;
                    self.terminate(
                        arm_block,
                        ControlFlowTerminator::Jump {
                            target: end_block,
                            edge: ControlFlowEdge::Normal,
                        },
                    )?;
                }
            }
            if let Some(end_block) = end_block {
                Ok(Some(end_block))
            } else {
                Ok(None)
            }
        } else {
            if fallback_block == usize::MAX {
                let unreachable_block = self.new_block();
                self.terminate(unreachable_block, ControlFlowTerminator::Unreachable)?;
                fallback_block = unreachable_block;
            }
            let mut dispatch = current;
            for (index, arm) in arms.iter().enumerate() {
                let arm_block = arm_blocks[index];
                let is_last = index + 1 == arms.len();
                let else_block = if is_last {
                    fallback_block
                } else {
                    self.new_block()
                };
                self.terminate(
                    dispatch,
                    ControlFlowTerminator::Branch {
                        condition: pattern_to_expr(
                            &scrutinee_name,
                            &arm.pattern,
                            &self.variant_tags,
                        ),
                        then_target: arm_block,
                        else_target: else_block,
                    },
                )?;
                let binding_stmts = bindings_for_match_arm_pattern(
                    &arm.pattern,
                    &resolved_scrutinee,
                    &self.variant_tags,
                )?;
                for stmt in binding_stmts {
                    self.append_stmt(arm_block, stmt)?;
                }
                let value_block = if let Some(guard) = &arm.guard {
                    let guarded_value_block = self.new_block();
                    self.terminate(
                        arm_block,
                        ControlFlowTerminator::Branch {
                            condition: guard.clone(),
                            then_target: guarded_value_block,
                            else_target: else_block,
                        },
                    )?;
                    guarded_value_block
                } else {
                    arm_block
                };
                if arm.returns {
                    self.append_deferred_cleanup_from(value_block, 0)?;
                    self.terminate(
                        value_block,
                        ControlFlowTerminator::Return(Some(arm.value.clone())),
                    )?;
                } else {
                    let end_block = end_block.expect("non-returning match must have end block");
                    self.append_stmt(value_block, ast::Stmt::Expr(arm.value.clone()))?;
                    self.terminate(
                        value_block,
                        ControlFlowTerminator::Jump {
                            target: end_block,
                            edge: ControlFlowEdge::Normal,
                        },
                    )?;
                }
                dispatch = else_block;
            }
            if let Some(end_block) = end_block {
                self.known_pattern_values.clear();
                Ok(Some(end_block))
            } else {
                Ok(None)
            }
        }
    }
}

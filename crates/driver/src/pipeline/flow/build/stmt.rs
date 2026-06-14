use super::*;

impl ControlFlowBuilder {
    pub(super) fn lower_let_stmt(
        &mut self,
        current: CfgBlockId,
        name: &str,
        mutable: bool,
        ty: &Option<ast::Type>,
        value: &ast::Expr,
    ) -> Result<()> {
        if let Some(resolved) = resolve_pattern_source_expr(
            value,
            &self.known_pattern_values,
            &self.pattern_source_functions,
            &self.variant_tags,
        ) {
            self.known_pattern_values.insert(name.to_string(), resolved);
        } else {
            self.known_pattern_values.remove(name);
        }
        self.append_stmt(
            current,
            ast::Stmt::Let {
                name: name.to_string(),
                mutable,
                ty: ty.clone(),
                value: value.clone(),
            },
        )
    }

    pub(super) fn lower_let_pattern_stmt(
        &mut self,
        current: CfgBlockId,
        pattern: &ast::Pattern,
        value: &ast::Expr,
        mutable: bool,
        ty: &Option<ast::Type>,
    ) -> Result<()> {
        let resolved = resolve_pattern_source_expr(
            value,
            &self.known_pattern_values,
            &self.pattern_source_functions,
            &self.variant_tags,
        )
        .unwrap_or_else(|| value.clone());
        self.append_stmt(
            current,
            ast::Stmt::LetPattern {
                pattern: pattern.clone(),
                value: resolved,
                mutable,
                ty: ty.clone(),
            },
        )
    }

    pub(super) fn lower_assign_stmt(
        &mut self,
        current: CfgBlockId,
        target: &str,
        value: &ast::Expr,
    ) -> Result<()> {
        if let Some(resolved) = resolve_pattern_source_expr(
            value,
            &self.known_pattern_values,
            &self.pattern_source_functions,
            &self.variant_tags,
        ) {
            self.known_pattern_values.insert(target.to_string(), resolved);
        } else {
            self.known_pattern_values.remove(target);
        }
        self.append_stmt(
            current,
            ast::Stmt::Assign {
                target: target.to_string(),
                value: value.clone(),
            },
        )
    }

    pub(super) fn lower_compound_assign_stmt(
        &mut self,
        current: CfgBlockId,
        target: &str,
        op: ast::BinaryOp,
        value: &ast::Expr,
    ) -> Result<()> {
        self.known_pattern_values.remove(target);
        self.append_stmt(
            current,
            ast::Stmt::CompoundAssign {
                target: target.to_string(),
                op,
                value: value.clone(),
            },
        )
    }

    pub(super) fn lower_return_stmt(
        &mut self,
        current: CfgBlockId,
        expr: Option<&ast::Expr>,
        scope_defer_base: usize,
    ) -> Result<Option<CfgBlockId>> {
        let return_expr = if let Some(expr) = expr {
            let temp = self.next_temp_name("return");
            self.append_stmt(
                current,
                ast::Stmt::Let {
                    name: temp.clone(),
                    mutable: false,
                    ty: None,
                    value: expr.clone(),
                },
            )?;
            Some(ast::Expr::Ident(temp))
        } else {
            None
        };
        self.append_deferred_cleanup_from(current, 0)?;
        self.active_defers.truncate(scope_defer_base);
        self.terminate(current, ControlFlowTerminator::Return(return_expr))?;
        Ok(None)
    }

    pub(super) fn lower_break_stmt(
        &mut self,
        current: CfgBlockId,
        scope_defer_base: usize,
    ) -> Result<Option<CfgBlockId>> {
        let active = self.active_loops.last().copied().ok_or_else(|| {
            anyhow!("control-flow lowering encountered `break` outside loop scope")
        })?;
        self.append_deferred_cleanup_from(current, active.defer_base)?;
        self.active_defers.truncate(scope_defer_base);
        self.terminate(
            current,
            ControlFlowTerminator::Jump {
                target: active.break_target,
                edge: ControlFlowEdge::Break {
                    loop_id: active.id,
                },
            },
        )?;
        Ok(None)
    }

    pub(super) fn lower_continue_stmt(
        &mut self,
        current: CfgBlockId,
        scope_defer_base: usize,
    ) -> Result<Option<CfgBlockId>> {
        let active = self.active_loops.last().copied().ok_or_else(|| {
            anyhow!("control-flow lowering encountered `continue` outside loop scope")
        })?;
        self.append_deferred_cleanup_from(current, active.defer_base)?;
        self.active_defers.truncate(scope_defer_base);
        self.terminate(
            current,
            ControlFlowTerminator::Jump {
                target: active.continue_target,
                edge: ControlFlowEdge::Continue {
                    loop_id: active.id,
                },
            },
        )?;
        Ok(None)
    }

    pub(super) fn lower_if_stmt(
        &mut self,
        current: CfgBlockId,
        condition: &ast::Expr,
        then_body: &[ast::Stmt],
        else_body: &[ast::Stmt],
    ) -> Result<Option<CfgBlockId>> {
        self.known_pattern_values.clear();
        let then_block = self.new_block();
        let else_block = self.new_block();
        self.terminate(
            current,
            ControlFlowTerminator::Branch {
                condition: condition.clone(),
                then_target: then_block,
                else_target: else_block,
            },
        )?;
        let then_tail = self.lower_stmt_seq(then_block, then_body)?;
        let else_tail = self.lower_stmt_seq(else_block, else_body)?;
        match (then_tail, else_tail) {
            (None, None) => Ok(None),
            (then_tail, else_tail) => {
                let cont = self.new_block();
                if let Some(tail) = then_tail {
                    self.terminate(
                        tail,
                        ControlFlowTerminator::Jump {
                            target: cont,
                            edge: ControlFlowEdge::Normal,
                        },
                    )?;
                }
                if let Some(tail) = else_tail {
                    self.terminate(
                        tail,
                        ControlFlowTerminator::Jump {
                            target: cont,
                            edge: ControlFlowEdge::Normal,
                        },
                    )?;
                }
                Ok(Some(cont))
            }
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum BackendKind {
    Llvm,
    Cranelift,
}

type CfgBlockId = usize;

#[derive(Debug, Clone)]
struct ControlFlowCfg {
    entry: CfgBlockId,
    blocks: Vec<ControlFlowBlock>,
    loops: Vec<ControlFlowLoop>,
}

#[derive(Debug, Clone)]
struct ControlFlowLoop {
    id: usize,
    break_target: CfgBlockId,
    continue_target: CfgBlockId,
}

#[derive(Debug, Clone)]
struct ControlFlowBlock {
    stmts: Vec<ast::Stmt>,
    terminator: ControlFlowTerminator,
}

#[derive(Debug, Clone)]
enum ControlFlowTerminator {
    Return(Option<ast::Expr>),
    Jump {
        target: CfgBlockId,
        edge: ControlFlowEdge,
    },
    Branch {
        condition: ast::Expr,
        then_target: CfgBlockId,
        else_target: CfgBlockId,
    },
    Switch {
        scrutinee: ast::Expr,
        cases: Vec<(i32, CfgBlockId)>,
        default_target: CfgBlockId,
    },
    Unreachable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ControlFlowEdge {
    Normal,
    LoopBack { loop_id: usize },
    Break { loop_id: usize },
    Continue { loop_id: usize },
}

#[derive(Clone, Copy)]
struct ActiveLoop {
    id: usize,
    break_target: CfgBlockId,
    continue_target: CfgBlockId,
    defer_base: usize,
}

#[derive(Clone)]
struct CfgBuildBlock {
    stmts: Vec<ast::Stmt>,
    terminator: Option<ControlFlowTerminator>,
}

struct ControlFlowBuilder {
    blocks: Vec<CfgBuildBlock>,
    loops: Vec<ControlFlowLoop>,
    active_loops: Vec<ActiveLoop>,
    active_defers: Vec<ast::Expr>,
    next_loop_id: usize,
    next_temp: usize,
    variant_tags: HashMap<String, i32>,
    pattern_source_functions: HashMap<String, PatternSourceFunction>,
    known_pattern_values: HashMap<String, ast::Expr>,
}

impl ControlFlowBuilder {
    fn new(
        variant_tags: HashMap<String, i32>,
        pattern_source_functions: HashMap<String, PatternSourceFunction>,
    ) -> Self {
        Self {
            blocks: vec![CfgBuildBlock {
                stmts: Vec::new(),
                terminator: None,
            }],
            loops: Vec::new(),
            active_loops: Vec::new(),
            active_defers: Vec::new(),
            next_loop_id: 0,
            next_temp: 0,
            variant_tags,
            pattern_source_functions,
            known_pattern_values: HashMap::new(),
        }
    }

    fn new_block(&mut self) -> CfgBlockId {
        let id = self.blocks.len();
        self.blocks.push(CfgBuildBlock {
            stmts: Vec::new(),
            terminator: None,
        });
        id
    }

    fn append_stmt(&mut self, block: CfgBlockId, stmt: ast::Stmt) -> Result<()> {
        let current = self
            .blocks
            .get_mut(block)
            .ok_or_else(|| anyhow!("control-flow builder referenced missing block {}", block))?;
        if current.terminator.is_some() {
            bail!("control-flow builder attempted to append into terminated block {block}");
        }
        current.stmts.push(stmt);
        Ok(())
    }

    fn terminate(&mut self, block: CfgBlockId, terminator: ControlFlowTerminator) -> Result<()> {
        let current = self
            .blocks
            .get_mut(block)
            .ok_or_else(|| anyhow!("control-flow builder referenced missing block {}", block))?;
        if current.terminator.is_some() {
            bail!("control-flow builder attempted to re-terminate block {block}");
        }
        current.terminator = Some(terminator);
        Ok(())
    }

    fn next_temp_name(&mut self, prefix: &str) -> String {
        let name = format!("__cfg_{prefix}_{}", self.next_temp);
        self.next_temp += 1;
        name
    }

    fn append_deferred_cleanup_from(&mut self, block: CfgBlockId, start: usize) -> Result<()> {
        if start > self.active_defers.len() {
            bail!(
                "control-flow builder requested defer cleanup from invalid index {} > {}",
                start,
                self.active_defers.len()
            );
        }
        let pending = self.active_defers[start..].to_vec();
        for expr in pending.into_iter().rev() {
            self.append_stmt(block, ast::Stmt::Expr(expr))?;
        }
        Ok(())
    }

    fn lower_stmt_seq(
        &mut self,
        mut current: CfgBlockId,
        body: &[ast::Stmt],
    ) -> Result<Option<CfgBlockId>> {
        let scope_defer_base = self.active_defers.len();
        for stmt in body {
            match stmt {
                ast::Stmt::Let {
                    name,
                    mutable,
                    ty,
                    value,
                } => {
                    if let Some(resolved) = resolve_pattern_source_expr(
                        value,
                        &self.known_pattern_values,
                        &self.pattern_source_functions,
                        &self.variant_tags,
                    ) {
                        self.known_pattern_values.insert(name.clone(), resolved);
                    } else {
                        self.known_pattern_values.remove(name);
                    }
                    self.append_stmt(
                        current,
                        ast::Stmt::Let {
                            name: name.clone(),
                            mutable: *mutable,
                            ty: ty.clone(),
                            value: value.clone(),
                        },
                    )?;
                }
                ast::Stmt::LetPattern {
                    pattern,
                    value,
                    mutable,
                    ty,
                } => {
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
                            mutable: *mutable,
                            ty: ty.clone(),
                        },
                    )?;
                }
                ast::Stmt::Assign { target, value } => {
                    if let Some(resolved) = resolve_pattern_source_expr(
                        value,
                        &self.known_pattern_values,
                        &self.pattern_source_functions,
                        &self.variant_tags,
                    ) {
                        self.known_pattern_values.insert(target.clone(), resolved);
                    } else {
                        self.known_pattern_values.remove(target);
                    }
                    self.append_stmt(
                        current,
                        ast::Stmt::Assign {
                            target: target.clone(),
                            value: value.clone(),
                        },
                    )?;
                }
                ast::Stmt::CompoundAssign { target, op, value } => {
                    self.known_pattern_values.remove(target);
                    self.append_stmt(
                        current,
                        ast::Stmt::CompoundAssign {
                            target: target.clone(),
                            op: *op,
                            value: value.clone(),
                        },
                    )?;
                }
                ast::Stmt::Defer(expr) => {
                    self.active_defers.push(expr.clone());
                }
                ast::Stmt::Requires(_) | ast::Stmt::Ensures(_) | ast::Stmt::Expr(_) => {
                    self.append_stmt(current, stmt.clone())?;
                }
                ast::Stmt::Return(expr) => {
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
                    return Ok(None);
                }
                ast::Stmt::Break(_) => {
                    let active = self.active_loops.last().copied().ok_or_else(|| {
                        anyhow!("control-flow lowering encountered `break` outside loop scope")
                    })?;
                    self.append_deferred_cleanup_from(current, active.defer_base)?;
                    self.active_defers.truncate(scope_defer_base);
                    self.terminate(
                        current,
                        ControlFlowTerminator::Jump {
                            target: active.break_target,
                            edge: ControlFlowEdge::Break { loop_id: active.id },
                        },
                    )?;
                    return Ok(None);
                }
                ast::Stmt::Continue => {
                    let active = self.active_loops.last().copied().ok_or_else(|| {
                        anyhow!("control-flow lowering encountered `continue` outside loop scope")
                    })?;
                    self.append_deferred_cleanup_from(current, active.defer_base)?;
                    self.active_defers.truncate(scope_defer_base);
                    self.terminate(
                        current,
                        ControlFlowTerminator::Jump {
                            target: active.continue_target,
                            edge: ControlFlowEdge::Continue { loop_id: active.id },
                        },
                    )?;
                    return Ok(None);
                }
                ast::Stmt::If {
                    condition,
                    then_body,
                    else_body,
                } => {
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
                        (None, None) => return Ok(None),
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
                            current = cont;
                        }
                    }
                }
                ast::Stmt::While { condition, body } => {
                    self.known_pattern_values.clear();
                    let head = self.new_block();
                    let loop_body = self.new_block();
                    let exit = self.new_block();
                    let loop_id = self.next_loop_id;
                    self.next_loop_id += 1;
                    self.loops.push(ControlFlowLoop {
                        id: loop_id,
                        break_target: exit,
                        continue_target: head,
                    });
                    self.terminate(
                        current,
                        ControlFlowTerminator::Jump {
                            target: head,
                            edge: ControlFlowEdge::Normal,
                        },
                    )?;
                    self.terminate(
                        head,
                        ControlFlowTerminator::Branch {
                            condition: condition.clone(),
                            then_target: loop_body,
                            else_target: exit,
                        },
                    )?;
                    self.active_loops.push(ActiveLoop {
                        id: loop_id,
                        break_target: exit,
                        continue_target: head,
                        defer_base: self.active_defers.len(),
                    });
                    let body_tail = self.lower_stmt_seq(loop_body, body)?;
                    let _ = self.active_loops.pop();
                    if let Some(tail) = body_tail {
                        self.terminate(
                            tail,
                            ControlFlowTerminator::Jump {
                                target: head,
                                edge: ControlFlowEdge::LoopBack { loop_id },
                            },
                        )?;
                    }
                    current = exit;
                }
                ast::Stmt::For {
                    init,
                    condition,
                    step,
                    body,
                } => {
                    self.known_pattern_values.clear();
                    if let Some(init) = init {
                        let Some(next) =
                            self.lower_stmt_seq(current, std::slice::from_ref(init.as_ref()))?
                        else {
                            return Ok(None);
                        };
                        current = next;
                    }
                    let head = self.new_block();
                    let loop_body = self.new_block();
                    let step_block = self.new_block();
                    let exit = self.new_block();
                    let loop_id = self.next_loop_id;
                    self.next_loop_id += 1;
                    self.loops.push(ControlFlowLoop {
                        id: loop_id,
                        break_target: exit,
                        continue_target: step_block,
                    });
                    self.terminate(
                        current,
                        ControlFlowTerminator::Jump {
                            target: head,
                            edge: ControlFlowEdge::Normal,
                        },
                    )?;
                    if let Some(condition) = condition {
                        self.terminate(
                            head,
                            ControlFlowTerminator::Branch {
                                condition: condition.clone(),
                                then_target: loop_body,
                                else_target: exit,
                            },
                        )?;
                    } else {
                        self.terminate(
                            head,
                            ControlFlowTerminator::Jump {
                                target: loop_body,
                                edge: ControlFlowEdge::LoopBack { loop_id },
                            },
                        )?;
                    }
                    self.active_loops.push(ActiveLoop {
                        id: loop_id,
                        break_target: exit,
                        continue_target: step_block,
                        defer_base: self.active_defers.len(),
                    });
                    let body_tail = self.lower_stmt_seq(loop_body, body)?;
                    let _ = self.active_loops.pop();
                    if let Some(tail) = body_tail {
                        self.terminate(
                            tail,
                            ControlFlowTerminator::Jump {
                                target: step_block,
                                edge: ControlFlowEdge::Normal,
                            },
                        )?;
                    }
                    if let Some(step) = step {
                        if let Some(step_tail) =
                            self.lower_stmt_seq(step_block, std::slice::from_ref(step.as_ref()))?
                        {
                            self.terminate(
                                step_tail,
                                ControlFlowTerminator::Jump {
                                    target: head,
                                    edge: ControlFlowEdge::LoopBack { loop_id },
                                },
                            )?;
                        }
                    } else {
                        self.terminate(
                            step_block,
                            ControlFlowTerminator::Jump {
                                target: head,
                                edge: ControlFlowEdge::LoopBack { loop_id },
                            },
                        )?;
                    }
                    current = exit;
                }
                ast::Stmt::ForIn {
                    binding,
                    iterable,
                    body,
                } => {
                    self.known_pattern_values.clear();
                    if let ast::Expr::Range {
                        start,
                        end,
                        inclusive,
                    } = iterable
                    {
                        self.append_stmt(
                            current,
                            ast::Stmt::Let {
                                name: binding.clone(),
                                mutable: true,
                                ty: Some(ast::Type::Int {
                                    signed: true,
                                    bits: 32,
                                }),
                                value: *start.clone(),
                            },
                        )?;
                        let head = self.new_block();
                        let loop_body = self.new_block();
                        let step_block = self.new_block();
                        let exit = self.new_block();
                        let loop_id = self.next_loop_id;
                        self.next_loop_id += 1;
                        self.loops.push(ControlFlowLoop {
                            id: loop_id,
                            break_target: exit,
                            continue_target: step_block,
                        });
                        self.terminate(
                            current,
                            ControlFlowTerminator::Jump {
                                target: head,
                                edge: ControlFlowEdge::Normal,
                            },
                        )?;
                        let cond_expr = ast::Expr::Binary {
                            op: if *inclusive {
                                ast::BinaryOp::Lte
                            } else {
                                ast::BinaryOp::Lt
                            },
                            left: Box::new(ast::Expr::Ident(binding.clone())),
                            right: Box::new(*end.clone()),
                        };
                        self.terminate(
                            head,
                            ControlFlowTerminator::Branch {
                                condition: cond_expr,
                                then_target: loop_body,
                                else_target: exit,
                            },
                        )?;
                        self.active_loops.push(ActiveLoop {
                            id: loop_id,
                            break_target: exit,
                            continue_target: step_block,
                            defer_base: self.active_defers.len(),
                        });
                        let body_tail = self.lower_stmt_seq(loop_body, body)?;
                        let _ = self.active_loops.pop();
                        if let Some(tail) = body_tail {
                            self.terminate(
                                tail,
                                ControlFlowTerminator::Jump {
                                    target: step_block,
                                    edge: ControlFlowEdge::Normal,
                                },
                            )?;
                        }
                        let step_stmt = ast::Stmt::CompoundAssign {
                            target: binding.clone(),
                            op: ast::BinaryOp::Add,
                            value: ast::Expr::Int(1),
                        };
                        self.append_stmt(step_block, step_stmt)?;
                        self.terminate(
                            step_block,
                            ControlFlowTerminator::Jump {
                                target: head,
                                edge: ControlFlowEdge::LoopBack { loop_id },
                            },
                        )?;
                        current = exit;
                    } else {
                        let body_block = self.new_block();
                        let exit = self.new_block();
                        let loop_id = self.next_loop_id;
                        self.next_loop_id += 1;
                        self.loops.push(ControlFlowLoop {
                            id: loop_id,
                            break_target: exit,
                            continue_target: exit,
                        });
                        self.terminate(
                            current,
                            ControlFlowTerminator::Jump {
                                target: body_block,
                                edge: ControlFlowEdge::Normal,
                            },
                        )?;
                        self.active_loops.push(ActiveLoop {
                            id: loop_id,
                            break_target: exit,
                            continue_target: exit,
                            defer_base: self.active_defers.len(),
                        });
                        let body_tail = self.lower_stmt_seq(body_block, body)?;
                        let _ = self.active_loops.pop();
                        if let Some(tail) = body_tail {
                            self.terminate(
                                tail,
                                ControlFlowTerminator::Jump {
                                    target: exit,
                                    edge: ControlFlowEdge::Normal,
                                },
                            )?;
                        }
                        current = exit;
                    }
                }
                ast::Stmt::Loop { body } => {
                    self.known_pattern_values.clear();
                    let head = self.new_block();
                    let has_loop_break = body_contains_break_at_depth(body, 0);
                    let exit = if has_loop_break {
                        Some(self.new_block())
                    } else {
                        None
                    };
                    let loop_id = self.next_loop_id;
                    self.next_loop_id += 1;
                    self.loops.push(ControlFlowLoop {
                        id: loop_id,
                        break_target: exit.unwrap_or(head),
                        continue_target: head,
                    });
                    self.terminate(
                        current,
                        ControlFlowTerminator::Jump {
                            target: head,
                            edge: ControlFlowEdge::Normal,
                        },
                    )?;
                    self.active_loops.push(ActiveLoop {
                        id: loop_id,
                        break_target: exit.unwrap_or(head),
                        continue_target: head,
                        defer_base: self.active_defers.len(),
                    });
                    let body_tail = self.lower_stmt_seq(head, body)?;
                    let _ = self.active_loops.pop();
                    if let Some(tail) = body_tail {
                        self.terminate(
                            tail,
                            ControlFlowTerminator::Jump {
                                target: head,
                                edge: ControlFlowEdge::LoopBack { loop_id },
                            },
                        )?;
                    }
                    if let Some(exit) = exit {
                        current = exit;
                    } else {
                        return Ok(None);
                    }
                }
                ast::Stmt::Match { scrutinee, arms } => {
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
                    let has_terminal_catchall = arms.last().is_some_and(|arm| {
                        arm.guard.is_none() && pattern_is_catchall(&arm.pattern)
                    });
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
                        } else if let Some(values) =
                            pattern_switch_values(&arm.pattern, &self.variant_tags)
                        {
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
                                let end_block =
                                    end_block.expect("non-returning match must have end block");
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
                            current = end_block;
                        } else {
                            return Ok(None);
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
                                let end_block =
                                    end_block.expect("non-returning match must have end block");
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
                            current = end_block;
                            self.known_pattern_values.clear();
                        } else {
                            return Ok(None);
                        }
                    }
                }
            }
        }
        self.append_deferred_cleanup_from(current, scope_defer_base)?;
        self.active_defers.truncate(scope_defer_base);
        Ok(Some(current))
    }

    fn finish(mut self, body: &[ast::Stmt]) -> Result<ControlFlowCfg> {
        if let Some(tail) = self.lower_stmt_seq(0, body)? {
            self.terminate(tail, ControlFlowTerminator::Return(None))?;
        }
        let blocks = self
            .blocks
            .into_iter()
            .enumerate()
            .map(|(id, block)| {
                let terminator = block.terminator.ok_or_else(|| {
                    anyhow!("control-flow builder emitted block {id} without terminator")
                })?;
                Ok(ControlFlowBlock {
                    stmts: block.stmts,
                    terminator,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(ControlFlowCfg {
            entry: 0,
            blocks,
            loops: self.loops,
        })
    }
}

fn build_control_flow_cfg(
    body: &[ast::Stmt],
    variant_tags: &HashMap<String, i32>,
    pattern_source_functions: &HashMap<String, PatternSourceFunction>,
) -> Result<ControlFlowCfg> {
    ControlFlowBuilder::new(variant_tags.clone(), pattern_source_functions.clone()).finish(body)
}

fn body_contains_break_at_depth(body: &[ast::Stmt], depth: usize) -> bool {
    body.iter()
        .any(|stmt| stmt_contains_break_at_depth(stmt, depth))
}

fn stmt_contains_break_at_depth(stmt: &ast::Stmt, depth: usize) -> bool {
    match stmt {
        ast::Stmt::Break(_) => depth == 0,
        ast::Stmt::If {
            then_body,
            else_body,
            ..
        } => {
            body_contains_break_at_depth(then_body, depth)
                || body_contains_break_at_depth(else_body, depth)
        }
        ast::Stmt::While { body, .. }
        | ast::Stmt::For { body, .. }
        | ast::Stmt::ForIn { body, .. }
        | ast::Stmt::Loop { body } => body_contains_break_at_depth(body, depth + 1),
        ast::Stmt::Match { .. }
        | ast::Stmt::Continue
        | ast::Stmt::Return(_)
        | ast::Stmt::Defer(_)
        | ast::Stmt::Requires(_)
        | ast::Stmt::Ensures(_)
        | ast::Stmt::Expr(_)
        | ast::Stmt::Let { .. }
        | ast::Stmt::LetPattern { .. }
        | ast::Stmt::Assign { .. }
        | ast::Stmt::CompoundAssign { .. } => false,
    }
}

fn pattern_to_expr(
    scrutinee_name: &str,
    pattern: &ast::Pattern,
    variant_tags: &HashMap<String, i32>,
) -> ast::Expr {
    match pattern {
        ast::Pattern::Wildcard | ast::Pattern::Ident(_) => ast::Expr::Bool(true),
        ast::Pattern::Int(value) => ast::Expr::Binary {
            op: ast::BinaryOp::Eq,
            left: Box::new(ast::Expr::Ident(scrutinee_name.to_string())),
            right: Box::new(ast::Expr::Int(*value)),
        },
        ast::Pattern::Bool(value) => ast::Expr::Binary {
            op: ast::BinaryOp::Eq,
            left: Box::new(ast::Expr::Ident(scrutinee_name.to_string())),
            right: Box::new(ast::Expr::Bool(*value)),
        },
        ast::Pattern::Variant {
            enum_name, variant, ..
        } => {
            let key = format!("{enum_name}::{variant}");
            ast::Expr::Binary {
                op: ast::BinaryOp::Eq,
                left: Box::new(ast::Expr::Ident(scrutinee_name.to_string())),
                right: Box::new(ast::Expr::Int(
                    variant_tag_for_key(&key, variant_tags) as i128
                )),
            }
        }
        ast::Pattern::Struct { .. } => ast::Expr::Bool(true),
        ast::Pattern::Tuple(_) => ast::Expr::Bool(true),
        ast::Pattern::Or(patterns) => {
            let mut iter = patterns.iter();
            let first = iter
                .next()
                .map(|pattern| pattern_to_expr(scrutinee_name, pattern, variant_tags))
                .unwrap_or(ast::Expr::Bool(true));
            iter.fold(first, |acc, pattern| ast::Expr::Binary {
                op: ast::BinaryOp::Or,
                left: Box::new(acc),
                right: Box::new(pattern_to_expr(scrutinee_name, pattern, variant_tags)),
            })
        }
    }
}

fn pattern_is_catchall(pattern: &ast::Pattern) -> bool {
    matches!(pattern, ast::Pattern::Wildcard | ast::Pattern::Ident(_))
}

fn pattern_switch_values(
    pattern: &ast::Pattern,
    variant_tags: &HashMap<String, i32>,
) -> Option<Vec<i32>> {
    match pattern {
        ast::Pattern::Int(value) => i32::try_from(*value).ok().map(|v| vec![v]),
        ast::Pattern::Bool(value) => Some(vec![if *value { 1 } else { 0 }]),
        ast::Pattern::Variant {
            enum_name, variant, ..
        } => {
            let key = format!("{enum_name}::{variant}");
            Some(vec![variant_tag_for_key(&key, variant_tags)])
        }
        ast::Pattern::Or(patterns) => {
            let mut out = Vec::new();
            for pattern in patterns {
                let mut values = pattern_switch_values(pattern, variant_tags)?;
                out.append(&mut values);
            }
            Some(out)
        }
        ast::Pattern::Wildcard
        | ast::Pattern::Ident(_)
        | ast::Pattern::Tuple(_)
        | ast::Pattern::Struct { .. } => None,
    }
}

fn pattern_has_variant_payload_bindings(pattern: &ast::Pattern) -> bool {
    match pattern {
        ast::Pattern::Variant {
            bindings,
            named_bindings,
            ..
        } => !bindings.is_empty() || !named_bindings.is_empty(),
        ast::Pattern::Or(patterns) => patterns.iter().any(pattern_has_variant_payload_bindings),
        ast::Pattern::Wildcard
        | ast::Pattern::Int(_)
        | ast::Pattern::Bool(_)
        | ast::Pattern::Tuple(_)
        | ast::Pattern::Struct { .. }
        | ast::Pattern::Ident(_) => false,
    }
}

fn pattern_has_struct_field_bindings(pattern: &ast::Pattern) -> bool {
    match pattern {
        ast::Pattern::Struct { fields, .. } => fields.iter().any(|(_, binding)| binding != "_"),
        ast::Pattern::Or(patterns) => patterns.iter().any(pattern_has_struct_field_bindings),
        ast::Pattern::Wildcard
        | ast::Pattern::Int(_)
        | ast::Pattern::Bool(_)
        | ast::Pattern::Tuple(_)
        | ast::Pattern::Ident(_)
        | ast::Pattern::Variant { .. } => false,
    }
}

fn pattern_has_tuple_bindings(items: &[ast::Pattern]) -> bool {
    items.iter().any(|item| match item {
        ast::Pattern::Wildcard => false,
        ast::Pattern::Int(_) | ast::Pattern::Bool(_) | ast::Pattern::Ident(_) => true,
        ast::Pattern::Tuple(nested) => pattern_has_tuple_bindings(nested),
        ast::Pattern::Struct { fields, .. } => fields.iter().any(|(_, binding)| binding != "_"),
        ast::Pattern::Variant {
            bindings,
            named_bindings,
            ..
        } => !bindings.is_empty() || !named_bindings.is_empty(),
        ast::Pattern::Or(patterns) => {
            patterns.iter().any(pattern_has_variant_payload_bindings)
                || patterns.iter().any(pattern_has_struct_field_bindings)
                || patterns.iter().any(|pattern| match pattern {
                    ast::Pattern::Tuple(nested) => pattern_has_tuple_bindings(nested),
                    ast::Pattern::Ident(_) | ast::Pattern::Int(_) | ast::Pattern::Bool(_) => true,
                    _ => false,
                })
        }
    })
}

fn pattern_matches_resolved_scrutinee(
    pattern: &ast::Pattern,
    scrutinee: &ast::Expr,
    variant_tags: &HashMap<String, i32>,
) -> bool {
    match pattern {
        ast::Pattern::Wildcard | ast::Pattern::Ident(_) => true,
        ast::Pattern::Int(expected) => {
            matches!(scrutinee, ast::Expr::Int(actual) if actual == expected)
        }
        ast::Pattern::Bool(expected) => {
            matches!(scrutinee, ast::Expr::Bool(actual) if actual == expected)
        }
        ast::Pattern::Variant {
            enum_name, variant, ..
        } => {
            if let ast::Expr::EnumInit {
                enum_name: value_enum,
                variant: value_variant,
                ..
            } = scrutinee
            {
                value_enum == enum_name && value_variant == variant
            } else if let ast::Expr::Int(value) = scrutinee {
                i32::try_from(*value).ok().is_some_and(|actual| {
                    let key = format!("{enum_name}::{variant}");
                    actual == variant_tag_for_key(&key, variant_tags)
                })
            } else {
                false
            }
        }
        ast::Pattern::Struct { name, .. } => matches!(
            scrutinee,
            ast::Expr::StructInit {
                name: value_name,
                ..
            } if value_name == name
        ),
        ast::Pattern::Tuple(items) => match scrutinee {
            ast::Expr::Tuple(values) => {
                items.len() == values.len()
                    && items.iter().zip(values.iter()).all(|(pattern, value)| {
                        pattern_matches_resolved_scrutinee(pattern, value, variant_tags)
                    })
            }
            _ => false,
        },
        ast::Pattern::Or(patterns) => patterns
            .iter()
            .any(|pattern| pattern_matches_resolved_scrutinee(pattern, scrutinee, variant_tags)),
    }
}

fn resolve_pattern_source_expr(
    expr: &ast::Expr,
    known_values: &HashMap<String, ast::Expr>,
    pattern_source_functions: &HashMap<String, PatternSourceFunction>,
    variant_tags: &HashMap<String, i32>,
) -> Option<ast::Expr> {
    fn extract_terminal_return_expr(body: &[ast::Stmt]) -> Option<&ast::Expr> {
        body.iter().rev().find_map(|stmt| match stmt {
            ast::Stmt::Return(Some(expr)) => Some(expr),
            _ => None,
        })
    }

    fn substitute_pattern_source_template(
        expr: &ast::Expr,
        bindings: &HashMap<String, ast::Expr>,
    ) -> ast::Expr {
        match expr {
            ast::Expr::Ident(name) => bindings
                .get(name)
                .cloned()
                .unwrap_or_else(|| ast::Expr::Ident(name.clone())),
            ast::Expr::Call { callee, args } => ast::Expr::Call {
                callee: callee.clone(),
                args: args
                    .iter()
                    .map(|arg| substitute_pattern_source_template(arg, bindings))
                    .collect(),
            },
            ast::Expr::FieldAccess { base, field } => ast::Expr::FieldAccess {
                base: Box::new(substitute_pattern_source_template(base, bindings)),
                field: field.clone(),
            },
            ast::Expr::StructInit { name, fields } => ast::Expr::StructInit {
                name: name.clone(),
                fields: fields
                    .iter()
                    .map(|(field, value)| {
                        (
                            field.clone(),
                            substitute_pattern_source_template(value, bindings),
                        )
                    })
                    .collect(),
            },
            ast::Expr::EnumInit {
                enum_name,
                variant,
                payload,
                named_payload,
            } => ast::Expr::EnumInit {
                enum_name: enum_name.clone(),
                variant: variant.clone(),
                payload: payload
                    .iter()
                    .map(|value| substitute_pattern_source_template(value, bindings))
                    .collect(),
                named_payload: named_payload
                    .iter()
                    .map(|(field, value)| {
                        (
                            field.clone(),
                            substitute_pattern_source_template(value, bindings),
                        )
                    })
                    .collect(),
            },
            ast::Expr::Group(inner) => ast::Expr::Group(Box::new(
                substitute_pattern_source_template(inner, bindings),
            )),
            ast::Expr::Tuple(items) => ast::Expr::Tuple(
                items
                    .iter()
                    .map(|item| substitute_pattern_source_template(item, bindings))
                    .collect(),
            ),
            ast::Expr::Await(inner) => ast::Expr::Await(Box::new(
                substitute_pattern_source_template(inner, bindings),
            )),
            ast::Expr::Discard(inner) => ast::Expr::Discard(Box::new(
                substitute_pattern_source_template(inner, bindings),
            )),
            ast::Expr::TryCatch {
                try_expr,
                catch_expr,
            } => ast::Expr::TryCatch {
                try_expr: Box::new(substitute_pattern_source_template(try_expr, bindings)),
                catch_expr: Box::new(substitute_pattern_source_template(catch_expr, bindings)),
            },
            ast::Expr::If {
                condition,
                then_expr,
                else_expr,
            } => ast::Expr::If {
                condition: Box::new(substitute_pattern_source_template(condition, bindings)),
                then_expr: Box::new(substitute_pattern_source_template(then_expr, bindings)),
                else_expr: Box::new(substitute_pattern_source_template(else_expr, bindings)),
            },
            ast::Expr::Match { scrutinee, arms } => ast::Expr::Match {
                scrutinee: Box::new(substitute_pattern_source_template(scrutinee, bindings)),
                arms: arms
                    .iter()
                    .map(|arm| ast::MatchArm {
                        pattern: arm.pattern.clone(),
                        guard: arm
                            .guard
                            .as_ref()
                            .map(|guard| substitute_pattern_source_template(guard, bindings)),
                        returns: arm.returns,
                        value: substitute_pattern_source_template(&arm.value, bindings),
                    })
                    .collect(),
            },
            ast::Expr::Range {
                start,
                end,
                inclusive,
            } => ast::Expr::Range {
                start: Box::new(substitute_pattern_source_template(start, bindings)),
                end: Box::new(substitute_pattern_source_template(end, bindings)),
                inclusive: *inclusive,
            },
            ast::Expr::ArrayLiteral(items) => ast::Expr::ArrayLiteral(
                items
                    .iter()
                    .map(|item| substitute_pattern_source_template(item, bindings))
                    .collect(),
            ),
            ast::Expr::ObjectLiteral(fields) => ast::Expr::ObjectLiteral(
                fields
                    .iter()
                    .map(|(field, value)| {
                        (
                            field.clone(),
                            substitute_pattern_source_template(value, bindings),
                        )
                    })
                    .collect(),
            ),
            ast::Expr::Index { base, index } => ast::Expr::Index {
                base: Box::new(substitute_pattern_source_template(base, bindings)),
                index: Box::new(substitute_pattern_source_template(index, bindings)),
            },
            ast::Expr::Unary { op, expr } => ast::Expr::Unary {
                op: *op,
                expr: Box::new(substitute_pattern_source_template(expr, bindings)),
            },
            ast::Expr::Binary { op, left, right } => ast::Expr::Binary {
                op: *op,
                left: Box::new(substitute_pattern_source_template(left, bindings)),
                right: Box::new(substitute_pattern_source_template(right, bindings)),
            },
            ast::Expr::Closure {
                params,
                return_type,
                body,
            } => ast::Expr::Closure {
                params: params.clone(),
                return_type: return_type.clone(),
                body: body.clone(),
            },
            ast::Expr::UnsafeBlock { body, meta } => ast::Expr::UnsafeBlock {
                body: body.clone(),
                meta: meta.clone(),
            },
            ast::Expr::While { condition, body } => ast::Expr::While {
                condition: Box::new(substitute_pattern_source_template(condition, bindings)),
                body: body.clone(),
            },
            ast::Expr::For {
                init,
                condition,
                step,
                body,
            } => ast::Expr::For {
                init: init.clone(),
                condition: condition
                    .as_ref()
                    .map(|value| Box::new(substitute_pattern_source_template(value, bindings))),
                step: step.clone(),
                body: body.clone(),
            },
            ast::Expr::ForIn {
                binding,
                iterable,
                body,
            } => ast::Expr::ForIn {
                binding: binding.clone(),
                iterable: Box::new(substitute_pattern_source_template(iterable, bindings)),
                body: body.clone(),
            },
            ast::Expr::Loop { body } => ast::Expr::Loop { body: body.clone() },
            ast::Expr::Break(value) => ast::Expr::Break(
                value
                    .as_ref()
                    .map(|value| Box::new(substitute_pattern_source_template(value, bindings))),
            ),
            ast::Expr::Return(value) => ast::Expr::Return(
                value
                    .as_ref()
                    .map(|value| Box::new(substitute_pattern_source_template(value, bindings))),
            ),
            ast::Expr::Int(_)
            | ast::Expr::Float { .. }
            | ast::Expr::Char(_)
            | ast::Expr::Bool(_)
            | ast::Expr::Str(_)
            | ast::Expr::Continue => expr.clone(),
        }
    }

    fn resolve_pattern_source_function_call<ResolveFn, EvalScalarFn, SubstituteFn>(
        function: &PatternSourceFunction,
        args: &[ast::Expr],
        _known_values: &HashMap<String, ast::Expr>,
        pattern_source_functions: &HashMap<String, PatternSourceFunction>,
        variant_tags: &HashMap<String, i32>,
        depth: usize,
        substitute_pattern_source_template: &SubstituteFn,
        resolve_inner: &ResolveFn,
        eval_resolved_scalar_expr: &EvalScalarFn,
    ) -> Option<ast::Expr>
    where
        ResolveFn: Fn(
            &ast::Expr,
            &HashMap<String, ast::Expr>,
            &HashMap<String, PatternSourceFunction>,
            &HashMap<String, i32>,
            usize,
        ) -> Option<ast::Expr>,
        EvalScalarFn: Fn(
            &ast::Expr,
            &HashMap<String, ast::Expr>,
            &HashMap<String, PatternSourceFunction>,
            &HashMap<String, i32>,
            usize,
        ) -> Option<ast::Expr>,
        SubstituteFn: Fn(&ast::Expr, &HashMap<String, ast::Expr>) -> ast::Expr,
    {
        if function.params.len() != args.len() || depth > 32 {
            return None;
        }
        let mut env = function
            .params
            .iter()
            .cloned()
            .zip(args.iter().cloned())
            .collect::<HashMap<_, _>>();
        for stmt in &function.body {
            match stmt {
                ast::Stmt::Let { name, value, .. } => {
                    let expanded = substitute_pattern_source_template(value, &env);
                    env.insert(name.clone(), expanded);
                }
                ast::Stmt::Assign { target, value } => {
                    let expanded = substitute_pattern_source_template(value, &env);
                    env.insert(target.clone(), expanded);
                }
                ast::Stmt::Return(Some(expr)) => {
                    let expanded = substitute_pattern_source_template(expr, &env);
                    return Some(expanded);
                }
                ast::Stmt::If {
                    condition,
                    then_body,
                    else_body,
                } => {
                    let expanded_condition = substitute_pattern_source_template(condition, &env);
                    let condition = eval_resolved_scalar_expr(
                        &expanded_condition,
                        &env,
                        pattern_source_functions,
                        variant_tags,
                        depth + 1,
                    )?;
                    let branch = match condition {
                        ast::Expr::Bool(true) => then_body,
                        ast::Expr::Bool(false) => else_body,
                        ast::Expr::Int(value) => {
                            if value != 0 {
                                then_body
                            } else {
                                else_body
                            }
                        }
                        _ => return None,
                    };
                    if let Some(value) = resolve_pattern_source_stmt_branch(
                        branch,
                        &env,
                        pattern_source_functions,
                        variant_tags,
                        depth + 1,
                        substitute_pattern_source_template,
                        resolve_inner,
                        eval_resolved_scalar_expr,
                    ) {
                        return Some(value);
                    }
                }
                _ => {}
            }
        }
        extract_terminal_return_expr(&function.body)
            .map(|expr| substitute_pattern_source_template(expr, &env))
    }

    fn resolve_pattern_source_stmt_branch<ResolveFn, EvalScalarFn, SubstituteFn>(
        body: &[ast::Stmt],
        parent_env: &HashMap<String, ast::Expr>,
        pattern_source_functions: &HashMap<String, PatternSourceFunction>,
        variant_tags: &HashMap<String, i32>,
        depth: usize,
        substitute_pattern_source_template: &SubstituteFn,
        resolve_inner: &ResolveFn,
        eval_resolved_scalar_expr: &EvalScalarFn,
    ) -> Option<ast::Expr>
    where
        ResolveFn: Fn(
            &ast::Expr,
            &HashMap<String, ast::Expr>,
            &HashMap<String, PatternSourceFunction>,
            &HashMap<String, i32>,
            usize,
        ) -> Option<ast::Expr>,
        EvalScalarFn: Fn(
            &ast::Expr,
            &HashMap<String, ast::Expr>,
            &HashMap<String, PatternSourceFunction>,
            &HashMap<String, i32>,
            usize,
        ) -> Option<ast::Expr>,
        SubstituteFn: Fn(&ast::Expr, &HashMap<String, ast::Expr>) -> ast::Expr,
    {
        if depth > 32 {
            return None;
        }
        let mut env = parent_env.clone();
        for stmt in body {
            match stmt {
                ast::Stmt::Let { name, value, .. } => {
                    env.insert(
                        name.clone(),
                        substitute_pattern_source_template(value, &env),
                    );
                }
                ast::Stmt::Assign { target, value } => {
                    env.insert(
                        target.clone(),
                        substitute_pattern_source_template(value, &env),
                    );
                }
                ast::Stmt::Return(Some(expr)) => {
                    return Some(substitute_pattern_source_template(expr, &env));
                }
                ast::Stmt::Expr(expr) => {
                    if let Some(resolved) = resolve_inner(
                        &substitute_pattern_source_template(expr, &env),
                        &env,
                        pattern_source_functions,
                        variant_tags,
                        depth + 1,
                    ) {
                        if matches!(
                            resolved,
                            ast::Expr::Tuple(_)
                                | ast::Expr::StructInit { .. }
                                | ast::Expr::EnumInit { .. }
                        ) {
                            return Some(resolved);
                        }
                    }
                }
                ast::Stmt::If {
                    condition,
                    then_body,
                    else_body,
                } => {
                    let condition = substitute_pattern_source_template(condition, &env);
                    let condition = eval_resolved_scalar_expr(
                        &condition,
                        &env,
                        pattern_source_functions,
                        variant_tags,
                        depth + 1,
                    )?;
                    let branch = match condition {
                        ast::Expr::Bool(true) => then_body,
                        ast::Expr::Bool(false) => else_body,
                        ast::Expr::Int(value) => {
                            if value != 0 {
                                then_body
                            } else {
                                else_body
                            }
                        }
                        _ => return None,
                    };
                    return resolve_pattern_source_stmt_branch(
                        branch,
                        &env,
                        pattern_source_functions,
                        variant_tags,
                        depth + 1,
                        substitute_pattern_source_template,
                        resolve_inner,
                        eval_resolved_scalar_expr,
                    );
                }
                _ => return None,
            }
        }
        None
    }

    fn eval_resolved_scalar_expr(
        expr: &ast::Expr,
        known_values: &HashMap<String, ast::Expr>,
        pattern_source_functions: &HashMap<String, PatternSourceFunction>,
        variant_tags: &HashMap<String, i32>,
        depth: usize,
    ) -> Option<ast::Expr> {
        if depth > 32 {
            return None;
        }
        match expr {
            ast::Expr::Int(_) | ast::Expr::Bool(_) => Some(expr.clone()),
            ast::Expr::Group(inner) => eval_resolved_scalar_expr(
                inner,
                known_values,
                pattern_source_functions,
                variant_tags,
                depth + 1,
            ),
            ast::Expr::Ident(name) => {
                let value = known_values.get(name)?;
                eval_resolved_scalar_expr(
                    value,
                    known_values,
                    pattern_source_functions,
                    variant_tags,
                    depth + 1,
                )
            }
            ast::Expr::Call { callee, args } => {
                let function = pattern_source_functions.get(callee)?;
                if function.params.len() != args.len() {
                    return None;
                }
                if let Some(resolved) = resolve_pattern_source_function_call(
                    function,
                    args,
                    known_values,
                    pattern_source_functions,
                    variant_tags,
                    depth + 1,
                    &substitute_pattern_source_template,
                    &resolve_inner,
                    &eval_resolved_scalar_expr,
                ) {
                    return eval_resolved_scalar_expr(
                        &resolved,
                        known_values,
                        pattern_source_functions,
                        variant_tags,
                        depth + 1,
                    );
                }
                let params = &function.params;
                let template = extract_terminal_return_expr(&function.body)?;
                if params.len() != args.len() {
                    return None;
                }
                let bindings = params
                    .iter()
                    .cloned()
                    .zip(args.iter().cloned())
                    .collect::<HashMap<_, _>>();
                let expanded = substitute_pattern_source_template(template, &bindings);
                eval_resolved_scalar_expr(
                    &expanded,
                    known_values,
                    pattern_source_functions,
                    variant_tags,
                    depth + 1,
                )
            }
            ast::Expr::FieldAccess { base, field } => {
                let resolved_base = resolve_inner(
                    base,
                    known_values,
                    pattern_source_functions,
                    variant_tags,
                    depth + 1,
                )?;
                let field_expr = resolve_field_expr(&resolved_base, field)?;
                eval_resolved_scalar_expr(
                    &field_expr,
                    known_values,
                    pattern_source_functions,
                    variant_tags,
                    depth + 1,
                )
            }
            ast::Expr::Unary { op, expr } => {
                let value = eval_resolved_scalar_expr(
                    expr,
                    known_values,
                    pattern_source_functions,
                    variant_tags,
                    depth + 1,
                )?;
                match (op, value) {
                    (ast::UnaryOp::Not, ast::Expr::Bool(value)) => Some(ast::Expr::Bool(!value)),
                    (ast::UnaryOp::Not, ast::Expr::Int(value)) => Some(ast::Expr::Bool(value == 0)),
                    (ast::UnaryOp::Neg, ast::Expr::Int(value)) => Some(ast::Expr::Int(-value)),
                    (ast::UnaryOp::Plus, ast::Expr::Int(value)) => Some(ast::Expr::Int(value)),
                    _ => None,
                }
            }
            ast::Expr::Binary { op, left, right } => {
                let left = eval_resolved_scalar_expr(
                    left,
                    known_values,
                    pattern_source_functions,
                    variant_tags,
                    depth + 1,
                )?;
                let right = eval_resolved_scalar_expr(
                    right,
                    known_values,
                    pattern_source_functions,
                    variant_tags,
                    depth + 1,
                )?;
                match (op, left, right) {
                    (ast::BinaryOp::Add, ast::Expr::Int(a), ast::Expr::Int(b)) => {
                        Some(ast::Expr::Int(a + b))
                    }
                    (ast::BinaryOp::Sub, ast::Expr::Int(a), ast::Expr::Int(b)) => {
                        Some(ast::Expr::Int(a - b))
                    }
                    (ast::BinaryOp::Mul, ast::Expr::Int(a), ast::Expr::Int(b)) => {
                        Some(ast::Expr::Int(a * b))
                    }
                    (ast::BinaryOp::Div, ast::Expr::Int(a), ast::Expr::Int(b)) => {
                        (b != 0).then_some(ast::Expr::Int(a / b))
                    }
                    (ast::BinaryOp::Mod, ast::Expr::Int(a), ast::Expr::Int(b)) => {
                        (b != 0).then_some(ast::Expr::Int(a % b))
                    }
                    (ast::BinaryOp::Eq, ast::Expr::Int(a), ast::Expr::Int(b)) => {
                        Some(ast::Expr::Bool(a == b))
                    }
                    (ast::BinaryOp::Neq, ast::Expr::Int(a), ast::Expr::Int(b)) => {
                        Some(ast::Expr::Bool(a != b))
                    }
                    (ast::BinaryOp::Lt, ast::Expr::Int(a), ast::Expr::Int(b)) => {
                        Some(ast::Expr::Bool(a < b))
                    }
                    (ast::BinaryOp::Lte, ast::Expr::Int(a), ast::Expr::Int(b)) => {
                        Some(ast::Expr::Bool(a <= b))
                    }
                    (ast::BinaryOp::Gt, ast::Expr::Int(a), ast::Expr::Int(b)) => {
                        Some(ast::Expr::Bool(a > b))
                    }
                    (ast::BinaryOp::Gte, ast::Expr::Int(a), ast::Expr::Int(b)) => {
                        Some(ast::Expr::Bool(a >= b))
                    }
                    (ast::BinaryOp::Eq, ast::Expr::Bool(a), ast::Expr::Bool(b)) => {
                        Some(ast::Expr::Bool(a == b))
                    }
                    (ast::BinaryOp::Neq, ast::Expr::Bool(a), ast::Expr::Bool(b)) => {
                        Some(ast::Expr::Bool(a != b))
                    }
                    (ast::BinaryOp::And, ast::Expr::Bool(a), ast::Expr::Bool(b)) => {
                        Some(ast::Expr::Bool(a && b))
                    }
                    (ast::BinaryOp::Or, ast::Expr::Bool(a), ast::Expr::Bool(b)) => {
                        Some(ast::Expr::Bool(a || b))
                    }
                    _ => None,
                }
            }
            ast::Expr::If {
                condition,
                then_expr,
                else_expr,
            } => {
                let condition = eval_resolved_scalar_expr(
                    condition,
                    known_values,
                    pattern_source_functions,
                    variant_tags,
                    depth + 1,
                )?;
                match condition {
                    ast::Expr::Bool(true) => eval_resolved_scalar_expr(
                        then_expr,
                        known_values,
                        pattern_source_functions,
                        variant_tags,
                        depth + 1,
                    ),
                    ast::Expr::Bool(false) => eval_resolved_scalar_expr(
                        else_expr,
                        known_values,
                        pattern_source_functions,
                        variant_tags,
                        depth + 1,
                    ),
                    ast::Expr::Int(value) => {
                        let branch = if value != 0 { then_expr } else { else_expr };
                        eval_resolved_scalar_expr(
                            branch,
                            known_values,
                            pattern_source_functions,
                            variant_tags,
                            depth + 1,
                        )
                    }
                    _ => None,
                }
            }
            ast::Expr::Match { scrutinee, arms } => {
                let resolved_scrutinee = resolve_inner(
                    scrutinee,
                    known_values,
                    pattern_source_functions,
                    variant_tags,
                    depth + 1,
                )
                .or_else(|| {
                    eval_resolved_scalar_expr(
                        scrutinee,
                        known_values,
                        pattern_source_functions,
                        variant_tags,
                        depth + 1,
                    )
                })?;
                for arm in arms {
                    if !pattern_matches_resolved_scrutinee(
                        &arm.pattern,
                        &resolved_scrutinee,
                        variant_tags,
                    ) {
                        continue;
                    }
                    let mut guard_values = known_values.clone();
                    if let Ok(binding_stmts) = bindings_for_match_arm_pattern(
                        &arm.pattern,
                        &resolved_scrutinee,
                        variant_tags,
                    ) {
                        for stmt in binding_stmts {
                            if let ast::Stmt::Let { name, value, .. } = stmt {
                                guard_values.insert(name, value);
                            }
                        }
                    }
                    if let Some(guard) = &arm.guard {
                        let Some(guard_value) = eval_resolved_scalar_expr(
                            guard,
                            &guard_values,
                            pattern_source_functions,
                            variant_tags,
                            depth + 1,
                        ) else {
                            continue;
                        };
                        match guard_value {
                            ast::Expr::Bool(true) => {}
                            ast::Expr::Int(value) if value != 0 => {}
                            _ => continue,
                        }
                    }
                    return eval_resolved_scalar_expr(
                        &arm.value,
                        &guard_values,
                        pattern_source_functions,
                        variant_tags,
                        depth + 1,
                    );
                }
                None
            }
            _ => None,
        }
    }

    fn resolve_inner(
        expr: &ast::Expr,
        known_values: &HashMap<String, ast::Expr>,
        pattern_source_functions: &HashMap<String, PatternSourceFunction>,
        variant_tags: &HashMap<String, i32>,
        depth: usize,
    ) -> Option<ast::Expr> {
        if depth > 32 {
            return None;
        }
        match expr {
            ast::Expr::EnumInit { .. } | ast::Expr::StructInit { .. } | ast::Expr::Tuple(_) => {
                Some(expr.clone())
            }
            ast::Expr::Group(inner) => resolve_inner(
                inner,
                known_values,
                pattern_source_functions,
                variant_tags,
                depth + 1,
            ),
            ast::Expr::Ident(name) => known_values.get(name).and_then(|value| {
                resolve_inner(
                    value,
                    known_values,
                    pattern_source_functions,
                    variant_tags,
                    depth + 1,
                )
            }),
            ast::Expr::Call { callee, args } => {
                let function = pattern_source_functions.get(callee)?;
                let resolved = resolve_pattern_source_function_call(
                    function,
                    args,
                    known_values,
                    pattern_source_functions,
                    variant_tags,
                    depth + 1,
                    &substitute_pattern_source_template,
                    &resolve_inner,
                    &eval_resolved_scalar_expr,
                )?;
                resolve_inner(
                    &resolved,
                    known_values,
                    pattern_source_functions,
                    variant_tags,
                    depth + 1,
                )
            }
            ast::Expr::FieldAccess { base, field } => {
                let resolved_base = resolve_inner(
                    base,
                    known_values,
                    pattern_source_functions,
                    variant_tags,
                    depth + 1,
                )?;
                let field_expr = resolve_field_expr(&resolved_base, field)?;
                resolve_inner(
                    &field_expr,
                    known_values,
                    pattern_source_functions,
                    variant_tags,
                    depth + 1,
                )
                .or(Some(field_expr))
            }
            ast::Expr::If {
                condition,
                then_expr,
                else_expr,
            } => {
                let condition = eval_resolved_scalar_expr(
                    condition,
                    known_values,
                    pattern_source_functions,
                    variant_tags,
                    depth + 1,
                )?;
                let branch = match condition {
                    ast::Expr::Bool(true) => then_expr,
                    ast::Expr::Bool(false) => else_expr,
                    ast::Expr::Int(value) => {
                        if value != 0 {
                            then_expr
                        } else {
                            else_expr
                        }
                    }
                    _ => return None,
                };
                resolve_inner(
                    branch,
                    known_values,
                    pattern_source_functions,
                    variant_tags,
                    depth + 1,
                )
            }
            ast::Expr::Match { scrutinee, arms } => {
                let resolved_scrutinee = resolve_inner(
                    scrutinee,
                    known_values,
                    pattern_source_functions,
                    variant_tags,
                    depth + 1,
                )
                .or_else(|| {
                    eval_resolved_scalar_expr(
                        scrutinee,
                        known_values,
                        pattern_source_functions,
                        variant_tags,
                        depth + 1,
                    )
                })?;
                for arm in arms {
                    if !pattern_matches_resolved_scrutinee(
                        &arm.pattern,
                        &resolved_scrutinee,
                        variant_tags,
                    ) {
                        continue;
                    }
                    let mut arm_values = known_values.clone();
                    if let Ok(binding_stmts) = bindings_for_match_arm_pattern(
                        &arm.pattern,
                        &resolved_scrutinee,
                        variant_tags,
                    ) {
                        for stmt in binding_stmts {
                            if let ast::Stmt::Let { name, value, .. } = stmt {
                                arm_values.insert(name, value);
                            }
                        }
                    }
                    if let Some(guard) = &arm.guard {
                        let guard = eval_resolved_scalar_expr(
                            guard,
                            &arm_values,
                            pattern_source_functions,
                            variant_tags,
                            depth + 1,
                        )?;
                        match guard {
                            ast::Expr::Bool(true) => {}
                            ast::Expr::Int(value) if value != 0 => {}
                            _ => continue,
                        }
                    }
                    return resolve_inner(
                        &arm.value,
                        &arm_values,
                        pattern_source_functions,
                        variant_tags,
                        depth + 1,
                    );
                }
                None
            }
            _ => None,
        }
    }

    resolve_inner(
        expr,
        known_values,
        pattern_source_functions,
        variant_tags,
        0,
    )
}

fn resolve_field_expr(base: &ast::Expr, field: &str) -> Option<ast::Expr> {
    match base {
        ast::Expr::StructInit { fields, .. } => fields.iter().find_map(|(name, value)| {
            if name == field {
                Some(value.clone())
            } else {
                None
            }
        }),
        ast::Expr::Range {
            start,
            end,
            inclusive,
        } => match field {
            "start" => Some((**start).clone()),
            "end" => Some((**end).clone()),
            "inclusive" => Some(ast::Expr::Bool(*inclusive)),
            _ => None,
        },
        ast::Expr::FieldAccess { base, field: lhs } => {
            let resolved_base = resolve_field_expr(base, lhs)?;
            resolve_field_expr(&resolved_base, field)
        }
        ast::Expr::Group(inner) => resolve_field_expr(inner, field),
        _ => None,
    }
}

fn expr_symbol_name(expr: &ast::Expr) -> Option<String> {
    match expr {
        ast::Expr::Ident(name) => Some(name.clone()),
        ast::Expr::FieldAccess { base, field } => {
            Some(format!("{}.{}", expr_symbol_name(base)?, field))
        }
        ast::Expr::Group(inner) => expr_symbol_name(inner),
        _ => None,
    }
}

fn native_current_namespace(function_name: &str) -> &str {
    function_name
        .rsplit_once('.')
        .map(|(namespace, _)| namespace)
        .unwrap_or("")
}

fn resolve_native_global_const_i32_expr(
    expr: &ast::Expr,
    current_namespace: &str,
    globals: &HashMap<String, i32>,
) -> Option<i32> {
    let symbol = expr_symbol_name(expr)?;
    globals.get(&symbol).copied().or_else(|| {
        if symbol.contains('.') || current_namespace.is_empty() {
            None
        } else {
            globals
                .get(&qualify_name(current_namespace, &symbol))
                .copied()
        }
    })
}

fn bindings_for_match_arm_pattern(
    pattern: &ast::Pattern,
    scrutinee: &ast::Expr,
    variant_tags: &HashMap<String, i32>,
) -> Result<Vec<ast::Stmt>> {
    match pattern {
        ast::Pattern::Tuple(items) => {
            if !pattern_has_tuple_bindings(items) {
                Ok(Vec::new())
            } else {
                Ok(vec![ast::Stmt::LetPattern {
                    pattern: pattern.clone(),
                    mutable: false,
                    ty: None,
                    value: scrutinee.clone(),
                }])
            }
        }
        ast::Pattern::Variant {
            enum_name,
            variant,
            bindings,
            named_bindings,
        } => {
            if bindings.is_empty() && named_bindings.is_empty() {
                return Ok(Vec::new());
            }
            let _ = (enum_name, variant);
            Ok(vec![ast::Stmt::LetPattern {
                pattern: pattern.clone(),
                mutable: false,
                ty: None,
                value: scrutinee.clone(),
            }])
        }
        ast::Pattern::Struct { name, fields } => {
            let binding_fields = fields
                .iter()
                .filter(|(_, binding)| binding != "_")
                .collect::<Vec<_>>();
            if binding_fields.is_empty() {
                return Ok(Vec::new());
            }
            let _ = name;
            Ok(vec![ast::Stmt::LetPattern {
                pattern: pattern.clone(),
                mutable: false,
                ty: None,
                value: scrutinee.clone(),
            }])
        }
        ast::Pattern::Or(patterns) => {
            if let Some(matched) = patterns.iter().find(|pattern| {
                pattern_matches_resolved_scrutinee(pattern, scrutinee, variant_tags)
            }) {
                return bindings_for_match_arm_pattern(matched, scrutinee, variant_tags);
            }
            if patterns.iter().any(pattern_has_variant_payload_bindings)
                || patterns.iter().any(pattern_has_struct_field_bindings)
            {
                bail!(
                    "native backend requires resolvable scrutinee for payload or struct-field bindings within or-pattern match arms"
                );
            }
            Ok(Vec::new())
        }
        ast::Pattern::Wildcard
        | ast::Pattern::Int(_)
        | ast::Pattern::Bool(_)
        | ast::Pattern::Ident(_) => Ok(Vec::new()),
    }
}

fn verify_control_flow_cfg(cfg: &ControlFlowCfg) -> Result<()> {
    if cfg.blocks.is_empty() {
        bail!("control-flow cfg must include at least one block");
    }
    if cfg.entry >= cfg.blocks.len() {
        bail!(
            "control-flow cfg entry {} out of range (blocks={})",
            cfg.entry,
            cfg.blocks.len()
        );
    }
    let loop_map = cfg
        .loops
        .iter()
        .map(|loop_cfg| (loop_cfg.id, loop_cfg))
        .collect::<HashMap<_, _>>();
    let mut reachable = vec![false; cfg.blocks.len()];
    let mut stack = vec![cfg.entry];
    while let Some(block_id) = stack.pop() {
        if reachable[block_id] {
            continue;
        }
        reachable[block_id] = true;
        match &cfg.blocks[block_id].terminator {
            ControlFlowTerminator::Return(_) | ControlFlowTerminator::Unreachable => {}
            ControlFlowTerminator::Jump { target, edge } => {
                if *target >= cfg.blocks.len() {
                    bail!(
                        "control-flow cfg block {} jumps to invalid target {}",
                        block_id,
                        target
                    );
                }
                match edge {
                    ControlFlowEdge::Break { loop_id } => {
                        let loop_cfg = loop_map.get(loop_id).ok_or_else(|| {
                            anyhow!(
                                "control-flow cfg block {} references unknown break loop id {}",
                                block_id,
                                loop_id
                            )
                        })?;
                        if loop_cfg.break_target != *target {
                            bail!(
                                "control-flow cfg block {} break edge target {} does not match loop {} break target {}",
                                block_id,
                                target,
                                loop_id,
                                loop_cfg.break_target
                            );
                        }
                    }
                    ControlFlowEdge::Continue { loop_id } => {
                        let loop_cfg = loop_map.get(loop_id).ok_or_else(|| {
                            anyhow!(
                                "control-flow cfg block {} references unknown continue loop id {}",
                                block_id,
                                loop_id
                            )
                        })?;
                        if loop_cfg.continue_target != *target {
                            bail!(
                                "control-flow cfg block {} continue edge target {} does not match loop {} continue target {}",
                                block_id,
                                target,
                                loop_id,
                                loop_cfg.continue_target
                            );
                        }
                    }
                    ControlFlowEdge::Normal | ControlFlowEdge::LoopBack { .. } => {}
                }
                stack.push(*target);
            }
            ControlFlowTerminator::Branch {
                then_target,
                else_target,
                ..
            } => {
                if *then_target >= cfg.blocks.len() || *else_target >= cfg.blocks.len() {
                    bail!(
                        "control-flow cfg block {} has invalid branch targets ({}, {})",
                        block_id,
                        then_target,
                        else_target
                    );
                }
                stack.push(*then_target);
                stack.push(*else_target);
            }
            ControlFlowTerminator::Switch {
                cases,
                default_target,
                ..
            } => {
                if *default_target >= cfg.blocks.len() {
                    bail!(
                        "control-flow cfg block {} has invalid switch default target {}",
                        block_id,
                        default_target
                    );
                }
                for (_, target) in cases {
                    if *target >= cfg.blocks.len() {
                        bail!(
                            "control-flow cfg block {} has invalid switch case target {}",
                            block_id,
                            target
                        );
                    }
                }
                stack.push(*default_target);
                for (_, target) in cases {
                    stack.push(*target);
                }
            }
        }
    }
    for (index, is_reachable) in reachable.iter().enumerate() {
        if !is_reachable {
            bail!(
                "control-flow cfg contains unreachable declared block {}",
                index
            );
        }
    }
    Ok(())
}


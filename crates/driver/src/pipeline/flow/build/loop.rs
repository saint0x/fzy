use super::*;

impl ControlFlowBuilder {
    pub(super) fn lower_while_stmt(
        &mut self,
        current: CfgBlockId,
        condition: &ast::Expr,
        body: &[ast::Stmt],
    ) -> Result<CfgBlockId> {
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
        Ok(exit)
    }

    pub(super) fn lower_for_stmt(
        &mut self,
        mut current: CfgBlockId,
        init: Option<&ast::Stmt>,
        condition: Option<&ast::Expr>,
        step: Option<&ast::Stmt>,
        body: &[ast::Stmt],
    ) -> Result<Option<CfgBlockId>> {
        self.known_pattern_values.clear();
        if let Some(init) = init {
            let Some(next) = self.lower_stmt_seq(current, std::slice::from_ref(init))? else {
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
            if let Some(step_tail) = self.lower_stmt_seq(step_block, std::slice::from_ref(step))? {
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
        Ok(Some(exit))
    }

    pub(super) fn lower_for_in_stmt(
        &mut self,
        current: CfgBlockId,
        binding: &str,
        iterable: &ast::Expr,
        body: &[ast::Stmt],
    ) -> Result<CfgBlockId> {
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
                    name: binding.to_string(),
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
                left: Box::new(ast::Expr::Ident(binding.to_string())),
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
                target: binding.to_string(),
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
            Ok(exit)
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
            Ok(exit)
        }
    }

    pub(super) fn lower_loop_stmt(
        &mut self,
        current: CfgBlockId,
        body: &[ast::Stmt],
    ) -> Result<Option<CfgBlockId>> {
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
            Ok(Some(exit))
        } else {
            Ok(None)
        }
    }
}

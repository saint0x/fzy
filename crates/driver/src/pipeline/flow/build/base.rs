use super::*;

impl ControlFlowBuilder {
    pub(super) fn new(
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

    pub(super) fn new_block(&mut self) -> CfgBlockId {
        let id = self.blocks.len();
        self.blocks.push(CfgBuildBlock {
            stmts: Vec::new(),
            terminator: None,
        });
        id
    }

    pub(super) fn append_stmt(&mut self, block: CfgBlockId, stmt: ast::Stmt) -> Result<()> {
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

    pub(super) fn terminate(
        &mut self,
        block: CfgBlockId,
        terminator: ControlFlowTerminator,
    ) -> Result<()> {
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

    pub(super) fn next_temp_name(&mut self, prefix: &str) -> String {
        let name = format!("__cfg_{prefix}_{}", self.next_temp);
        self.next_temp += 1;
        name
    }

    pub(super) fn append_deferred_cleanup_from(
        &mut self,
        block: CfgBlockId,
        start: usize,
    ) -> Result<()> {
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

    pub(super) fn lower_stmt_seq(
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
                } => self.lower_let_stmt(current, name, *mutable, ty, value)?,
                ast::Stmt::LetPattern {
                    pattern,
                    value,
                    mutable,
                    ty,
                } => self.lower_let_pattern_stmt(current, pattern, value, *mutable, ty)?,
                ast::Stmt::Assign { target, value } => {
                    self.lower_assign_stmt(current, target, value)?
                }
                ast::Stmt::CompoundAssign { target, op, value } => {
                    self.lower_compound_assign_stmt(current, target, *op, value)?
                }
                ast::Stmt::Defer(expr) => {
                    self.active_defers.push(expr.clone());
                }
                ast::Stmt::Requires(_) | ast::Stmt::Ensures(_) | ast::Stmt::Expr(_) => {
                    self.append_stmt(current, stmt.clone())?;
                }
                ast::Stmt::Return(expr) => {
                    return self.lower_return_stmt(current, expr.as_ref(), scope_defer_base);
                }
                ast::Stmt::Break(_) => {
                    return self.lower_break_stmt(current, scope_defer_base);
                }
                ast::Stmt::Continue => {
                    return self.lower_continue_stmt(current, scope_defer_base);
                }
                ast::Stmt::If {
                    condition,
                    then_body,
                    else_body,
                } => {
                    let Some(next) =
                        self.lower_if_stmt(current, condition, then_body, else_body)?
                    else {
                        return Ok(None);
                    };
                    current = next;
                }
                ast::Stmt::While { condition, body } => {
                    current = self.lower_while_stmt(current, condition, body)?;
                }
                ast::Stmt::For {
                    init,
                    condition,
                    step,
                    body,
                } => {
                    let Some(next) = self.lower_for_stmt(
                        current,
                        init.as_deref(),
                        condition.as_ref(),
                        step.as_deref(),
                        body,
                    )?
                    else {
                        return Ok(None);
                    };
                    current = next;
                }
                ast::Stmt::ForIn {
                    binding,
                    iterable,
                    body,
                } => {
                    current = self.lower_for_in_stmt(current, binding, iterable, body)?;
                }
                ast::Stmt::Loop { body } => {
                    let Some(next) = self.lower_loop_stmt(current, body)? else {
                        return Ok(None);
                    };
                    current = next;
                }
                ast::Stmt::Match { scrutinee, arms } => {
                    let Some(next) = self.lower_match_stmt(current, scrutinee, arms)? else {
                        return Ok(None);
                    };
                    current = next;
                }
            }
        }
        self.append_deferred_cleanup_from(current, scope_defer_base)?;
        self.active_defers.truncate(scope_defer_base);
        Ok(Some(current))
    }

    pub(super) fn finish(mut self, body: &[ast::Stmt]) -> Result<ControlFlowCfg> {
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

pub(crate) fn build_control_flow_cfg(
    body: &[ast::Stmt],
    variant_tags: &HashMap<String, i32>,
    pattern_source_functions: &HashMap<String, PatternSourceFunction>,
) -> Result<ControlFlowCfg> {
    ControlFlowBuilder::new(variant_tags.clone(), pattern_source_functions.clone()).finish(body)
}

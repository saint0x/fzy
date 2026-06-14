use super::*;

#[derive(Debug, Clone, Copy)]
pub(super) enum BackendKind {
    Llvm,
    Cranelift,
}

pub(super) type CfgBlockId = usize;

#[derive(Debug, Clone)]
pub(super) struct ControlFlowCfg {
    pub(super) entry: CfgBlockId,
    pub(super) blocks: Vec<ControlFlowBlock>,
    pub(super) loops: Vec<ControlFlowLoop>,
}

#[derive(Debug, Clone)]
pub(super) struct ControlFlowLoop {
    pub(super) id: usize,
    pub(super) break_target: CfgBlockId,
    pub(super) continue_target: CfgBlockId,
}

#[derive(Debug, Clone)]
pub(super) struct ControlFlowBlock {
    pub(super) stmts: Vec<ast::Stmt>,
    pub(super) terminator: ControlFlowTerminator,
}

#[derive(Debug, Clone)]
pub(super) enum ControlFlowTerminator {
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
pub(super) enum ControlFlowEdge {
    Normal,
    LoopBack { loop_id: usize },
    Break { loop_id: usize },
    Continue { loop_id: usize },
}

#[derive(Clone, Copy)]
pub(super) struct ActiveLoop {
    pub(super) id: usize,
    pub(super) break_target: CfgBlockId,
    pub(super) continue_target: CfgBlockId,
    pub(super) defer_base: usize,
}

#[derive(Clone)]
pub(super) struct CfgBuildBlock {
    pub(super) stmts: Vec<ast::Stmt>,
    pub(super) terminator: Option<ControlFlowTerminator>,
}

pub(super) struct ControlFlowBuilder {
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

#[path = "flow/build.rs"]
mod build;
#[path = "flow/pattern.rs"]
mod pattern;
#[path = "flow/verify.rs"]
mod verify;

pub(super) use self::build::*;
pub(super) use self::pattern::*;
pub(super) use self::verify::*;

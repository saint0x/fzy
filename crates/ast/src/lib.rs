#[derive(Debug, Clone, Default)]
pub struct Module {
    pub name: String,
    pub items: Vec<Item>,
    pub modules: Vec<String>,
    pub imports: Vec<String>,
    pub capabilities: Vec<String>,
    pub inferred_capabilities: Vec<String>,
    pub host_syscall_sites: usize,
    pub unsafe_sites: usize,
    pub unsafe_reasoned_sites: usize,
    pub reference_sites: usize,
    pub alloc_sites: usize,
    pub free_sites: usize,
}

#[derive(Debug, Clone)]
pub enum Item {
    Function(Function),
    Struct(Struct),
    Enum(Enum),
    Test(TestBlock),
}

#[derive(Debug, Clone)]
pub struct Function {
    pub name: String,
    pub params: Vec<Param>,
    pub return_type: String,
    pub body: Vec<Stmt>,
    pub is_pub: bool,
    pub is_extern: bool,
    pub abi: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Param {
    pub name: String,
    pub ty: String,
}

#[derive(Debug, Clone)]
pub struct Struct {
    pub name: String,
    pub fields: Vec<Field>,
    pub repr: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Enum {
    pub name: String,
    pub variants: Vec<Variant>,
    pub repr: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Field {
    pub name: String,
    pub ty: String,
}

#[derive(Debug, Clone)]
pub struct Variant {
    pub name: String,
    pub payload: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct TestBlock {
    pub name: String,
    pub deterministic: bool,
}

#[derive(Debug, Clone)]
pub enum Stmt {
    Let {
        name: String,
        ty: Option<String>,
        value: Expr,
    },
    Return(Expr),
    Defer(Expr),
    Requires(Expr),
    Ensures(Expr),
    Match {
        scrutinee: Expr,
        arms: Vec<MatchArm>,
    },
    Expr(Expr),
}

#[derive(Debug, Clone)]
pub enum Expr {
    Int(i32),
    Bool(bool),
    Ident(String),
    Call {
        callee: String,
        args: Vec<Expr>,
    },
    TryCatch {
        try_expr: Box<Expr>,
        catch_expr: Box<Expr>,
    },
    Binary {
        op: BinaryOp,
        left: Box<Expr>,
        right: Box<Expr>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinaryOp {
    Add,
    Sub,
    Eq,
    Neq,
}

#[derive(Debug, Clone)]
pub struct MatchArm {
    pub pattern: Pattern,
    pub value: Expr,
}

#[derive(Debug, Clone)]
pub enum Pattern {
    Wildcard,
    Int(i32),
    Bool(bool),
    Ident(String),
}

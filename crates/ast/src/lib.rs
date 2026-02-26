#[derive(Debug, Clone, Default)]
pub struct Module {
    pub name: String,
    pub items: Vec<Item>,
    pub modules: Vec<String>,
    pub imports: Vec<String>,
    pub capabilities: Vec<String>,
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
    Const(ConstItem),
    Static(StaticItem),
    Struct(Struct),
    Enum(Enum),
    Trait(Trait),
    Impl(Impl),
    Test(TestBlock),
}

#[derive(Debug, Clone)]
pub struct ConstItem {
    pub name: String,
    pub ty: Type,
    pub value: Expr,
    pub is_pub: bool,
}

#[derive(Debug, Clone)]
pub struct StaticItem {
    pub name: String,
    pub ty: Type,
    pub value: Expr,
    pub is_pub: bool,
    pub mutable: bool,
}

#[derive(Debug, Clone)]
pub struct Function {
    pub name: String,
    pub generics: Vec<GenericParam>,
    pub params: Vec<Param>,
    pub return_type: Type,
    pub body: Vec<Stmt>,
    pub is_async: bool,
    pub is_pub: bool,
    pub is_extern: bool,
    pub abi: Option<String>,
    pub ffi_panic: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Param {
    pub name: String,
    pub ty: Type,
}

#[derive(Debug, Clone)]
pub struct GenericParam {
    pub name: String,
    pub bounds: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct Struct {
    pub name: String,
    pub fields: Vec<Field>,
    pub repr: Option<String>,
    pub is_pub: bool,
}

#[derive(Debug, Clone)]
pub struct Enum {
    pub name: String,
    pub variants: Vec<Variant>,
    pub repr: Option<String>,
    pub is_pub: bool,
}

#[derive(Debug, Clone)]
pub struct Field {
    pub name: String,
    pub ty: Type,
}

#[derive(Debug, Clone)]
pub struct Variant {
    pub name: String,
    pub payload: Vec<Type>,
}

#[derive(Debug, Clone)]
pub struct Trait {
    pub name: String,
    pub methods: Vec<TraitMethod>,
    pub is_pub: bool,
}

#[derive(Debug, Clone)]
pub struct TraitMethod {
    pub name: String,
    pub params: Vec<Param>,
    pub return_type: Type,
}

#[derive(Debug, Clone)]
pub struct Impl {
    pub trait_name: Option<String>,
    pub for_type: Type,
    pub methods: Vec<Function>,
    pub is_pub: bool,
}

#[derive(Debug, Clone)]
pub struct TestBlock {
    pub name: String,
    pub deterministic: bool,
    pub body: Vec<Stmt>,
}

#[derive(Debug, Clone)]
pub enum Stmt {
    Let {
        name: String,
        mutable: bool,
        ty: Option<Type>,
        value: Expr,
    },
    LetPattern {
        pattern: Pattern,
        mutable: bool,
        ty: Option<Type>,
        value: Expr,
    },
    Assign {
        target: String,
        value: Expr,
    },
    CompoundAssign {
        target: String,
        op: BinaryOp,
        value: Expr,
    },
    If {
        condition: Expr,
        then_body: Vec<Stmt>,
        else_body: Vec<Stmt>,
    },
    While {
        condition: Expr,
        body: Vec<Stmt>,
    },
    For {
        init: Option<Box<Stmt>>,
        condition: Option<Expr>,
        step: Option<Box<Stmt>>,
        body: Vec<Stmt>,
    },
    ForIn {
        binding: String,
        iterable: Expr,
        body: Vec<Stmt>,
    },
    Loop {
        body: Vec<Stmt>,
    },
    Break,
    Continue,
    Return(Option<Expr>),
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
    Int(i128),
    Float {
        value: f64,
        bits: Option<u16>,
    },
    Char(char),
    Bool(bool),
    Str(String),
    Ident(String),
    Call {
        callee: String,
        args: Vec<Expr>,
    },
    FieldAccess {
        base: Box<Expr>,
        field: String,
    },
    StructInit {
        name: String,
        fields: Vec<(String, Expr)>,
    },
    EnumInit {
        enum_name: String,
        variant: String,
        payload: Vec<Expr>,
    },
    Closure {
        params: Vec<Param>,
        return_type: Option<Type>,
        body: Box<Expr>,
    },
    Group(Box<Expr>),
    Await(Box<Expr>),
    TryCatch {
        try_expr: Box<Expr>,
        catch_expr: Box<Expr>,
    },
    Range {
        start: Box<Expr>,
        end: Box<Expr>,
        inclusive: bool,
    },
    ArrayLiteral(Vec<Expr>),
    Index {
        base: Box<Expr>,
        index: Box<Expr>,
    },
    Unary {
        op: UnaryOp,
        expr: Box<Expr>,
    },
    Binary {
        op: BinaryOp,
        left: Box<Expr>,
        right: Box<Expr>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnaryOp {
    Not,
    Plus,
    Neg,
    BitNot,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinaryOp {
    Add,
    Sub,
    Mul,
    Div,
    Mod,
    BitAnd,
    BitOr,
    BitXor,
    Shl,
    Shr,
    And,
    Or,
    Lt,
    Lte,
    Gt,
    Gte,
    Eq,
    Neq,
}

#[derive(Debug, Clone)]
pub struct MatchArm {
    pub pattern: Pattern,
    pub guard: Option<Expr>,
    pub returns: bool,
    pub value: Expr,
}

#[derive(Debug, Clone)]
pub enum Pattern {
    Wildcard,
    Int(i128),
    Bool(bool),
    Ident(String),
    Variant {
        enum_name: String,
        variant: String,
        bindings: Vec<String>,
    },
    Or(Vec<Pattern>),
}

impl Pattern {
    pub fn bound_names(&self, out: &mut Vec<String>) {
        match self {
            Pattern::Ident(name) => out.push(name.clone()),
            Pattern::Variant { bindings, .. } => out.extend(bindings.iter().cloned()),
            Pattern::Or(patterns) => {
                for pattern in patterns {
                    pattern.bound_names(out);
                }
            }
            Pattern::Wildcard | Pattern::Int(_) | Pattern::Bool(_) => {}
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Type {
    Void,
    Bool,
    ISize,
    USize,
    Int {
        signed: bool,
        bits: u16,
    },
    Float {
        bits: u16,
    },
    Char,
    Str,
    Ptr {
        mutable: bool,
        to: Box<Type>,
    },
    Ref {
        mutable: bool,
        lifetime: Option<String>,
        to: Box<Type>,
    },
    Slice(Box<Type>),
    Array {
        elem: Box<Type>,
        len: usize,
    },
    Result {
        ok: Box<Type>,
        err: Box<Type>,
    },
    Option(Box<Type>),
    Vec(Box<Type>),
    Function {
        params: Vec<Type>,
        ret: Box<Type>,
    },
    Named {
        name: String,
        args: Vec<Type>,
    },
    TypeVar(String),
}

impl Type {
    pub fn is_pointer_like(&self) -> bool {
        matches!(self, Type::Ptr { .. } | Type::Ref { .. } | Type::Slice(_))
    }
}

impl std::fmt::Display for Type {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Type::Void => write!(f, "void"),
            Type::Bool => write!(f, "bool"),
            Type::ISize => write!(f, "isize"),
            Type::USize => write!(f, "usize"),
            Type::Int { signed: true, bits } => write!(f, "i{bits}"),
            Type::Int {
                signed: false,
                bits,
            } => write!(f, "u{bits}"),
            Type::Float { bits } => write!(f, "f{bits}"),
            Type::Char => write!(f, "char"),
            Type::Str => write!(f, "str"),
            Type::Ptr { mutable, to } => {
                if *mutable {
                    write!(f, "*mut {to}")
                } else {
                    write!(f, "*{to}")
                }
            }
            Type::Ref {
                mutable,
                lifetime,
                to,
            } => {
                if *mutable {
                    if let Some(lifetime) = lifetime {
                        write!(f, "&'{lifetime} mut {to}")
                    } else {
                        write!(f, "&mut {to}")
                    }
                } else if let Some(lifetime) = lifetime {
                    write!(f, "&'{lifetime} {to}")
                } else {
                    write!(f, "&{to}")
                }
            }
            Type::Slice(elem) => write!(f, "[]{elem}"),
            Type::Array { elem, len } => write!(f, "[{elem}; {len}]"),
            Type::Result { ok, err } => write!(f, "Result<{ok}, {err}>"),
            Type::Option(inner) => write!(f, "Option<{inner}>"),
            Type::Vec(inner) => write!(f, "Vec<{inner}>"),
            Type::Function { params, ret } => {
                write!(
                    f,
                    "fn({}) -> {}",
                    params
                        .iter()
                        .map(|t| t.to_string())
                        .collect::<Vec<_>>()
                        .join(", "),
                    ret
                )
            }
            Type::Named { name, args } => {
                if args.is_empty() {
                    write!(f, "{name}")
                } else {
                    write!(
                        f,
                        "{}<{}>",
                        name,
                        args.iter()
                            .map(|t| t.to_string())
                            .collect::<Vec<_>>()
                            .join(", ")
                    )
                }
            }
            Type::TypeVar(name) => write!(f, "{name}"),
        }
    }
}

pub trait AstVisitor {
    fn visit_stmt(&mut self, stmt: &Stmt) {
        walk_stmt(self, stmt);
    }
    fn visit_expr(&mut self, expr: &Expr) {
        walk_expr(self, expr);
    }
}

pub fn walk_stmt<V: AstVisitor + ?Sized>(visitor: &mut V, stmt: &Stmt) {
    match stmt {
        Stmt::Let { value, .. }
        | Stmt::LetPattern { value, .. }
        | Stmt::Defer(value)
        | Stmt::Requires(value)
        | Stmt::Ensures(value)
        | Stmt::Expr(value) => visitor.visit_expr(value),
        Stmt::Assign { value, .. } | Stmt::CompoundAssign { value, .. } => {
            visitor.visit_expr(value)
        }
        Stmt::Return(value) => {
            if let Some(value) = value {
                visitor.visit_expr(value);
            }
        }
        Stmt::If {
            condition,
            then_body,
            else_body,
        } => {
            visitor.visit_expr(condition);
            for nested in then_body {
                visitor.visit_stmt(nested);
            }
            for nested in else_body {
                visitor.visit_stmt(nested);
            }
        }
        Stmt::While { condition, body } => {
            visitor.visit_expr(condition);
            for nested in body {
                visitor.visit_stmt(nested);
            }
        }
        Stmt::For {
            init,
            condition,
            step,
            body,
        } => {
            if let Some(init) = init {
                visitor.visit_stmt(init);
            }
            if let Some(condition) = condition {
                visitor.visit_expr(condition);
            }
            if let Some(step) = step {
                visitor.visit_stmt(step);
            }
            for nested in body {
                visitor.visit_stmt(nested);
            }
        }
        Stmt::ForIn { iterable, body, .. } => {
            visitor.visit_expr(iterable);
            for nested in body {
                visitor.visit_stmt(nested);
            }
        }
        Stmt::Loop { body } => {
            for nested in body {
                visitor.visit_stmt(nested);
            }
        }
        Stmt::Break | Stmt::Continue => {}
        Stmt::Match { scrutinee, arms } => {
            visitor.visit_expr(scrutinee);
            for arm in arms {
                if let Some(guard) = &arm.guard {
                    visitor.visit_expr(guard);
                }
                visitor.visit_expr(&arm.value);
            }
        }
    }
}

pub fn walk_expr<V: AstVisitor + ?Sized>(visitor: &mut V, expr: &Expr) {
    match expr {
        Expr::Call { args, .. } => {
            for arg in args {
                visitor.visit_expr(arg);
            }
        }
        Expr::FieldAccess { base, .. } => visitor.visit_expr(base),
        Expr::StructInit { fields, .. } => {
            for (_, value) in fields {
                visitor.visit_expr(value);
            }
        }
        Expr::EnumInit { payload, .. } => {
            for value in payload {
                visitor.visit_expr(value);
            }
        }
        Expr::Closure { body, .. } => visitor.visit_expr(body),
        Expr::TryCatch {
            try_expr,
            catch_expr,
        } => {
            visitor.visit_expr(try_expr);
            visitor.visit_expr(catch_expr);
        }
        Expr::Range {
            start,
            end,
            inclusive: _,
        } => {
            visitor.visit_expr(start);
            visitor.visit_expr(end);
        }
        Expr::ArrayLiteral(items) => {
            for item in items {
                visitor.visit_expr(item);
            }
        }
        Expr::Index { base, index } => {
            visitor.visit_expr(base);
            visitor.visit_expr(index);
        }
        Expr::Await(inner) => visitor.visit_expr(inner),
        Expr::Unary { expr, .. } => visitor.visit_expr(expr),
        Expr::Binary { left, right, .. } => {
            visitor.visit_expr(left);
            visitor.visit_expr(right);
        }
        Expr::Group(inner) => visitor.visit_expr(inner),
        Expr::Int(_)
        | Expr::Float { .. }
        | Expr::Char(_)
        | Expr::Bool(_)
        | Expr::Str(_)
        | Expr::Ident(_) => {}
    }
}

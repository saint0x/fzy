use std::collections::{BTreeMap, BTreeSet, VecDeque};

use ast::{BinaryOp, ExecutionSpace, Expr, Param, Stmt, Type, UnaryOp};
use diagnostics::{Diagnostic, Severity};

#[derive(Debug, Clone)]
pub struct KernelModule {
    pub name: String,
    pub kernels: Vec<String>,
    pub functions: Vec<KernelFunction>,
}

#[derive(Debug, Clone)]
pub struct KernelFunction {
    pub name: String,
    pub execution_space: ExecutionSpace,
    pub params: Vec<Param>,
    pub slice_access: BTreeMap<String, KernelSliceAccessMode>,
    pub return_type: Type,
    pub body: Vec<KernelStmt>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum KernelSliceAccessMode {
    Observe,
    ReadOnly,
    WriteOnly,
    ReadWrite,
}

impl KernelSliceAccessMode {
    fn with_read(self) -> Self {
        match self {
            Self::Observe => Self::ReadOnly,
            Self::ReadOnly => Self::ReadOnly,
            Self::WriteOnly => Self::ReadWrite,
            Self::ReadWrite => Self::ReadWrite,
        }
    }

    fn with_write(self) -> Self {
        match self {
            Self::Observe => Self::WriteOnly,
            Self::ReadOnly => Self::ReadWrite,
            Self::WriteOnly => Self::WriteOnly,
            Self::ReadWrite => Self::ReadWrite,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Observe => "observe",
            Self::ReadOnly => "readonly",
            Self::WriteOnly => "writeonly",
            Self::ReadWrite => "readwrite",
        }
    }

    pub fn layout_suffix(self) -> &'static str {
        match self {
            Self::Observe | Self::ReadOnly => "ro",
            Self::WriteOnly => "wo",
            Self::ReadWrite => "rw",
        }
    }

    pub fn is_read_only_like(self) -> bool {
        matches!(self, Self::Observe | Self::ReadOnly)
    }
}

#[derive(Debug, Clone)]
pub enum KernelStmt {
    Let {
        name: String,
        ty: Option<Type>,
        value: KernelExpr,
    },
    Assign {
        target: String,
        value: KernelExpr,
    },
    Store {
        base: KernelExpr,
        index: KernelExpr,
        value: KernelExpr,
    },
    If {
        condition: KernelExpr,
        then_body: Vec<KernelStmt>,
        else_body: Vec<KernelStmt>,
    },
    While {
        condition: KernelExpr,
        body: Vec<KernelStmt>,
    },
    Loop {
        body: Vec<KernelStmt>,
    },
    Break(Option<KernelExpr>),
    Continue,
    Return(Option<KernelExpr>),
    Expr(KernelExpr),
}

#[derive(Debug, Clone)]
pub enum KernelExpr {
    Int(i128),
    Float {
        value: f64,
        bits: Option<u16>,
    },
    Bool(bool),
    Char(char),
    Ident(String),
    Unary {
        op: UnaryOp,
        expr: Box<KernelExpr>,
    },
    Binary {
        op: BinaryOp,
        left: Box<KernelExpr>,
        right: Box<KernelExpr>,
    },
    Call {
        callee: String,
        args: Vec<KernelExpr>,
    },
    Intrinsic {
        op: KernelIntrinsic,
        args: Vec<KernelExpr>,
    },
    Load {
        base: Box<KernelExpr>,
        index: Box<KernelExpr>,
    },
    Group(Box<KernelExpr>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KernelIntrinsic {
    GlobalIdX,
    GlobalIdY,
    GlobalIdZ,
    ThreadIdX,
    ThreadIdY,
    ThreadIdZ,
    BlockIdX,
    BlockIdY,
    BlockIdZ,
    BlockDimX,
    BlockDimY,
    BlockDimZ,
    GridDimX,
    GridDimY,
    GridDimZ,
    Barrier,
    SliceLen,
    LoadF32,
    LoadI32,
    LoadU32,
    StoreF32,
    StoreI32,
    StoreU32,
}

impl KernelIntrinsic {
    fn from_callee(callee: &str) -> Option<Self> {
        Some(match callee {
            "gpu.global_id_x" => Self::GlobalIdX,
            "gpu.global_id_y" => Self::GlobalIdY,
            "gpu.global_id_z" => Self::GlobalIdZ,
            "gpu.thread_id_x" => Self::ThreadIdX,
            "gpu.thread_id_y" => Self::ThreadIdY,
            "gpu.thread_id_z" => Self::ThreadIdZ,
            "gpu.block_id_x" => Self::BlockIdX,
            "gpu.block_id_y" => Self::BlockIdY,
            "gpu.block_id_z" => Self::BlockIdZ,
            "gpu.block_dim_x" => Self::BlockDimX,
            "gpu.block_dim_y" => Self::BlockDimY,
            "gpu.block_dim_z" => Self::BlockDimZ,
            "gpu.grid_dim_x" => Self::GridDimX,
            "gpu.grid_dim_y" => Self::GridDimY,
            "gpu.grid_dim_z" => Self::GridDimZ,
            "gpu.barrier" => Self::Barrier,
            "gpu.slice_len" => Self::SliceLen,
            "gpu.load_f32" => Self::LoadF32,
            "gpu.load_i32" => Self::LoadI32,
            "gpu.load_u32" => Self::LoadU32,
            "gpu.store_f32" => Self::StoreF32,
            "gpu.store_i32" => Self::StoreI32,
            "gpu.store_u32" => Self::StoreU32,
            _ => return None,
        })
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::GlobalIdX => "global_id_x",
            Self::GlobalIdY => "global_id_y",
            Self::GlobalIdZ => "global_id_z",
            Self::ThreadIdX => "thread_id_x",
            Self::ThreadIdY => "thread_id_y",
            Self::ThreadIdZ => "thread_id_z",
            Self::BlockIdX => "block_id_x",
            Self::BlockIdY => "block_id_y",
            Self::BlockIdZ => "block_id_z",
            Self::BlockDimX => "block_dim_x",
            Self::BlockDimY => "block_dim_y",
            Self::BlockDimZ => "block_dim_z",
            Self::GridDimX => "grid_dim_x",
            Self::GridDimY => "grid_dim_y",
            Self::GridDimZ => "grid_dim_z",
            Self::Barrier => "barrier",
            Self::SliceLen => "slice_len",
            Self::LoadF32 => "load_f32",
            Self::LoadI32 => "load_i32",
            Self::LoadU32 => "load_u32",
            Self::StoreF32 => "store_f32",
            Self::StoreI32 => "store_i32",
            Self::StoreU32 => "store_u32",
        }
    }
}

pub fn lower(module: &hir::TypedModule) -> Result<KernelModule, Vec<Diagnostic>> {
    let function_map = module
        .typed_functions
        .iter()
        .map(|function| (function.name.clone(), function))
        .collect::<BTreeMap<_, _>>();
    let kernels = module
        .typed_functions
        .iter()
        .filter(|function| function.execution_space == ExecutionSpace::Kernel)
        .map(|function| function.name.clone())
        .collect::<Vec<_>>();
    if kernels.is_empty() {
        return Ok(KernelModule {
            name: module.name.clone(),
            kernels,
            functions: Vec::new(),
        });
    }

    let reachable = collect_reachable_gpu_functions(module, &function_map, &kernels);
    let mut functions = Vec::new();
    let mut diagnostics = Vec::new();
    for name in reachable {
        let Some(function) = function_map.get(&name) else {
            continue;
        };
        match lower_function(function, &function_map) {
            Ok(function) => functions.push(function),
            Err(mut errors) => diagnostics.append(&mut errors),
        }
    }
    if diagnostics.is_empty() {
        infer_slice_access_modes(&mut functions);
        Ok(KernelModule {
            name: module.name.clone(),
            kernels,
            functions,
        })
    } else {
        Err(diagnostics)
    }
}

pub fn render(module: &KernelModule) -> String {
    if module.functions.is_empty() {
        return String::new();
    }
    let mut out = String::new();
    out.push_str("kernel.module ");
    out.push_str(&module.name);
    out.push('\n');
    for kernel in &module.kernels {
        out.push_str("kernel.entry ");
        out.push_str(kernel);
        out.push('\n');
    }
    for function in &module.functions {
        out.push('\n');
        out.push_str(function.execution_space.as_str());
        out.push_str(" fn ");
        out.push_str(&function.name);
        out.push('(');
        for (index, param) in function.params.iter().enumerate() {
            if index > 0 {
                out.push_str(", ");
            }
            out.push_str(&param.name);
            out.push_str(": ");
            out.push_str(&param.ty.to_string());
        }
        out.push(')');
        out.push_str(" -> ");
        out.push_str(&function.return_type.to_string());
        out.push_str(" {\n");
        render_stmts(&function.body, 1, &mut out);
        out.push_str("}\n");
    }
    out
}

fn render_stmts(stmts: &[KernelStmt], indent: usize, out: &mut String) {
    let pad = "    ".repeat(indent);
    for stmt in stmts {
        match stmt {
            KernelStmt::Let { name, ty, value } => {
                out.push_str(&pad);
                out.push_str("let ");
                out.push_str(name);
                if let Some(ty) = ty {
                    out.push_str(": ");
                    out.push_str(&ty.to_string());
                }
                out.push_str(" = ");
                render_expr(value, out);
                out.push_str(";\n");
            }
            KernelStmt::Assign { target, value } => {
                out.push_str(&pad);
                out.push_str(target);
                out.push_str(" = ");
                render_expr(value, out);
                out.push_str(";\n");
            }
            KernelStmt::Store { base, index, value } => {
                out.push_str(&pad);
                render_expr(base, out);
                out.push('[');
                render_expr(index, out);
                out.push_str("] = ");
                render_expr(value, out);
                out.push_str(";\n");
            }
            KernelStmt::If {
                condition,
                then_body,
                else_body,
            } => {
                out.push_str(&pad);
                out.push_str("if ");
                render_expr(condition, out);
                out.push_str(" {\n");
                render_stmts(then_body, indent + 1, out);
                out.push_str(&pad);
                out.push('}');
                if !else_body.is_empty() {
                    out.push_str(" else {\n");
                    render_stmts(else_body, indent + 1, out);
                    out.push_str(&pad);
                    out.push('}');
                }
                out.push('\n');
            }
            KernelStmt::While { condition, body } => {
                out.push_str(&pad);
                out.push_str("while ");
                render_expr(condition, out);
                out.push_str(" {\n");
                render_stmts(body, indent + 1, out);
                out.push_str(&pad);
                out.push_str("}\n");
            }
            KernelStmt::Loop { body } => {
                out.push_str(&pad);
                out.push_str("loop {\n");
                render_stmts(body, indent + 1, out);
                out.push_str(&pad);
                out.push_str("}\n");
            }
            KernelStmt::Break(value) => {
                out.push_str(&pad);
                out.push_str("break");
                if let Some(value) = value {
                    out.push(' ');
                    render_expr(value, out);
                }
                out.push_str(";\n");
            }
            KernelStmt::Continue => {
                out.push_str(&pad);
                out.push_str("continue;\n");
            }
            KernelStmt::Return(value) => {
                out.push_str(&pad);
                out.push_str("return");
                if let Some(value) = value {
                    out.push(' ');
                    render_expr(value, out);
                }
                out.push_str(";\n");
            }
            KernelStmt::Expr(expr) => {
                out.push_str(&pad);
                render_expr(expr, out);
                out.push_str(";\n");
            }
        }
    }
}

fn render_expr(expr: &KernelExpr, out: &mut String) {
    match expr {
        KernelExpr::Int(value) => out.push_str(&value.to_string()),
        KernelExpr::Float { value, bits } => {
            out.push_str(&value.to_string());
            if let Some(bits) = bits {
                out.push('_');
                out.push_str(&bits.to_string());
            }
        }
        KernelExpr::Bool(value) => out.push_str(if *value { "true" } else { "false" }),
        KernelExpr::Char(value) => {
            out.push('\'');
            out.push(*value);
            out.push('\'');
        }
        KernelExpr::Ident(name) => out.push_str(name),
        KernelExpr::Unary { op, expr } => {
            out.push_str(match op {
                UnaryOp::Not => "!",
                UnaryOp::Plus => "+",
                UnaryOp::Neg => "-",
                UnaryOp::BitNot => "~",
            });
            render_expr(expr, out);
        }
        KernelExpr::Binary { op, left, right } => {
            render_expr(left, out);
            out.push(' ');
            out.push_str(match op {
                BinaryOp::Add => "+",
                BinaryOp::Sub => "-",
                BinaryOp::Mul => "*",
                BinaryOp::Div => "/",
                BinaryOp::Mod => "%",
                BinaryOp::BitAnd => "&",
                BinaryOp::BitOr => "|",
                BinaryOp::BitXor => "^",
                BinaryOp::Shl => "<<",
                BinaryOp::Shr => ">>",
                BinaryOp::And => "&&",
                BinaryOp::Or => "||",
                BinaryOp::Lt => "<",
                BinaryOp::Lte => "<=",
                BinaryOp::Gt => ">",
                BinaryOp::Gte => ">=",
                BinaryOp::Eq => "==",
                BinaryOp::Neq => "!=",
            });
            out.push(' ');
            render_expr(right, out);
        }
        KernelExpr::Call { callee, args } => {
            out.push_str(callee);
            out.push('(');
            for (index, arg) in args.iter().enumerate() {
                if index > 0 {
                    out.push_str(", ");
                }
                render_expr(arg, out);
            }
            out.push(')');
        }
        KernelExpr::Intrinsic { op, args } => {
            out.push_str("intrinsic.");
            out.push_str(op.as_str());
            out.push('(');
            for (index, arg) in args.iter().enumerate() {
                if index > 0 {
                    out.push_str(", ");
                }
                render_expr(arg, out);
            }
            out.push(')');
        }
        KernelExpr::Load { base, index } => {
            render_expr(base, out);
            out.push('[');
            render_expr(index, out);
            out.push(']');
        }
        KernelExpr::Group(inner) => {
            out.push('(');
            render_expr(inner, out);
            out.push(')');
        }
    }
}

fn collect_reachable_gpu_functions(
    module: &hir::TypedModule,
    function_map: &BTreeMap<String, &hir::TypedFunction>,
    kernels: &[String],
) -> Vec<String> {
    let mut queue = VecDeque::from(kernels.to_vec());
    let mut reachable = BTreeSet::new();
    while let Some(current) = queue.pop_front() {
        if !reachable.insert(current.clone()) {
            continue;
        }
        for (_, callee) in module
            .call_graph
            .iter()
            .filter(|(caller, _)| caller == &current)
        {
            let Some(function) = function_map.get(callee) else {
                continue;
            };
            if matches!(
                function.execution_space,
                ExecutionSpace::Kernel | ExecutionSpace::Device | ExecutionSpace::Pure
            ) {
                queue.push_back(callee.clone());
            }
        }
    }
    reachable.into_iter().collect()
}

fn lower_function(
    function: &hir::TypedFunction,
    function_map: &BTreeMap<String, &hir::TypedFunction>,
) -> Result<KernelFunction, Vec<Diagnostic>> {
    let mut diagnostics = Vec::new();
    if function.is_async {
        diagnostics.push(lowering_error(
            function,
            "async GPU functions are not supported in Kernel IR",
        ));
    }
    if function.is_extern {
        diagnostics.push(lowering_error(
            function,
            "extern GPU functions are not supported in Kernel IR",
        ));
    }
    if !function.generics.is_empty() {
        diagnostics.push(lowering_error(
            function,
            "generic GPU functions are not yet supported in Kernel IR",
        ));
    }
    if !matches!(
        function.execution_space,
        ExecutionSpace::Kernel | ExecutionSpace::Device | ExecutionSpace::Pure
    ) {
        diagnostics.push(lowering_error(
            function,
            "host functions are not part of Kernel IR lowering",
        ));
    }
    let mut scope = function
        .params
        .iter()
        .map(|param| (param.name.clone(), param.ty.clone()))
        .collect::<BTreeMap<_, _>>();
    scope.extend(
        function
            .local_types
            .iter()
            .map(|(name, ty)| (name.clone(), ty.clone())),
    );

    let body = lower_stmts(
        function,
        &function.body,
        function_map,
        &scope,
        &mut diagnostics,
    );
    if diagnostics.is_empty() {
        Ok(KernelFunction {
            name: function.name.clone(),
            execution_space: function.execution_space,
            params: function.params.clone(),
            slice_access: function
                .params
                .iter()
                .filter(|param| is_gpu_slice_type(&param.ty))
                .map(|param| (param.name.clone(), KernelSliceAccessMode::Observe))
                .collect(),
            return_type: function.return_type.clone(),
            body,
        })
    } else {
        Err(diagnostics)
    }
}

fn infer_slice_access_modes(functions: &mut [KernelFunction]) {
    let function_map = functions
        .iter()
        .enumerate()
        .map(|(index, function)| (function.name.clone(), index))
        .collect::<BTreeMap<_, _>>();
    loop {
        let snapshot = functions
            .iter()
            .map(|function| (function.name.clone(), function.slice_access.clone()))
            .collect::<BTreeMap<_, _>>();
        let param_orders = functions
            .iter()
            .map(|function| {
                (
                    function.name.clone(),
                    function
                        .params
                        .iter()
                        .filter(|param| is_gpu_slice_type(&param.ty))
                        .map(|param| param.name.clone())
                        .collect::<Vec<_>>(),
                )
            })
            .collect::<BTreeMap<_, _>>();
        let mut changed = false;
        for index in 0..functions.len() {
            let body = functions[index].body.clone();
            let params = functions[index].params.clone();
            let mut aliases = params
                .iter()
                .filter(|param| is_gpu_slice_type(&param.ty))
                .map(|param| (param.name.clone(), param.name.clone()))
                .collect::<BTreeMap<_, _>>();
            let mut updates = BTreeMap::<String, KernelSliceAccessMode>::new();
            collect_stmt_slice_access(
                &body,
                &mut aliases,
                &snapshot,
                &param_orders,
                &function_map,
                &mut updates,
            );
            for (param, mode) in updates {
                let entry = functions[index]
                    .slice_access
                    .entry(param)
                    .or_insert(KernelSliceAccessMode::Observe);
                if *entry != mode {
                    *entry = mode;
                    changed = true;
                }
            }
        }
        if !changed {
            break;
        }
    }
}

fn collect_stmt_slice_access(
    stmts: &[KernelStmt],
    aliases: &mut BTreeMap<String, String>,
    summaries: &BTreeMap<String, BTreeMap<String, KernelSliceAccessMode>>,
    param_orders: &BTreeMap<String, Vec<String>>,
    function_map: &BTreeMap<String, usize>,
    out: &mut BTreeMap<String, KernelSliceAccessMode>,
) {
    for stmt in stmts {
        match stmt {
            KernelStmt::Let { name, ty, value } => {
                collect_expr_slice_access(value, aliases, summaries, param_orders, function_map, out);
                if ty.as_ref().is_some_and(is_gpu_slice_type) {
                    if let Some(owner) = infer_slice_alias_source(value, aliases, summaries, param_orders) {
                        aliases.insert(name.clone(), owner);
                    } else {
                        aliases.remove(name);
                    }
                } else {
                    aliases.remove(name);
                }
            }
            KernelStmt::Assign { value, .. } => {
                collect_expr_slice_access(value, aliases, summaries, param_orders, function_map, out);
            }
            KernelStmt::Store { base, index, value } => {
                mark_expr_slice_write(base, aliases, out);
                collect_expr_slice_access(index, aliases, summaries, param_orders, function_map, out);
                collect_expr_slice_access(value, aliases, summaries, param_orders, function_map, out);
            }
            KernelStmt::If {
                condition,
                then_body,
                else_body,
            } => {
                collect_expr_slice_access(condition, aliases, summaries, param_orders, function_map, out);
                collect_stmt_slice_access(
                    then_body,
                    &mut aliases.clone(),
                    summaries,
                    param_orders,
                    function_map,
                    out,
                );
                collect_stmt_slice_access(
                    else_body,
                    &mut aliases.clone(),
                    summaries,
                    param_orders,
                    function_map,
                    out,
                );
            }
            KernelStmt::While { condition, body } => {
                collect_expr_slice_access(condition, aliases, summaries, param_orders, function_map, out);
                collect_stmt_slice_access(body, &mut aliases.clone(), summaries, param_orders, function_map, out);
            }
            KernelStmt::Loop { body } => {
                collect_stmt_slice_access(body, &mut aliases.clone(), summaries, param_orders, function_map, out);
            }
            KernelStmt::Break(value) | KernelStmt::Return(value) => {
                if let Some(value) = value {
                    collect_expr_slice_access(value, aliases, summaries, param_orders, function_map, out);
                }
            }
            KernelStmt::Expr(expr) => {
                collect_expr_slice_access(expr, aliases, summaries, param_orders, function_map, out);
            }
            KernelStmt::Continue => {}
        }
    }
}

fn collect_expr_slice_access(
    expr: &KernelExpr,
    aliases: &BTreeMap<String, String>,
    summaries: &BTreeMap<String, BTreeMap<String, KernelSliceAccessMode>>,
    param_orders: &BTreeMap<String, Vec<String>>,
    function_map: &BTreeMap<String, usize>,
    out: &mut BTreeMap<String, KernelSliceAccessMode>,
) {
    match expr {
        KernelExpr::Load { base, index } => {
            mark_expr_slice_read(base, aliases, out);
            collect_expr_slice_access(index, aliases, summaries, param_orders, function_map, out);
        }
        KernelExpr::Call { callee, args } => {
            if let (Some(params), Some(order)) = (summaries.get(callee), param_orders.get(callee)) {
                for (arg, param_name) in args.iter().zip(order.iter()) {
                    let mode = params
                        .get(param_name)
                        .copied()
                        .unwrap_or(KernelSliceAccessMode::Observe);
                    match mode {
                        KernelSliceAccessMode::Observe => {}
                        KernelSliceAccessMode::ReadOnly => mark_expr_slice_read(arg, aliases, out),
                        KernelSliceAccessMode::WriteOnly => mark_expr_slice_write(arg, aliases, out),
                        KernelSliceAccessMode::ReadWrite => {
                            mark_expr_slice_read(arg, aliases, out);
                            mark_expr_slice_write(arg, aliases, out);
                        }
                    }
                }
            } else {
                for arg in args {
                    collect_expr_slice_access(arg, aliases, summaries, param_orders, function_map, out);
                }
            }
            let _ = function_map;
        }
        KernelExpr::Intrinsic { op, args } => {
            match op {
                KernelIntrinsic::LoadF32 | KernelIntrinsic::LoadI32 | KernelIntrinsic::LoadU32 => {
                    if let Some(base) = args.first() {
                        mark_expr_slice_read(base, aliases, out);
                    }
                }
                KernelIntrinsic::StoreF32
                | KernelIntrinsic::StoreI32
                | KernelIntrinsic::StoreU32 => {
                    if let Some(base) = args.first() {
                        mark_expr_slice_write(base, aliases, out);
                    }
                }
                KernelIntrinsic::SliceLen | KernelIntrinsic::Barrier => {}
                _ => {}
            }
            for arg in args.iter().skip(1) {
                collect_expr_slice_access(arg, aliases, summaries, param_orders, function_map, out);
            }
        }
        KernelExpr::Unary { expr, .. } | KernelExpr::Group(expr) => {
            collect_expr_slice_access(expr, aliases, summaries, param_orders, function_map, out);
        }
        KernelExpr::Binary { left, right, .. } => {
            collect_expr_slice_access(left, aliases, summaries, param_orders, function_map, out);
            collect_expr_slice_access(right, aliases, summaries, param_orders, function_map, out);
        }
        KernelExpr::Int(_)
        | KernelExpr::Float { .. }
        | KernelExpr::Bool(_)
        | KernelExpr::Char(_)
        | KernelExpr::Ident(_) => {}
    }
}

fn infer_slice_alias_source(
    expr: &KernelExpr,
    aliases: &BTreeMap<String, String>,
    summaries: &BTreeMap<String, BTreeMap<String, KernelSliceAccessMode>>,
    param_orders: &BTreeMap<String, Vec<String>>,
) -> Option<String> {
    match expr {
        KernelExpr::Ident(name) => aliases.get(name).cloned(),
        KernelExpr::Group(inner) => {
            infer_slice_alias_source(inner, aliases, summaries, param_orders)
        }
        KernelExpr::Call { callee, args } => {
            if let (Some(params), Some(order)) = (summaries.get(callee), param_orders.get(callee)) {
                for (arg, param_name) in args.iter().zip(order.iter()) {
                    if params.contains_key(param_name) {
                        if let Some(owner) = infer_slice_alias_source(arg, aliases, summaries, param_orders) {
                            return Some(owner);
                        }
                    }
                }
            }
            None
        }
        _ => None,
    }
}

fn mark_expr_slice_read(
    expr: &KernelExpr,
    aliases: &BTreeMap<String, String>,
    out: &mut BTreeMap<String, KernelSliceAccessMode>,
) {
    if let Some(param) = kernel_slice_root_name(expr, aliases) {
        let entry = out.entry(param).or_insert(KernelSliceAccessMode::Observe);
        *entry = entry.with_read();
    }
}

fn mark_expr_slice_write(
    expr: &KernelExpr,
    aliases: &BTreeMap<String, String>,
    out: &mut BTreeMap<String, KernelSliceAccessMode>,
) {
    if let Some(param) = kernel_slice_root_name(expr, aliases) {
        let entry = out.entry(param).or_insert(KernelSliceAccessMode::Observe);
        *entry = entry.with_write();
    }
}

fn kernel_slice_root_name(
    expr: &KernelExpr,
    aliases: &BTreeMap<String, String>,
) -> Option<String> {
    match expr {
        KernelExpr::Ident(name) => aliases.get(name).cloned(),
        KernelExpr::Group(inner) => kernel_slice_root_name(inner, aliases),
        _ => None,
    }
}

fn lower_stmts(
    function: &hir::TypedFunction,
    stmts: &[Stmt],
    function_map: &BTreeMap<String, &hir::TypedFunction>,
    scope: &BTreeMap<String, Type>,
    diagnostics: &mut Vec<Diagnostic>,
) -> Vec<KernelStmt> {
    let mut out = Vec::new();
    for stmt in stmts {
        match lower_stmt(function, stmt, function_map, scope, diagnostics) {
            Some(stmt) => out.push(stmt),
            None => {}
        }
    }
    out
}

fn lower_stmt(
    function: &hir::TypedFunction,
    stmt: &Stmt,
    function_map: &BTreeMap<String, &hir::TypedFunction>,
    scope: &BTreeMap<String, Type>,
    diagnostics: &mut Vec<Diagnostic>,
) -> Option<KernelStmt> {
    match stmt {
        Stmt::Let {
            name, ty, value, ..
        } => Some(KernelStmt::Let {
            name: name.clone(),
            ty: ty.clone(),
            value: lower_expr(function, value, function_map, scope, diagnostics)?,
        }),
        Stmt::Assign { target, value } => Some(KernelStmt::Assign {
            target: target.clone(),
            value: lower_expr(function, value, function_map, scope, diagnostics)?,
        }),
        Stmt::CompoundAssign { target, op, value } => {
            let rhs = lower_expr(function, value, function_map, scope, diagnostics)?;
            Some(KernelStmt::Assign {
                target: target.clone(),
                value: KernelExpr::Binary {
                    op: *op,
                    left: Box::new(KernelExpr::Ident(target.clone())),
                    right: Box::new(rhs),
                },
            })
        }
        Stmt::If {
            condition,
            then_body,
            else_body,
        } => Some(KernelStmt::If {
            condition: lower_expr(function, condition, function_map, scope, diagnostics)?,
            then_body: lower_stmts(function, then_body, function_map, scope, diagnostics),
            else_body: lower_stmts(function, else_body, function_map, scope, diagnostics),
        }),
        Stmt::While { condition, body } => Some(KernelStmt::While {
            condition: lower_expr(function, condition, function_map, scope, diagnostics)?,
            body: lower_stmts(function, body, function_map, scope, diagnostics),
        }),
        Stmt::Loop { body } => Some(KernelStmt::Loop {
            body: lower_stmts(function, body, function_map, scope, diagnostics),
        }),
        Stmt::Break(value) => {
            Some(KernelStmt::Break(value.as_ref().and_then(|value| {
                lower_expr(function, value, function_map, scope, diagnostics)
            })))
        }
        Stmt::Continue => Some(KernelStmt::Continue),
        Stmt::Return(value) => {
            Some(KernelStmt::Return(value.as_ref().and_then(|value| {
                lower_expr(function, value, function_map, scope, diagnostics)
            })))
        }
        Stmt::Expr(Expr::Call { callee, args }) if base_callee(callee) == "__index_assign" => {
            if args.len() != 3 {
                diagnostics.push(lowering_error(
                    function,
                    "indexed assignment lowering expects exactly 3 arguments",
                ));
                return None;
            }
            Some(KernelStmt::Store {
                base: lower_expr(function, &args[0], function_map, scope, diagnostics)?,
                index: lower_expr(function, &args[1], function_map, scope, diagnostics)?,
                value: lower_expr(function, &args[2], function_map, scope, diagnostics)?,
            })
        }
        Stmt::Expr(expr) => Some(KernelStmt::Expr(lower_expr(
            function,
            expr,
            function_map,
            scope,
            diagnostics,
        )?)),
        Stmt::LetPattern { .. } => {
            diagnostics.push(lowering_error(
                function,
                "Kernel IR does not yet support pattern bindings in GPU functions",
            ));
            None
        }
        Stmt::For { .. } => {
            diagnostics.push(lowering_error(
                function,
                "Kernel IR does not yet support `for` loops; use `while` or `loop` in GPU code",
            ));
            None
        }
        Stmt::ForIn { .. } => {
            diagnostics.push(lowering_error(
                function,
                "Kernel IR does not yet support `for in` loops in GPU functions",
            ));
            None
        }
        Stmt::Defer(_) => {
            diagnostics.push(lowering_error(
                function,
                "Kernel IR does not support `defer` inside GPU functions",
            ));
            None
        }
        Stmt::Requires(_) | Stmt::Ensures(_) => {
            diagnostics.push(lowering_error(
                function,
                "Kernel IR does not yet support contracts inside GPU functions",
            ));
            None
        }
        Stmt::Match { .. } => {
            diagnostics.push(lowering_error(
                function,
                "Kernel IR does not yet support `match` statements in GPU functions",
            ));
            None
        }
    }
}

fn lower_expr(
    function: &hir::TypedFunction,
    expr: &Expr,
    function_map: &BTreeMap<String, &hir::TypedFunction>,
    scope: &BTreeMap<String, Type>,
    diagnostics: &mut Vec<Diagnostic>,
) -> Option<KernelExpr> {
    match expr {
        Expr::Int(value) => Some(KernelExpr::Int(*value)),
        Expr::Float { value, bits } => Some(KernelExpr::Float {
            value: *value,
            bits: *bits,
        }),
        Expr::Bool(value) => Some(KernelExpr::Bool(*value)),
        Expr::Char(value) => Some(KernelExpr::Char(*value)),
        Expr::Ident(name) => Some(KernelExpr::Ident(name.clone())),
        Expr::Group(inner) => Some(KernelExpr::Group(Box::new(lower_expr(
            function,
            inner,
            function_map,
            scope,
            diagnostics,
        )?))),
        Expr::Unary { op, expr } => Some(KernelExpr::Unary {
            op: *op,
            expr: Box::new(lower_expr(
                function,
                expr,
                function_map,
                scope,
                diagnostics,
            )?),
        }),
        Expr::Binary { op, left, right } => Some(KernelExpr::Binary {
            op: *op,
            left: Box::new(lower_expr(
                function,
                left,
                function_map,
                scope,
                diagnostics,
            )?),
            right: Box::new(lower_expr(
                function,
                right,
                function_map,
                scope,
                diagnostics,
            )?),
        }),
        Expr::Call { callee, args } => {
            let callee = base_callee(callee);
            let lowered_args = args
                .iter()
                .filter_map(|arg| lower_expr(function, arg, function_map, scope, diagnostics))
                .collect::<Vec<_>>();
            if lowered_args.len() != args.len() {
                return None;
            }
            if let Some(op) = KernelIntrinsic::from_callee(callee) {
                return Some(KernelExpr::Intrinsic {
                    op,
                    args: lowered_args,
                });
            }
            if callee == "__index_assign" {
                diagnostics.push(lowering_error(
                    function,
                    "indexed assignments must appear as standalone statements in Kernel IR lowering",
                ));
                return None;
            }
            let Some(target) = function_map.get(callee) else {
                diagnostics.push(lowering_error(
                    function,
                    format!("Kernel IR cannot resolve GPU call target `{callee}`"),
                ));
                return None;
            };
            if matches!(target.execution_space, ExecutionSpace::Host) {
                diagnostics.push(lowering_error(
                    function,
                    format!("Kernel IR cannot lower host call `{callee}` inside GPU code"),
                ));
                return None;
            }
            Some(KernelExpr::Call {
                callee: callee.to_string(),
                args: lowered_args,
            })
        }
        Expr::Index { base, index } => {
            let base_ty = infer_expr_type(base, scope);
            if !base_ty.as_ref().is_some_and(is_kernel_indexable_type) {
                diagnostics.push(lowering_error(
                    function,
                    "Kernel IR only supports indexed loads from array, slice, vec, or GpuSlice values",
                ));
                return None;
            }
            Some(KernelExpr::Load {
                base: Box::new(lower_expr(
                    function,
                    base,
                    function_map,
                    scope,
                    diagnostics,
                )?),
                index: Box::new(lower_expr(
                    function,
                    index,
                    function_map,
                    scope,
                    diagnostics,
                )?),
            })
        }
        Expr::Discard(inner) => lower_expr(function, inner, function_map, scope, diagnostics),
        Expr::Str(_)
        | Expr::UnsafeBlock { .. }
        | Expr::FieldAccess { .. }
        | Expr::StructInit { .. }
        | Expr::EnumInit { .. }
        | Expr::Closure { .. }
        | Expr::Tuple(_)
        | Expr::Await(_)
        | Expr::TryCatch { .. }
        | Expr::If { .. }
        | Expr::Match { .. }
        | Expr::While { .. }
        | Expr::For { .. }
        | Expr::ForIn { .. }
        | Expr::Loop { .. }
        | Expr::Break(_)
        | Expr::Continue
        | Expr::Return(_)
        | Expr::Range { .. }
        | Expr::ArrayLiteral(_)
        | Expr::ObjectLiteral(_) => {
            diagnostics.push(lowering_error(
                function,
                format!(
                    "Kernel IR does not yet support expression form `{}`",
                    expr_kind(expr)
                ),
            ));
            None
        }
    }
}

fn infer_expr_type(expr: &Expr, scope: &BTreeMap<String, Type>) -> Option<Type> {
    match expr {
        Expr::Int(_) => Some(Type::Int {
            signed: true,
            bits: 32,
        }),
        Expr::Float { bits, .. } => Some(Type::Float {
            bits: bits.unwrap_or(64),
        }),
        Expr::Bool(_) => Some(Type::Bool),
        Expr::Char(_) => Some(Type::Char),
        Expr::Ident(name) => scope.get(name).cloned(),
        Expr::Group(inner) | Expr::Discard(inner) => infer_expr_type(inner, scope),
        Expr::Index { base, .. } => infer_expr_type(base, scope).and_then(index_element_type),
        Expr::Unary { expr, .. } => infer_expr_type(expr, scope),
        Expr::Binary { op, left, .. } => match op {
            BinaryOp::And
            | BinaryOp::Or
            | BinaryOp::Lt
            | BinaryOp::Lte
            | BinaryOp::Gt
            | BinaryOp::Gte
            | BinaryOp::Eq
            | BinaryOp::Neq => Some(Type::Bool),
            _ => infer_expr_type(left, scope),
        },
        _ => None,
    }
}

fn index_element_type(ty: Type) -> Option<Type> {
    match ty {
        Type::Array { elem, .. } | Type::Slice(elem) | Type::Vec(elem) => Some(*elem),
        Type::Named { name, args } if name == "GpuSlice" && args.len() == 1 => {
            Some(args[0].clone())
        }
        _ => None,
    }
}

fn is_kernel_indexable_type(ty: &Type) -> bool {
    match ty {
        Type::Array { .. } | Type::Slice(_) | Type::Vec(_) => true,
        Type::Named { name, args } => name == "GpuSlice" && args.len() == 1,
        _ => false,
    }
}

fn is_gpu_slice_type(ty: &Type) -> bool {
    matches!(ty, Type::Named { name, args } if name == "GpuSlice" && args.len() == 1)
}

fn base_callee(callee: &str) -> &str {
    callee.split('<').next().unwrap_or(callee)
}

fn expr_kind(expr: &Expr) -> &'static str {
    match expr {
        Expr::Int(_) => "int",
        Expr::Float { .. } => "float",
        Expr::Char(_) => "char",
        Expr::Bool(_) => "bool",
        Expr::Str(_) => "str",
        Expr::Ident(_) => "ident",
        Expr::Call { .. } => "call",
        Expr::UnsafeBlock { .. } => "unsafe block",
        Expr::FieldAccess { .. } => "field access",
        Expr::StructInit { .. } => "struct init",
        Expr::EnumInit { .. } => "enum init",
        Expr::Closure { .. } => "closure",
        Expr::Group(_) => "group",
        Expr::Tuple(_) => "tuple",
        Expr::Await(_) => "await",
        Expr::Discard(_) => "discard",
        Expr::TryCatch { .. } => "try/catch",
        Expr::If { .. } => "if expression",
        Expr::Match { .. } => "match expression",
        Expr::While { .. } => "while expression",
        Expr::For { .. } => "for expression",
        Expr::ForIn { .. } => "for-in expression",
        Expr::Loop { .. } => "loop expression",
        Expr::Break(_) => "break expression",
        Expr::Continue => "continue expression",
        Expr::Return(_) => "return expression",
        Expr::Range { .. } => "range",
        Expr::ArrayLiteral(_) => "array literal",
        Expr::ObjectLiteral(_) => "object literal",
        Expr::Index { .. } => "index",
        Expr::Unary { .. } => "unary",
        Expr::Binary { .. } => "binary",
    }
}

fn lowering_error(function: &hir::TypedFunction, detail: impl Into<String>) -> Diagnostic {
    Diagnostic::new(
        Severity::Error,
        format!(
            "kernel lowering for `{}` failed: {}",
            function.name,
            detail.into()
        ),
        None,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lower_source(source: &str) -> Result<KernelModule, Vec<Diagnostic>> {
        let module = parser::parse(source, "gpu_kernel_ir").expect("parse");
        let typed = hir::lower(&module);
        assert_eq!(typed.type_errors, 0, "{:?}", typed.type_error_details);
        lower(&typed)
    }

    #[test]
    fn lowers_reachable_kernel_call_graph() {
        let lowered = lower_source(
            r#"
            pure fn square(x: f32) -> f32 {
                return x * x;
            }
            device fn map_value(x: f32) -> f32 {
                return square(x);
            }
            kernel fn square_kernel(input: GpuSlice<f32>, output: GpuSlice<f32>, n: i32) -> void {
                let i = gpu.global_id_x();
                if i < n {
                    output[i] = map_value(input[i]);
                }
            }
            pure fn unused(x: f32) -> f32 {
                return x + 1.0;
            }
        "#,
        )
        .expect("kernel ir");
        assert_eq!(lowered.kernels, vec!["square_kernel".to_string()]);
        let names = lowered
            .functions
            .iter()
            .map(|function| function.name.clone())
            .collect::<Vec<_>>();
        assert_eq!(names, vec!["map_value", "square", "square_kernel"]);
        let rendered = render(&lowered);
        assert!(rendered.contains("kernel.entry square_kernel"));
        assert!(rendered.contains("output[i] = map_value(input[i]);"));
    }

    #[test]
    fn lowers_barrier_and_loop_forms() {
        let lowered = lower_source(
            r#"
            kernel fn sync_kernel(limit: i32) -> void {
                let i = 0;
                while i < limit {
                    gpu.barrier();
                    break;
                }
                loop {
                    continue;
                }
            }
        "#,
        )
        .expect("kernel ir");
        let rendered = render(&lowered);
        assert!(rendered.contains("intrinsic.barrier();"));
        assert!(rendered.contains("while i < limit {"));
        assert!(rendered.contains("loop {"));
    }

    #[test]
    fn rejects_match_statements_in_gpu_functions() {
        let module = parser::parse(
            r#"
            device fn classify(flag: bool) -> i32 {
                match flag {
                    true => return 1,
                    _ => return 0,
                }
            }
            kernel fn main(output: GpuSlice<i32>) -> void {
                output[0] = classify(true);
            }
        "#,
            "gpu_kernel_match",
        )
        .expect("parse");
        let typed = hir::lower(&module);
        assert_eq!(typed.type_errors, 0, "{:?}", typed.type_error_details);
        let errors = lower(&typed).expect_err("kernel ir should reject match");
        assert!(errors.iter().any(|error| error
            .message
            .contains("Kernel IR does not yet support `match` statements in GPU functions")));
    }
}

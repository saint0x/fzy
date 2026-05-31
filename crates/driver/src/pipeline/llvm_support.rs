use super::*;
use std::collections::BTreeMap;

#[derive(Clone)]
pub(super) struct LlvmClosureBinding {
    pub(super) params: Vec<ast::Param>,
    pub(super) return_type: Option<ast::Type>,
    pub(super) body: ast::Expr,
    pub(super) captures: HashMap<String, LlvmCaptureBinding>,
}

#[derive(Clone)]
pub(super) struct LlvmCaptureBinding {
    pub(super) slot: String,
    pub(super) ty: String,
}

#[derive(Clone)]
pub(super) struct LlvmValue {
    pub(super) value: String,
    pub(super) ty: String,
}

#[derive(Clone)]
pub(super) struct LlvmArrayBinding {
    pub(super) storage: String,
    pub(super) len: usize,
    pub(super) element_ty: String,
    pub(super) element_bits: u16,
    pub(super) element_align: u8,
    pub(super) element_stride: u8,
}

#[derive(Clone)]
pub(super) struct LlvmFunctionSig {
    pub(super) params: Vec<String>,
    pub(super) ret: Option<String>,
    pub(super) param_names: Vec<String>,
    pub(super) is_extern_c_import: bool,
}

#[derive(Clone)]
pub(super) struct LlvmAggregateItemBinding {
    pub(super) index: usize,
    pub(super) ty: String,
}

#[derive(Clone, Default)]
pub(super) struct LlvmAggregateBinding {
    pub(super) items: HashMap<String, LlvmAggregateItemBinding>,
}

pub(super) struct LlvmFuncCtx {
    pub(super) next_value: usize,
    pub(super) next_label: usize,
    pub(super) slots: HashMap<String, String>,
    pub(super) slot_tys: HashMap<String, String>,
    pub(super) array_slots: HashMap<String, LlvmArrayBinding>,
    pub(super) const_strings: HashMap<String, String>,
    pub(super) direct_values: HashMap<String, LlvmValue>,
    pub(super) aggregate_bindings: HashMap<String, LlvmAggregateBinding>,
    pub(super) wrapped_indices: HashMap<String, HashSet<usize>>,
    pub(super) extern_link_symbols: HashMap<String, String>,
    pub(super) closures: HashMap<String, LlvmClosureBinding>,
    pub(super) function_sigs: HashMap<String, LlvmFunctionSig>,
    pub(super) globals: HashMap<String, i32>,
    pub(super) variant_tags: HashMap<String, i32>,
    pub(super) mutable_globals: HashMap<String, String>,
    pub(super) local_types: BTreeMap<String, ast::Type>,
    pub(super) struct_defs: HashMap<String, ast::Struct>,
    pub(super) enum_defs: HashMap<String, ast::Enum>,
    pub(super) current_namespace: String,
    pub(super) function_return_ty: String,
    pub(super) alloca_prologue: String,
    pub(super) declared_allocas: HashSet<String>,
    pub(super) code: String,
}

impl LlvmFuncCtx {
    pub(super) fn new(
        current_function_name: &str,
        globals: HashMap<String, i32>,
        variant_tags: HashMap<String, i32>,
        mutable_globals: HashMap<String, String>,
        local_types: BTreeMap<String, ast::Type>,
        struct_defs: HashMap<String, ast::Struct>,
        enum_defs: HashMap<String, ast::Enum>,
        function_return_ty: String,
        wrapped_indices: HashMap<String, HashSet<usize>>,
        extern_link_symbols: HashMap<String, String>,
        function_sigs: HashMap<String, LlvmFunctionSig>,
    ) -> Self {
        Self {
            next_value: 0,
            next_label: 0,
            slots: HashMap::new(),
            slot_tys: HashMap::new(),
            array_slots: HashMap::new(),
            const_strings: HashMap::new(),
            direct_values: HashMap::new(),
            aggregate_bindings: HashMap::new(),
            wrapped_indices,
            extern_link_symbols,
            closures: HashMap::new(),
            function_sigs,
            globals,
            variant_tags,
            mutable_globals,
            local_types,
            struct_defs,
            enum_defs,
            current_namespace: native_current_namespace(current_function_name).to_string(),
            function_return_ty,
            alloca_prologue: String::new(),
            declared_allocas: HashSet::new(),
            code: String::new(),
        }
    }

    pub(super) fn value(&mut self) -> String {
        let id = self.next_value;
        self.next_value += 1;
        format!("%v{id}")
    }

    pub(super) fn label(&mut self, prefix: &str) -> String {
        let id = self.next_label;
        self.next_label += 1;
        format!("{prefix}.{id}")
    }

    pub(super) fn declare_alloca(&mut self, slot: &str, ty: &str) {
        if self.declared_allocas.insert(slot.to_string()) {
            self.alloca_prologue
                .push_str(&format!("  {slot} = alloca {ty}\n"));
        }
    }
}

fn llvm_cast_scalar_to_i64(ctx: &mut LlvmFuncCtx, value: LlvmValue) -> LlvmValue {
    match value.ty.as_str() {
        "i64" => value,
        "i32" | "i8" | "i1" => {
            let out = ctx.value();
            ctx.code.push_str(&format!(
                "  {out} = zext {} {} to i64\n",
                value.ty, value.value
            ));
            LlvmValue {
                value: out,
                ty: "i64".to_string(),
            }
        }
        _ => value,
    }
}

fn llvm_parse_simd_intrinsic(callee: &str) -> Option<(&str, &str)> {
    let body = callee.strip_prefix("simd.__")?;
    for kind in ["i32x4", "u32x4", "f32x4", "mask32x4"] {
        if let Some(op) = body.strip_prefix(kind) {
            return Some((kind, op));
        }
    }
    None
}

fn llvm_simd_vector_type(kind: &str) -> &'static str {
    match kind {
        "i32x4" | "u32x4" => "<4 x i32>",
        "f32x4" => "<4 x float>",
        "mask32x4" => "<4 x i1>",
        _ => "i32",
    }
}

fn llvm_simd_scalar_type(kind: &str) -> &'static str {
    match kind {
        "f32x4" => "float",
        "mask32x4" => "i1",
        _ => "i32",
    }
}

fn llvm_pointer_int_type() -> &'static str {
    if std::mem::size_of::<usize>() == 8 {
        "i64"
    } else {
        "i32"
    }
}

fn llvm_expr_is_fzy_str(expr: &ast::Expr, ctx: &LlvmFuncCtx) -> bool {
    match expr {
        ast::Expr::Str(_) => true,
        ast::Expr::Ident(name) => matches!(ctx.local_types.get(name), Some(ast::Type::Str)),
        ast::Expr::Group(inner) | ast::Expr::Await(inner) | ast::Expr::Discard(inner) => {
            llvm_expr_is_fzy_str(inner, ctx)
        }
        _ => false,
    }
}

fn llvm_is_extern_c_borrowed_ptr_param(sig: &LlvmFunctionSig, index: usize) -> bool {
    sig.is_extern_c_import
        && sig
            .param_names
            .get(index)
            .is_some_and(|name| name.contains("_borrowed"))
        && sig
            .params
            .get(index)
            .is_some_and(|ty| ty == llvm_pointer_int_type())
}

fn llvm_emit_borrowed_str_ptr_arg(
    arg: &ast::Expr,
    ctx: &mut LlvmFuncCtx,
    string_literal_ids: &HashMap<String, i32>,
    task_ref_ids: &HashMap<String, i32>,
) -> Result<LlvmValue> {
    let string_id = llvm_emit_expr_as(arg, ctx, string_literal_ids, task_ref_ids, "i32")?;
    let ptr = ctx.value();
    let symbol = native_mangle_symbol(NATIVE_STR_PTR_SYMBOL);
    ctx.code.push_str(&format!(
        "  {ptr} = call {} @{symbol}(i32 {})\n",
        llvm_pointer_int_type(),
        string_id.value
    ));
    Ok(LlvmValue {
        value: ptr,
        ty: llvm_pointer_int_type().to_string(),
    })
}

fn llvm_emit_simd_ptr_alignment_check(
    kind: &str,
    op: &str,
    ptr_int_value: &str,
    ptr_int_ty: &str,
    ctx: &mut LlvmFuncCtx,
) {
    if !op.contains("_aligned_") {
        return;
    }
    let align = if kind == "mask32x4" { 4 } else { 16 };
    let masked = ctx.value();
    let aligned = ctx.value();
    let ok_label = ctx.label("simd_ptr_align_ok");
    let trap_label = ctx.label("simd_ptr_align_trap");
    ctx.code.push_str(&format!(
        "  {masked} = and {ptr_int_ty} {ptr_int_value}, {}\n  {aligned} = icmp eq {ptr_int_ty} {masked}, 0\n  br i1 {aligned}, label %{ok_label}, label %{trap_label}\n",
        align - 1
    ));
    ctx.code.push_str(&format!("{trap_label}:\n"));
    ctx.code
        .push_str("  call void @llvm.trap()\n  unreachable\n");
    ctx.code.push_str(&format!("{ok_label}:\n"));
}

fn llvm_emit_simd_ptr_memory(
    kind: &str,
    op: &str,
    args: &[ast::Expr],
    ctx: &mut LlvmFuncCtx,
    string_literal_ids: &HashMap<String, i32>,
    task_ref_ids: &HashMap<String, i32>,
) -> Result<LlvmValue> {
    let lowered_ptr = llvm_emit_expr_as(
        &args[0],
        ctx,
        string_literal_ids,
        task_ref_ids,
        llvm_pointer_int_type(),
    )?;
    llvm_emit_simd_ptr_alignment_check(kind, op, &lowered_ptr.value, &lowered_ptr.ty, ctx);
    let base_ptr = {
        let ptr = ctx.value();
        ctx.code.push_str(&format!(
            "  {ptr} = inttoptr {} {} to ptr\n",
            lowered_ptr.ty, lowered_ptr.value
        ));
        ptr
    };
    let is_aligned = op.contains("_aligned_");
    let align = if is_aligned {
        if kind == "mask32x4" {
            4
        } else {
            16
        }
    } else {
        1
    };
    let vec_ty = llvm_simd_vector_type(kind).to_string();
    if op.starts_with("_load_") {
        if kind == "mask32x4" {
            let mut lanes = Vec::with_capacity(4);
            for index in 0..4 {
                let lane_ptr = if index == 0 {
                    base_ptr.clone()
                } else {
                    let next = ctx.value();
                    ctx.code.push_str(&format!(
                        "  {next} = getelementptr inbounds i8, ptr {base_ptr}, i64 {index}\n"
                    ));
                    next
                };
                let loaded = ctx.value();
                let pred = ctx.value();
                ctx.code.push_str(&format!(
                    "  {loaded} = load i8, ptr {lane_ptr}, align 1\n  {pred} = icmp ne i8 {loaded}, 0\n"
                ));
                lanes.push(pred);
            }
            let mut current = "undef".to_string();
            for (index, lane) in lanes.iter().enumerate() {
                let next = ctx.value();
                ctx.code.push_str(&format!(
                    "  {next} = insertelement {vec_ty} {current}, i1 {lane}, i32 {index}\n"
                ));
                current = next;
            }
            return Ok(LlvmValue {
                value: current,
                ty: vec_ty,
            });
        }
        let out = ctx.value();
        ctx.code.push_str(&format!(
            "  {out} = load {vec_ty}, ptr {base_ptr}, align {align}\n"
        ));
        return Ok(LlvmValue {
            value: out,
            ty: vec_ty,
        });
    }

    let value = llvm_emit_expr_as(&args[1], ctx, string_literal_ids, task_ref_ids, &vec_ty)?;
    if kind == "mask32x4" {
        for index in 0..4 {
            let lane = ctx.value();
            let widened = ctx.value();
            let lane_ptr = if index == 0 {
                base_ptr.clone()
            } else {
                let next = ctx.value();
                ctx.code.push_str(&format!(
                    "  {next} = getelementptr inbounds i8, ptr {base_ptr}, i64 {index}\n"
                ));
                next
            };
            ctx.code.push_str(&format!(
                "  {lane} = extractelement {vec_ty} {}, i32 {index}\n  {widened} = zext i1 {lane} to i8\n  store i8 {widened}, ptr {lane_ptr}, align 1\n",
                value.value
            ));
        }
    } else {
        ctx.code.push_str(&format!(
            "  store {vec_ty} {}, ptr {base_ptr}, align {align}\n",
            value.value
        ));
    }
    Ok(LlvmValue {
        value: "0".to_string(),
        ty: "i32".to_string(),
    })
}

fn llvm_simd_bool_splat_literal() -> &'static str {
    "<i1 true, i1 true, i1 true, i1 true>"
}

fn llvm_simd_i32_all_ones_literal() -> &'static str {
    "<i32 -1, i32 -1, i32 -1, i32 -1>"
}

fn llvm_emit_simd_lane_value(
    arg: &ast::Expr,
    kind: &str,
    ctx: &mut LlvmFuncCtx,
    string_literal_ids: &HashMap<String, i32>,
    task_ref_ids: &HashMap<String, i32>,
) -> Result<String> {
    if kind == "mask32x4" {
        let value = llvm_emit_expr(arg, ctx, string_literal_ids, task_ref_ids)?;
        Ok(llvm_emit_truthy_pred(ctx, &value))
    } else {
        Ok(llvm_emit_expr_as(
            arg,
            ctx,
            string_literal_ids,
            task_ref_ids,
            llvm_simd_scalar_type(kind),
        )?
        .value)
    }
}

fn llvm_emit_simd_ctor_from_lanes(
    kind: &str,
    args: &[ast::Expr],
    ctx: &mut LlvmFuncCtx,
    string_literal_ids: &HashMap<String, i32>,
    task_ref_ids: &HashMap<String, i32>,
) -> Result<LlvmValue> {
    let vec_ty = llvm_simd_vector_type(kind).to_string();
    let lane_ty = llvm_simd_scalar_type(kind);
    let mut current = "undef".to_string();
    for (index, arg) in args.iter().enumerate() {
        let lane = llvm_emit_simd_lane_value(arg, kind, ctx, string_literal_ids, task_ref_ids)?;
        let next = ctx.value();
        ctx.code.push_str(&format!(
            "  {next} = insertelement {vec_ty} {current}, {lane_ty} {lane}, i32 {index}\n"
        ));
        current = next;
    }
    Ok(LlvmValue {
        value: current,
        ty: vec_ty,
    })
}

fn llvm_emit_simd_splat(
    kind: &str,
    arg: &ast::Expr,
    ctx: &mut LlvmFuncCtx,
    string_literal_ids: &HashMap<String, i32>,
    task_ref_ids: &HashMap<String, i32>,
) -> Result<LlvmValue> {
    let vec_ty = llvm_simd_vector_type(kind).to_string();
    let lane_ty = llvm_simd_scalar_type(kind);
    let lane = llvm_emit_simd_lane_value(arg, kind, ctx, string_literal_ids, task_ref_ids)?;
    let mut current = "undef".to_string();
    for index in 0..4 {
        let next = ctx.value();
        ctx.code.push_str(&format!(
            "  {next} = insertelement {vec_ty} {current}, {lane_ty} {lane}, i32 {index}\n"
        ));
        current = next;
    }
    Ok(LlvmValue {
        value: current,
        ty: vec_ty,
    })
}

fn llvm_emit_simd_load_from_array(
    kind: &str,
    arg: &ast::Expr,
    ctx: &mut LlvmFuncCtx,
    string_literal_ids: &HashMap<String, i32>,
    task_ref_ids: &HashMap<String, i32>,
) -> Result<LlvmValue> {
    let vec_ty = llvm_simd_vector_type(kind).to_string();
    let lane_ty = llvm_simd_scalar_type(kind);
    let mut current = "undef".to_string();
    for index in 0..4 {
        let lane_expr = ast::Expr::Index {
            base: Box::new(arg.clone()),
            index: Box::new(ast::Expr::Int(index as i128)),
        };
        let lane =
            llvm_emit_simd_lane_value(&lane_expr, kind, ctx, string_literal_ids, task_ref_ids)?;
        let next = ctx.value();
        ctx.code.push_str(&format!(
            "  {next} = insertelement {vec_ty} {current}, {lane_ty} {lane}, i32 {index}\n"
        ));
        current = next;
    }
    Ok(LlvmValue {
        value: current,
        ty: vec_ty,
    })
}

fn llvm_array_layout_for_element_ty(element_ty: &str) -> (u16, u8, u8) {
    match element_ty {
        "i8" => (8, 1, 1),
        "i32" | "float" => (32, 4, 4),
        "i64" | "double" => (64, 8, 8),
        _ => (32, 4, 4),
    }
}

fn llvm_array_binding_from_type(slot: &str, ty: &ast::Type) -> Option<LlvmArrayBinding> {
    let ast::Type::Array { elem, len } = ty else {
        return None;
    };
    let element_ty = llvm_ir_type_for_ast_type(elem);
    let (element_bits, element_align, element_stride) =
        llvm_array_layout_for_element_ty(&element_ty);
    Some(LlvmArrayBinding {
        storage: slot.to_string(),
        len: *len,
        element_ty,
        element_bits,
        element_align,
        element_stride,
    })
}

fn llvm_parse_array_ir_type(ty: &str) -> Option<(usize, String)> {
    let ty = ty.trim();
    let inner = ty.strip_prefix('[')?.strip_suffix(']')?;
    let (len, element_ty) = inner.split_once(" x ")?;
    let len = len.parse::<usize>().ok()?;
    Some((len, element_ty.trim().to_string()))
}

fn llvm_array_binding_from_ir_type(slot: &str, ty: &str) -> Option<LlvmArrayBinding> {
    let (len, element_ty) = llvm_parse_array_ir_type(ty)?;
    let (element_bits, element_align, element_stride) =
        llvm_array_layout_for_element_ty(&element_ty);
    Some(LlvmArrayBinding {
        storage: slot.to_string(),
        len,
        element_ty,
        element_bits,
        element_align,
        element_stride,
    })
}

pub(super) fn llvm_emit_array_literal_value(
    items: &[ast::Expr],
    ctx: &mut LlvmFuncCtx,
    string_literal_ids: &HashMap<String, i32>,
    task_ref_ids: &HashMap<String, i32>,
) -> Result<LlvmValue> {
    let len = items.len();
    let lowered_items = items
        .iter()
        .map(|item| llvm_emit_expr(item, ctx, string_literal_ids, task_ref_ids))
        .collect::<Result<Vec<_>>>()?;
    let element_ty = lowered_items
        .first()
        .map(|value| value.ty.clone())
        .unwrap_or_else(|| "i32".to_string());
    let array_ty = format!("[{len} x {element_ty}]");
    let storage = format!("%slot_array_literal_{}", ctx.next_value);
    ctx.declare_alloca(&storage, &array_ty);
    for (idx, item) in items.iter().enumerate() {
        let item_value =
            llvm_emit_expr_as(item, ctx, string_literal_ids, task_ref_ids, &element_ty)?;
        let element_ptr = ctx.value();
        ctx.code.push_str(&format!(
            "  {element_ptr} = getelementptr inbounds {array_ty}, ptr {storage}, i32 0, i64 {idx}\n  store {element_ty} {}, ptr {element_ptr}\n",
            item_value.value
        ));
    }
    let loaded = ctx.value();
    ctx.code
        .push_str(&format!("  {loaded} = load {array_ty}, ptr {storage}\n"));
    Ok(LlvmValue {
        value: loaded,
        ty: array_ty,
    })
}

fn llvm_emit_array_index_from_binding(
    binding: LlvmArrayBinding,
    index: &ast::Expr,
    index_value: &str,
    ctx: &mut LlvmFuncCtx,
) -> Result<LlvmValue> {
    if binding.len == 0 {
        return Ok(LlvmValue {
            value: llvm_zero_literal(&binding.element_ty, 0),
            ty: binding.element_ty,
        });
    }
    if let ast::Expr::Ident(index_name) = index {
        if ctx
            .wrapped_indices
            .get(index_name)
            .map(|limits| limits.contains(&binding.len))
            .unwrap_or(false)
        {
            let idx64 = ctx.value();
            let elem_ptr = ctx.value();
            let loaded = ctx.value();
            ctx.code
                .push_str(&format!("  {idx64} = sext i32 {index_value} to i64\n"));
            ctx.code.push_str(&format!(
                "  {elem_ptr} = getelementptr inbounds [{} x {}], ptr {}, i32 0, i64 {idx64}\n",
                binding.len, binding.element_ty, binding.storage
            ));
            ctx.code.push_str(&format!(
                "  {loaded} = load {}, ptr {elem_ptr}\n",
                binding.element_ty
            ));
            return Ok(LlvmValue {
                value: loaded,
                ty: binding.element_ty,
            });
        }
    }
    if let Some(const_idx) = eval_const_i32_expr(index, &ctx.const_strings) {
        if const_idx >= 0 && (const_idx as usize) < binding.len {
            let elem_ptr = ctx.value();
            let loaded = ctx.value();
            ctx.code.push_str(&format!(
                "  {elem_ptr} = getelementptr inbounds [{} x {}], ptr {}, i32 0, i64 {}\n",
                binding.len, binding.element_ty, binding.storage, const_idx
            ));
            ctx.code.push_str(&format!(
                "  {loaded} = load {}, ptr {elem_ptr}\n",
                binding.element_ty
            ));
            return Ok(LlvmValue {
                value: loaded,
                ty: binding.element_ty,
            });
        }
    }
    let in_label = ctx.label("idx.in");
    let out_label = ctx.label("idx.oob");
    let merge_label = ctx.label("idx.merge");
    let ok = ctx.value();
    ctx.code.push_str(&format!(
        "  {ok} = icmp ult i32 {index_value}, {}\n",
        binding.len
    ));
    ctx.code.push_str(&format!(
        "  br i1 {ok}, label %{in_label}, label %{out_label}\n"
    ));
    ctx.code.push_str(&format!("{in_label}:\n"));
    let idx64 = ctx.value();
    let elem_ptr = ctx.value();
    let loaded = ctx.value();
    ctx.code
        .push_str(&format!("  {idx64} = sext i32 {index_value} to i64\n"));
    ctx.code.push_str(&format!(
        "  {elem_ptr} = getelementptr inbounds [{} x {}], ptr {}, i32 0, i64 {idx64}\n",
        binding.len, binding.element_ty, binding.storage
    ));
    ctx.code.push_str(&format!(
        "  {loaded} = load {}, ptr {elem_ptr}\n",
        binding.element_ty
    ));
    ctx.code.push_str(&format!("  br label %{merge_label}\n"));
    ctx.code.push_str(&format!("{out_label}:\n"));
    ctx.code.push_str(&format!("  br label %{merge_label}\n"));
    ctx.code.push_str(&format!("{merge_label}:\n"));
    let selected = ctx.value();
    ctx.code.push_str(&format!(
        "  {selected} = phi {} [ {loaded}, %{in_label} ], [ {}, %{out_label} ]\n",
        binding.element_ty,
        llvm_zero_literal(&binding.element_ty, 0)
    ));
    let _ = (
        binding.element_bits,
        binding.element_align,
        binding.element_stride,
    );
    Ok(LlvmValue {
        value: selected,
        ty: binding.element_ty,
    })
}

fn llvm_emit_simd_saturating_int_binop(
    kind: &str,
    op: &str,
    vec_ty: &str,
    scalar_ty: &str,
    args: &[ast::Expr],
    ctx: &mut LlvmFuncCtx,
    string_literal_ids: &HashMap<String, i32>,
    task_ref_ids: &HashMap<String, i32>,
) -> Result<LlvmValue> {
    let lhs = llvm_emit_expr_as(&args[0], ctx, string_literal_ids, task_ref_ids, vec_ty)?;
    let rhs = llvm_emit_expr_as(&args[1], ctx, string_literal_ids, task_ref_ids, vec_ty)?;
    let mut current = "undef".to_string();
    for index in 0..4 {
        let lhs_lane = ctx.value();
        let rhs_lane = ctx.value();
        ctx.code.push_str(&format!(
            "  {lhs_lane} = extractelement {vec_ty} {}, i32 {index}\n",
            lhs.value
        ));
        ctx.code.push_str(&format!(
            "  {rhs_lane} = extractelement {vec_ty} {}, i32 {index}\n",
            rhs.value
        ));
        let clamped_lane = if kind == "i32x4" {
            let lhs_i64 = ctx.value();
            let rhs_i64 = ctx.value();
            let wide = ctx.value();
            let below = ctx.value();
            let above = ctx.value();
            let lower_sel = ctx.value();
            let upper_sel = ctx.value();
            let clamped = ctx.value();
            ctx.code
                .push_str(&format!("  {lhs_i64} = sext i32 {lhs_lane} to i64\n"));
            ctx.code
                .push_str(&format!("  {rhs_i64} = sext i32 {rhs_lane} to i64\n"));
            let wide_op = if op == "_saturating_add" {
                "add"
            } else {
                "sub"
            };
            ctx.code
                .push_str(&format!("  {wide} = {wide_op} i64 {lhs_i64}, {rhs_i64}\n"));
            ctx.code
                .push_str(&format!("  {below} = icmp slt i64 {wide}, -2147483648\n"));
            ctx.code
                .push_str(&format!("  {above} = icmp sgt i64 {wide}, 2147483647\n"));
            ctx.code.push_str(&format!(
                "  {lower_sel} = select i1 {below}, i64 -2147483648, i64 {wide}\n"
            ));
            ctx.code.push_str(&format!(
                "  {upper_sel} = select i1 {above}, i64 2147483647, i64 {lower_sel}\n"
            ));
            ctx.code
                .push_str(&format!("  {clamped} = trunc i64 {upper_sel} to i32\n"));
            clamped
        } else {
            let lhs_i64 = ctx.value();
            let rhs_i64 = ctx.value();
            ctx.code
                .push_str(&format!("  {lhs_i64} = zext i32 {lhs_lane} to i64\n"));
            ctx.code
                .push_str(&format!("  {rhs_i64} = zext i32 {rhs_lane} to i64\n"));
            if op == "_saturating_add" {
                let wide = ctx.value();
                let overflow = ctx.value();
                let clamped_i64 = ctx.value();
                let clamped = ctx.value();
                ctx.code
                    .push_str(&format!("  {wide} = add i64 {lhs_i64}, {rhs_i64}\n"));
                ctx.code
                    .push_str(&format!("  {overflow} = icmp ugt i64 {wide}, 4294967295\n"));
                ctx.code.push_str(&format!(
                    "  {clamped_i64} = select i1 {overflow}, i64 4294967295, i64 {wide}\n"
                ));
                ctx.code
                    .push_str(&format!("  {clamped} = trunc i64 {clamped_i64} to i32\n"));
                clamped
            } else {
                let underflow = ctx.value();
                let wide = ctx.value();
                let clamped_i64 = ctx.value();
                let clamped = ctx.value();
                ctx.code.push_str(&format!(
                    "  {underflow} = icmp ult i64 {lhs_i64}, {rhs_i64}\n"
                ));
                ctx.code
                    .push_str(&format!("  {wide} = sub i64 {lhs_i64}, {rhs_i64}\n"));
                ctx.code.push_str(&format!(
                    "  {clamped_i64} = select i1 {underflow}, i64 0, i64 {wide}\n"
                ));
                ctx.code
                    .push_str(&format!("  {clamped} = trunc i64 {clamped_i64} to i32\n"));
                clamped
            }
        };
        let next = ctx.value();
        ctx.code.push_str(&format!(
            "  {next} = insertelement {vec_ty} {current}, {scalar_ty} {clamped_lane}, i32 {index}\n"
        ));
        current = next;
    }
    Ok(LlvmValue {
        value: current,
        ty: vec_ty.to_string(),
    })
}

fn llvm_emit_simd_reduce_scalar(
    kind: &str,
    op: &str,
    vec_ty: &str,
    scalar_ty: &str,
    arg: &ast::Expr,
    ctx: &mut LlvmFuncCtx,
    string_literal_ids: &HashMap<String, i32>,
    task_ref_ids: &HashMap<String, i32>,
) -> Result<LlvmValue> {
    let input = llvm_emit_expr_as(arg, ctx, string_literal_ids, task_ref_ids, vec_ty)?;
    let mut lanes = Vec::with_capacity(4);
    for index in 0..4 {
        let lane = ctx.value();
        ctx.code.push_str(&format!(
            "  {lane} = extractelement {vec_ty} {}, i32 {index}\n",
            input.value
        ));
        lanes.push(lane);
    }
    let fold_name = match op {
        "_reduce_add" if kind == "f32x4" => "fadd",
        "_reduce_add" => "add",
        _ => "",
    };
    if !fold_name.is_empty() {
        let fold0 = ctx.value();
        let fold1 = ctx.value();
        let fold2 = ctx.value();
        ctx.code.push_str(&format!(
            "  {fold0} = {fold_name} {scalar_ty} {}, {}\n",
            lanes[0], lanes[1]
        ));
        ctx.code.push_str(&format!(
            "  {fold1} = {fold_name} {scalar_ty} {fold0}, {}\n",
            lanes[2]
        ));
        ctx.code.push_str(&format!(
            "  {fold2} = {fold_name} {scalar_ty} {fold1}, {}\n",
            lanes[3]
        ));
        return Ok(LlvmValue {
            value: fold2,
            ty: scalar_ty.to_string(),
        });
    }
    let cmp = match (kind, op) {
        ("f32x4", "_reduce_min") => "olt",
        ("f32x4", "_reduce_max") => "ogt",
        ("u32x4", "_reduce_min") => "ult",
        ("u32x4", "_reduce_max") => "ugt",
        (_, "_reduce_min") => "slt",
        (_, "_reduce_max") => "sgt",
        _ => unreachable!(),
    };
    let mut current = lanes[0].clone();
    for lane in lanes.iter().skip(1) {
        let pred = ctx.value();
        let selected = ctx.value();
        let cmp_op = if kind == "f32x4" { "fcmp" } else { "icmp" };
        ctx.code.push_str(&format!(
            "  {pred} = {cmp_op} {cmp} {scalar_ty} {lane}, {current}\n"
        ));
        ctx.code.push_str(&format!(
            "  {selected} = select i1 {pred}, {scalar_ty} {lane}, {scalar_ty} {current}\n"
        ));
        current = selected;
    }
    Ok(LlvmValue {
        value: current,
        ty: scalar_ty.to_string(),
    })
}

fn llvm_emit_simd_intrinsic_call(
    callee: &str,
    args: &[ast::Expr],
    ctx: &mut LlvmFuncCtx,
    string_literal_ids: &HashMap<String, i32>,
    task_ref_ids: &HashMap<String, i32>,
) -> Result<Option<LlvmValue>> {
    let Some((kind, op)) = llvm_parse_simd_intrinsic(callee) else {
        return Ok(None);
    };
    let vec_ty = llvm_simd_vector_type(kind).to_string();
    let scalar_ty = llvm_simd_scalar_type(kind);
    let mask_ty = llvm_simd_vector_type("mask32x4").to_string();
    let value = match op {
        "" => llvm_emit_simd_ctor_from_lanes(kind, args, ctx, string_literal_ids, task_ref_ids)?,
        "_splat" => llvm_emit_simd_splat(kind, &args[0], ctx, string_literal_ids, task_ref_ids)?,
        "_load" => {
            llvm_emit_simd_load_from_array(kind, &args[0], ctx, string_literal_ids, task_ref_ids)?
        }
        "_load_aligned_ptr"
        | "_load_unaligned_ptr"
        | "_store_aligned_ptr"
        | "_store_unaligned_ptr" => {
            llvm_emit_simd_ptr_memory(kind, op, args, ctx, string_literal_ids, task_ref_ids)?
        }
        "_saturating_add" | "_saturating_sub" => llvm_emit_simd_saturating_int_binop(
            kind,
            op,
            &vec_ty,
            scalar_ty,
            args,
            ctx,
            string_literal_ids,
            task_ref_ids,
        )?,
        "_add" | "_sub" | "_mul" | "_and" | "_or" | "_xor" => {
            let lhs = llvm_emit_expr_as(&args[0], ctx, string_literal_ids, task_ref_ids, &vec_ty)?;
            let rhs = llvm_emit_expr_as(&args[1], ctx, string_literal_ids, task_ref_ids, &vec_ty)?;
            let op_name = match op {
                "_add" if kind == "f32x4" => "fadd",
                "_sub" if kind == "f32x4" => "fsub",
                "_mul" if kind == "f32x4" => "fmul",
                "_add" => "add",
                "_sub" => "sub",
                "_mul" => "mul",
                "_and" => "and",
                "_or" => "or",
                "_xor" => "xor",
                _ => unreachable!(),
            };
            let out = ctx.value();
            ctx.code.push_str(&format!(
                "  {out} = {op_name} {vec_ty} {}, {}\n",
                lhs.value, rhs.value
            ));
            LlvmValue {
                value: out,
                ty: vec_ty,
            }
        }
        "_shl" | "_shr" => {
            let lhs = llvm_emit_expr_as(&args[0], ctx, string_literal_ids, task_ref_ids, &vec_ty)?;
            let rhs =
                llvm_emit_simd_splat("i32x4", &args[1], ctx, string_literal_ids, task_ref_ids)?;
            let out = ctx.value();
            let op_name = match (kind, op) {
                ("u32x4", "_shr") => "lshr",
                (_, "_shr") => "ashr",
                _ => "shl",
            };
            ctx.code.push_str(&format!(
                "  {out} = {op_name} {vec_ty} {}, {}\n",
                lhs.value, rhs.value
            ));
            LlvmValue {
                value: out,
                ty: vec_ty,
            }
        }
        "_min" | "_max" => {
            let lhs = llvm_emit_expr_as(&args[0], ctx, string_literal_ids, task_ref_ids, &vec_ty)?;
            let rhs = llvm_emit_expr_as(&args[1], ctx, string_literal_ids, task_ref_ids, &vec_ty)?;
            let pred = ctx.value();
            if kind == "f32x4" {
                let cc = if op == "_min" { "olt" } else { "ogt" };
                ctx.code.push_str(&format!(
                    "  {pred} = fcmp {cc} {vec_ty} {}, {}\n",
                    lhs.value, rhs.value
                ));
            } else {
                let cc = match (kind, op) {
                    ("u32x4", "_min") => "ult",
                    ("u32x4", "_max") => "ugt",
                    (_, "_min") => "slt",
                    _ => "sgt",
                };
                ctx.code.push_str(&format!(
                    "  {pred} = icmp {cc} {vec_ty} {}, {}\n",
                    lhs.value, rhs.value
                ));
            }
            let out = ctx.value();
            ctx.code.push_str(&format!(
                "  {out} = select {mask_ty} {pred}, {vec_ty} {}, {vec_ty} {}\n",
                lhs.value, rhs.value
            ));
            LlvmValue {
                value: out,
                ty: vec_ty,
            }
        }
        "_not" => {
            let input =
                llvm_emit_expr_as(&args[0], ctx, string_literal_ids, task_ref_ids, &vec_ty)?;
            let out = ctx.value();
            let literal = if kind == "mask32x4" {
                llvm_simd_bool_splat_literal()
            } else {
                llvm_simd_i32_all_ones_literal()
            };
            ctx.code.push_str(&format!(
                "  {out} = xor {vec_ty} {}, {literal}\n",
                input.value
            ));
            LlvmValue {
                value: out,
                ty: vec_ty,
            }
        }
        "_eq" | "_ne" | "_lt" | "_le" | "_gt" | "_ge" => {
            let lhs = llvm_emit_expr_as(&args[0], ctx, string_literal_ids, task_ref_ids, &vec_ty)?;
            let rhs = llvm_emit_expr_as(&args[1], ctx, string_literal_ids, task_ref_ids, &vec_ty)?;
            let out = ctx.value();
            if kind == "f32x4" {
                let cc = match op {
                    "_eq" => "oeq",
                    "_ne" => "une",
                    "_lt" => "olt",
                    "_le" => "ole",
                    "_gt" => "ogt",
                    "_ge" => "oge",
                    _ => unreachable!(),
                };
                ctx.code.push_str(&format!(
                    "  {out} = fcmp {cc} {vec_ty} {}, {}\n",
                    lhs.value, rhs.value
                ));
            } else {
                let cc = match op {
                    "_eq" => "eq",
                    "_ne" => "ne",
                    "_lt" if kind == "u32x4" => "ult",
                    "_le" if kind == "u32x4" => "ule",
                    "_gt" if kind == "u32x4" => "ugt",
                    "_ge" if kind == "u32x4" => "uge",
                    "_lt" => "slt",
                    "_le" => "sle",
                    "_gt" => "sgt",
                    "_ge" => "sge",
                    _ => unreachable!(),
                };
                ctx.code.push_str(&format!(
                    "  {out} = icmp {cc} {vec_ty} {}, {}\n",
                    lhs.value, rhs.value
                ));
            }
            LlvmValue {
                value: out,
                ty: mask_ty,
            }
        }
        "_select" => {
            let mask =
                llvm_emit_expr_as(&args[0], ctx, string_literal_ids, task_ref_ids, &mask_ty)?;
            let then_vec =
                llvm_emit_expr_as(&args[1], ctx, string_literal_ids, task_ref_ids, &vec_ty)?;
            let else_vec =
                llvm_emit_expr_as(&args[2], ctx, string_literal_ids, task_ref_ids, &vec_ty)?;
            let out = ctx.value();
            ctx.code.push_str(&format!(
                "  {out} = select {mask_ty} {}, {vec_ty} {}, {vec_ty} {}\n",
                mask.value, then_vec.value, else_vec.value
            ));
            LlvmValue {
                value: out,
                ty: vec_ty,
            }
        }
        "_shuffle" => {
            let lhs = llvm_emit_expr_as(&args[0], ctx, string_literal_ids, task_ref_ids, &vec_ty)?;
            let rhs = llvm_emit_expr_as(&args[1], ctx, string_literal_ids, task_ref_ids, &vec_ty)?;
            let mut current = "undef".to_string();
            for (lane_index, arg) in args[2..].iter().enumerate() {
                let selector =
                    llvm_emit_expr_as(arg, ctx, string_literal_ids, task_ref_ids, "i32")?;
                let ge_zero = ctx.value();
                let lt_eight = ctx.value();
                let in_range = ctx.value();
                let ok_label = ctx.label("simd_shuffle_ok");
                let trap_label = ctx.label("simd_shuffle_trap");
                ctx.code.push_str(&format!(
                    "  {ge_zero} = icmp sge i32 {}, 0\n",
                    selector.value
                ));
                ctx.code.push_str(&format!(
                    "  {lt_eight} = icmp slt i32 {}, 8\n",
                    selector.value
                ));
                ctx.code
                    .push_str(&format!("  {in_range} = and i1 {ge_zero}, {lt_eight}\n"));
                ctx.code.push_str(&format!(
                    "  br i1 {in_range}, label %{ok_label}, label %{trap_label}\n"
                ));
                ctx.code.push_str(&format!("{trap_label}:\n"));
                ctx.code
                    .push_str("  call void @llvm.trap()\n  unreachable\n");
                ctx.code.push_str(&format!("{ok_label}:\n"));

                let use_left = ctx.value();
                let right_index = ctx.value();
                let left_lane = ctx.value();
                let right_lane = ctx.value();
                let picked_lane = ctx.value();
                let next = ctx.value();
                ctx.code.push_str(&format!(
                    "  {use_left} = icmp slt i32 {}, 4\n",
                    selector.value
                ));
                ctx.code.push_str(&format!(
                    "  {right_index} = sub i32 {}, 4\n",
                    selector.value
                ));
                ctx.code.push_str(&format!(
                    "  {left_lane} = extractelement {vec_ty} {}, i32 {}\n",
                    lhs.value, selector.value
                ));
                ctx.code.push_str(&format!(
                    "  {right_lane} = extractelement {vec_ty} {}, i32 {right_index}\n",
                    rhs.value
                ));
                ctx.code.push_str(&format!(
                    "  {picked_lane} = select i1 {use_left}, {scalar_ty} {left_lane}, {scalar_ty} {right_lane}\n"
                ));
                ctx.code.push_str(&format!(
                    "  {next} = insertelement {vec_ty} {current}, {scalar_ty} {picked_lane}, i32 {lane_index}\n"
                ));
                current = next;
            }
            LlvmValue {
                value: current,
                ty: vec_ty,
            }
        }
        "_as_u32x4" | "_as_i32x4" | "_bitcast_f32x4" | "_bitcast_i32x4" | "_bitcast_u32x4" => {
            let (source_ty, target_ty) = match op {
                "_as_u32x4" => ("<4 x i32>", "<4 x i32>"),
                "_as_i32x4" => ("<4 x i32>", "<4 x i32>"),
                "_bitcast_f32x4" => ("<4 x i32>", "<4 x float>"),
                "_bitcast_i32x4" => ("<4 x float>", "<4 x i32>"),
                "_bitcast_u32x4" => ("<4 x float>", "<4 x i32>"),
                _ => unreachable!(),
            };
            let input =
                llvm_emit_expr_as(&args[0], ctx, string_literal_ids, task_ref_ids, source_ty)?;
            let out = ctx.value();
            ctx.code.push_str(&format!(
                "  {out} = bitcast {source_ty} {} to {target_ty}\n",
                input.value
            ));
            LlvmValue {
                value: out,
                ty: target_ty.to_string(),
            }
        }
        "_reduce_add" | "_reduce_min" | "_reduce_max" => llvm_emit_simd_reduce_scalar(
            kind,
            op,
            &vec_ty,
            scalar_ty,
            &args[0],
            ctx,
            string_literal_ids,
            task_ref_ids,
        )?,
        "_any" | "_all" | "_none" => {
            let input =
                llvm_emit_expr_as(&args[0], ctx, string_literal_ids, task_ref_ids, &mask_ty)?;
            let mut lanes = Vec::with_capacity(4);
            for index in 0..4 {
                let lane = ctx.value();
                ctx.code.push_str(&format!(
                    "  {lane} = extractelement {mask_ty} {}, i32 {index}\n",
                    input.value
                ));
                lanes.push(lane);
            }
            let fold0 = ctx.value();
            let fold1 = ctx.value();
            let fold2 = ctx.value();
            let bit_op = if op == "_all" { "and" } else { "or" };
            ctx.code.push_str(&format!(
                "  {fold0} = {bit_op} i1 {}, {}\n",
                lanes[0], lanes[1]
            ));
            ctx.code
                .push_str(&format!("  {fold1} = {bit_op} i1 {fold0}, {}\n", lanes[2]));
            ctx.code
                .push_str(&format!("  {fold2} = {bit_op} i1 {fold1}, {}\n", lanes[3]));
            let pred = if op == "_none" {
                let inverted = ctx.value();
                ctx.code
                    .push_str(&format!("  {inverted} = xor i1 {fold2}, true\n"));
                inverted
            } else {
                fold2
            };
            llvm_bool_from_pred(ctx, &pred)
        }
        "_bitmask" => {
            let input =
                llvm_emit_expr_as(&args[0], ctx, string_literal_ids, task_ref_ids, &mask_ty)?;
            let mut acc = "0".to_string();
            for index in 0..4 {
                let lane = ctx.value();
                ctx.code.push_str(&format!(
                    "  {lane} = extractelement {mask_ty} {}, i32 {index}\n",
                    input.value
                ));
                let lane_i32 = ctx.value();
                ctx.code
                    .push_str(&format!("  {lane_i32} = zext i1 {lane} to i32\n"));
                let shifted = ctx.value();
                ctx.code
                    .push_str(&format!("  {shifted} = shl i32 {lane_i32}, {index}\n"));
                let next = ctx.value();
                ctx.code
                    .push_str(&format!("  {next} = or i32 {acc}, {shifted}\n"));
                acc = next;
            }
            LlvmValue {
                value: acc,
                ty: "i32".to_string(),
            }
        }
        "_lane0" | "_lane1" | "_lane2" | "_lane3" => {
            let index = match op {
                "_lane0" => 0,
                "_lane1" => 1,
                "_lane2" => 2,
                "_lane3" => 3,
                _ => unreachable!(),
            };
            let input =
                llvm_emit_expr_as(&args[0], ctx, string_literal_ids, task_ref_ids, &vec_ty)?;
            let lane = ctx.value();
            ctx.code.push_str(&format!(
                "  {lane} = extractelement {vec_ty} {}, i32 {index}\n",
                input.value
            ));
            if kind == "mask32x4" {
                llvm_bool_from_pred(ctx, &lane)
            } else {
                LlvmValue {
                    value: lane,
                    ty: scalar_ty.to_string(),
                }
            }
        }
        _ => {
            return Err(anyhow!(
                "unsupported llvm SIMD intrinsic lowering for `{callee}`"
            ))
        }
    };
    Ok(Some(value))
}

fn llvm_cast_i64_to_ty(ctx: &mut LlvmFuncCtx, raw_value: String, target_ty: &str) -> LlvmValue {
    match target_ty {
        "i64" => LlvmValue {
            value: raw_value,
            ty: "i64".to_string(),
        },
        "i32" | "i8" | "i1" => {
            let out = ctx.value();
            ctx.code
                .push_str(&format!("  {out} = trunc i64 {raw_value} to {target_ty}\n"));
            LlvmValue {
                value: out,
                ty: target_ty.to_string(),
            }
        }
        _ => LlvmValue {
            value: raw_value,
            ty: "i64".to_string(),
        },
    }
}

fn llvm_emit_aggregate_get(
    ctx: &mut LlvmFuncCtx,
    handle: &LlvmValue,
    index: usize,
    target_ty: &str,
) -> LlvmValue {
    let raw = ctx.value();
    ctx.code.push_str(&format!(
        "  {raw} = call i64 @{}(i64 {}, i32 {index})\n",
        NATIVE_AGG_GET_I64_SYMBOL, handle.value
    ));
    llvm_cast_i64_to_ty(ctx, raw, target_ty)
}

fn llvm_record_aggregate_binding(
    name: &str,
    value: &ast::Expr,
    ctx: &mut LlvmFuncCtx,
    string_literal_ids: &HashMap<String, i32>,
    task_ref_ids: &HashMap<String, i32>,
) -> Result<()> {
    let mut binding = LlvmAggregateBinding::default();
    match value {
        ast::Expr::StructInit { fields, .. } => {
            for (index, (field, field_expr)) in fields.iter().enumerate() {
                let field_value =
                    llvm_emit_expr(field_expr, ctx, string_literal_ids, task_ref_ids)?;
                binding.items.insert(
                    field.clone(),
                    LlvmAggregateItemBinding {
                        index,
                        ty: field_value.ty,
                    },
                );
            }
        }
        ast::Expr::Tuple(items) => {
            for (index, item_expr) in items.iter().enumerate() {
                let item_value = llvm_emit_expr(item_expr, ctx, string_literal_ids, task_ref_ids)?;
                binding.items.insert(
                    format!("__tuple{index}"),
                    LlvmAggregateItemBinding {
                        index,
                        ty: item_value.ty,
                    },
                );
            }
        }
        ast::Expr::EnumInit {
            payload,
            named_payload,
            ..
        } => {
            for (index, payload_expr) in payload.iter().enumerate() {
                let payload_value =
                    llvm_emit_expr(payload_expr, ctx, string_literal_ids, task_ref_ids)?;
                binding.items.insert(
                    format!("__payload{index}"),
                    LlvmAggregateItemBinding {
                        index,
                        ty: payload_value.ty,
                    },
                );
            }
            for (offset, (field, field_expr)) in named_payload.iter().enumerate() {
                let field_value =
                    llvm_emit_expr(field_expr, ctx, string_literal_ids, task_ref_ids)?;
                binding.items.insert(
                    field.clone(),
                    LlvmAggregateItemBinding {
                        index: payload.len() + offset,
                        ty: field_value.ty,
                    },
                );
            }
        }
        _ => return Ok(()),
    }
    ctx.aggregate_bindings.insert(name.to_string(), binding);
    Ok(())
}

fn llvm_tuple_item_binding_for_local(
    name: &str,
    index: usize,
    ctx: &LlvmFuncCtx,
) -> Option<LlvmAggregateItemBinding> {
    let ast::Type::Tuple(items) = ctx.local_types.get(name)? else {
        return None;
    };
    let item_ty = items.get(index)?;
    Some(LlvmAggregateItemBinding {
        index,
        ty: llvm_ir_type_for_ast_type(item_ty),
    })
}

fn llvm_struct_field_binding_for_local(
    name: &str,
    field: &str,
    ctx: &LlvmFuncCtx,
) -> Option<LlvmAggregateItemBinding> {
    let ast::Type::Named { name: ty_name, .. } = ctx.local_types.get(name)? else {
        return None;
    };
    let struct_def = ctx.struct_defs.get(ty_name.as_str())?;
    let (index, struct_field) = struct_def
        .fields
        .iter()
        .enumerate()
        .find(|(_, item)| item.name == field)?;
    Some(LlvmAggregateItemBinding {
        index,
        ty: llvm_ir_type_for_ast_type(&struct_field.ty),
    })
}

fn llvm_enum_payload_binding_for_local(
    name: &str,
    enum_name: &str,
    variant: &str,
    index: usize,
    ctx: &LlvmFuncCtx,
) -> Option<LlvmAggregateItemBinding> {
    let ast::Type::Named { name: ty_name, .. } = ctx.local_types.get(name)? else {
        return None;
    };
    if ty_name != enum_name {
        return None;
    }
    let enum_def = ctx.enum_defs.get(enum_name)?;
    let variant_def = enum_def.variants.iter().find(|item| item.name == variant)?;
    let payload_ty = variant_def.payload.get(index)?;
    Some(LlvmAggregateItemBinding {
        index,
        ty: llvm_ir_type_for_ast_type(payload_ty),
    })
}

fn llvm_enum_named_binding_for_local(
    name: &str,
    enum_name: &str,
    variant: &str,
    field: &str,
    ctx: &LlvmFuncCtx,
) -> Option<LlvmAggregateItemBinding> {
    let ast::Type::Named { name: ty_name, .. } = ctx.local_types.get(name)? else {
        return None;
    };
    if ty_name != enum_name {
        return None;
    }
    let enum_def = ctx.enum_defs.get(enum_name)?;
    let variant_def = enum_def.variants.iter().find(|item| item.name == variant)?;
    let (offset, named_field) = variant_def
        .named_payload
        .iter()
        .enumerate()
        .find(|(_, item)| item.name == field)?;
    Some(LlvmAggregateItemBinding {
        index: variant_def.payload.len() + offset,
        ty: llvm_ir_type_for_ast_type(&named_field.ty),
    })
}

fn llvm_local_is_aggregate(name: &str, ctx: &LlvmFuncCtx) -> bool {
    matches!(
        ctx.local_types.get(name),
        Some(ast::Type::Tuple(_)) | Some(ast::Type::Named { .. })
    )
}

fn llvm_emit_aggregate_handle(tag: i32, items: &[LlvmValue], ctx: &mut LlvmFuncCtx) -> LlvmValue {
    let handle = ctx.value();
    ctx.code.push_str(&format!(
        "  {handle} = call i64 @{}(i32 {tag}, i32 {})\n",
        NATIVE_AGG_NEW_SYMBOL,
        items.len()
    ));
    for (index, item) in items.iter().cloned().enumerate() {
        let raw = llvm_cast_scalar_to_i64(ctx, item);
        let status = ctx.value();
        ctx.code.push_str(&format!(
            "  {status} = call i32 @{}(i64 {handle}, i32 {index}, i64 {})\n",
            NATIVE_AGG_SET_I64_SYMBOL, raw.value
        ));
    }
    LlvmValue {
        value: handle,
        ty: "i64".to_string(),
    }
}

pub(super) fn collect_wrapped_index_candidates(
    body: &[ast::Stmt],
) -> HashMap<String, HashSet<usize>> {
    let mut out = HashMap::new();
    collect_wrapped_index_candidates_stmt(body, &mut out);
    out
}

fn collect_wrapped_index_candidates_stmt(
    stmts: &[ast::Stmt],
    out: &mut HashMap<String, HashSet<usize>>,
) {
    for stmt in stmts {
        match stmt {
            ast::Stmt::While { body, .. }
            | ast::Stmt::Loop { body }
            | ast::Stmt::ForIn { body, .. } => {
                collect_wrapped_index_candidates_stmt(body, out);
            }
            ast::Stmt::For {
                init,
                condition: _,
                step,
                body,
            } => {
                if let Some(init) = init {
                    collect_wrapped_index_candidates_stmt(std::slice::from_ref(init.as_ref()), out);
                }
                if let Some(step) = step {
                    collect_wrapped_index_candidates_stmt(std::slice::from_ref(step.as_ref()), out);
                }
                collect_wrapped_index_candidates_stmt(body, out);
            }
            ast::Stmt::If {
                then_body,
                else_body,
                ..
            } => {
                collect_wrapped_index_candidates_stmt(then_body, out);
                collect_wrapped_index_candidates_stmt(else_body, out);
            }
            _ => {}
        }
    }

    for pair in stmts.windows(2) {
        let first = &pair[0];
        let second = &pair[1];
        let (target, limit) = match first {
            ast::Stmt::CompoundAssign {
                target,
                op: ast::BinaryOp::Add,
                value: ast::Expr::Int(1),
            } => match second {
                ast::Stmt::If {
                    condition:
                        ast::Expr::Binary {
                            op: ast::BinaryOp::Eq,
                            left,
                            right,
                        },
                    then_body,
                    else_body,
                } if else_body.is_empty()
                    && then_body.len() == 1
                    && matches!(
                        then_body.first(),
                        Some(ast::Stmt::Assign {
                            target: assign_target,
                            value: ast::Expr::Int(0),
                        }) if assign_target == target
                    ) =>
                {
                    let cond_target = match left.as_ref() {
                        ast::Expr::Ident(name) => Some(name),
                        _ => None,
                    };
                    let cond_limit = match right.as_ref() {
                        ast::Expr::Int(v) if *v > 0 => Some(*v as usize),
                        _ => None,
                    };
                    if cond_target == Some(target) {
                        if let Some(limit) = cond_limit {
                            (target.clone(), limit)
                        } else {
                            continue;
                        }
                    } else {
                        continue;
                    }
                }
                _ => continue,
            },
            _ => continue,
        };
        out.entry(target).or_default().insert(limit);
    }
}

pub(super) fn llvm_snapshot_closure_captures(
    ctx: &mut LlvmFuncCtx,
) -> HashMap<String, LlvmCaptureBinding> {
    let visible = ctx.slots.clone();
    let mut captures = HashMap::new();
    for (name, slot) in visible {
        let ty = ctx
            .slot_tys
            .get(&name)
            .cloned()
            .unwrap_or_else(|| "i32".to_string());
        let loaded = ctx.value();
        ctx.code
            .push_str(&format!("  {loaded} = load {ty}, ptr {slot}\n"));
        let capture_slot = format!(
            "%slot_cap_{}_{}",
            native_mangle_symbol(&name),
            ctx.next_value
        );
        ctx.code.push_str(&format!(
            "  {capture_slot} = alloca {ty}\n  store {ty} {loaded}, ptr {capture_slot}\n"
        ));
        captures.insert(
            name,
            LlvmCaptureBinding {
                slot: capture_slot,
                ty,
            },
        );
    }
    captures
}

pub(super) fn llvm_restore_shadowed_slots(
    ctx: &mut LlvmFuncCtx,
    saved: HashMap<String, Option<String>>,
    inserted_names: HashSet<String>,
) {
    for (name, prior) in saved {
        if let Some(slot) = prior {
            ctx.slots.insert(name, slot);
        } else if inserted_names.contains(&name) {
            ctx.slots.remove(&name);
        }
    }
}

pub(super) fn llvm_emit_inlined_closure_call(
    binding: LlvmClosureBinding,
    args: &[ast::Expr],
    ctx: &mut LlvmFuncCtx,
    string_literal_ids: &HashMap<String, i32>,
    task_ref_ids: &HashMap<String, i32>,
) -> Result<LlvmValue> {
    let mut saved = HashMap::<String, Option<String>>::new();
    let mut inserted = HashSet::<String>::new();
    for (name, capture) in &binding.captures {
        if !saved.contains_key(name) {
            saved.insert(name.clone(), ctx.slots.get(name).cloned());
        }
        ctx.slots.insert(name.clone(), capture.slot.clone());
        ctx.slot_tys.insert(name.clone(), capture.ty.clone());
        inserted.insert(name.clone());
    }
    for (param, arg) in binding.params.iter().zip(args.iter()) {
        let value = llvm_emit_expr(arg, ctx, string_literal_ids, task_ref_ids)?;
        let target_ty = llvm_ir_type_for_ast_type(&param.ty);
        let value = llvm_cast_value(ctx, value, &target_ty)?;
        if !saved.contains_key(&param.name) {
            saved.insert(param.name.clone(), ctx.slots.get(&param.name).cloned());
        }
        let slot = format!("%slot_{}_{}", param.name, ctx.next_value);
        ctx.declare_alloca(&slot, &target_ty);
        ctx.code.push_str(&format!(
            "  store {} {}, ptr {slot}\n",
            value.ty, value.value
        ));
        ctx.slots.insert(param.name.clone(), slot);
        ctx.slot_tys.insert(param.name.clone(), target_ty);
        inserted.insert(param.name.clone());
    }
    let result = llvm_emit_expr(&binding.body, ctx, string_literal_ids, task_ref_ids)?;
    if let Some(return_type) = &binding.return_type {
        let target_ty = llvm_ir_type_for_ast_type(return_type);
        let result = llvm_cast_value(ctx, result, &target_ty)?;
        llvm_restore_shadowed_slots(ctx, saved, inserted);
        Ok(result)
    } else {
        llvm_restore_shadowed_slots(ctx, saved, inserted);
        Ok(result)
    }
}

pub(super) fn llvm_emit_let_pattern(
    pattern: &ast::Pattern,
    value: &ast::Expr,
    ctx: &mut LlvmFuncCtx,
    string_literal_ids: &HashMap<String, i32>,
    task_ref_ids: &HashMap<String, i32>,
) -> Result<()> {
    let rendered = llvm_emit_expr(value, ctx, string_literal_ids, task_ref_ids)?;
    match pattern {
        ast::Pattern::Wildcard => {}
        ast::Pattern::Ident(name) => {
            let slot = format!("%slot_{}_{}", native_mangle_symbol(name), ctx.next_value);
            ctx.declare_alloca(&slot, &rendered.ty);
            ctx.code.push_str(&format!(
                "  store {} {}, ptr {slot}\n",
                rendered.ty, rendered.value
            ));
            ctx.slots.insert(name.clone(), slot);
            ctx.slot_tys.insert(name.clone(), rendered.ty.clone());
        }
        ast::Pattern::Tuple(items) => {
            if let ast::Expr::Tuple(values) = value {
                if items.len() != values.len() {
                    bail!("native backend requires tuple pattern arity to match tuple initializer arity");
                }
                for (item, value) in items.iter().zip(values.iter()) {
                    llvm_emit_let_pattern(item, value, ctx, string_literal_ids, task_ref_ids)?;
                }
            } else if let ast::Expr::Ident(name) = value {
                for (index, item) in items.iter().enumerate() {
                    let synthetic = format!("{name}.__tuple{index}");
                    if ctx.slots.contains_key(&synthetic) {
                        llvm_emit_let_pattern(
                            item,
                            &ast::Expr::Ident(synthetic),
                            ctx,
                            string_literal_ids,
                            task_ref_ids,
                        )?;
                    } else {
                        let item_binding = ctx
                            .aggregate_bindings
                            .get(name)
                            .and_then(|binding| binding.items.get(&format!("__tuple{index}")).cloned())
                            .or_else(|| llvm_tuple_item_binding_for_local(name, index, ctx))
                            .ok_or_else(|| anyhow!("native backend requires tuple-bound aggregate metadata for `let` tuple destructuring"))?;
                        let handle = llvm_emit_expr(value, ctx, string_literal_ids, task_ref_ids)?;
                        let extracted = llvm_emit_aggregate_get(
                            ctx,
                            &handle,
                            item_binding.index,
                            &item_binding.ty,
                        );
                        let temp_name = format!("__agg_tuple_extract_{}_{}", name, index);
                        let slot = format!(
                            "%slot_{}_{}",
                            native_mangle_symbol(&temp_name),
                            ctx.next_value
                        );
                        ctx.declare_alloca(&slot, &extracted.ty);
                        ctx.code.push_str(&format!(
                            "  store {} {}, ptr {slot}\n",
                            extracted.ty, extracted.value
                        ));
                        ctx.slots.insert(temp_name.clone(), slot);
                        ctx.slot_tys.insert(temp_name.clone(), extracted.ty.clone());
                        llvm_emit_let_pattern(
                            item,
                            &ast::Expr::Ident(temp_name),
                            ctx,
                            string_literal_ids,
                            task_ref_ids,
                        )?;
                    }
                }
            } else {
                bail!("native backend requires tuple initializer or tuple-bound local for `let` tuple destructuring");
            }
        }
        ast::Pattern::Int(expected) => {
            let cmp = ctx.value();
            ctx.code.push_str(&format!(
                "  {cmp} = icmp eq {} {}, {expected}\n",
                rendered.ty, rendered.value
            ));
        }
        ast::Pattern::Bool(expected) => {
            let cmp = ctx.value();
            let expected_i32 = if *expected { 1 } else { 0 };
            ctx.code.push_str(&format!(
                "  {cmp} = icmp eq {} {}, {expected_i32}\n",
                rendered.ty, rendered.value
            ));
        }
        ast::Pattern::Struct { name, fields } => {
            if let ast::Expr::StructInit {
                name: value_name,
                fields: value_fields,
            } = value
            {
                if value_name != name {
                    bail!(
                        "native backend requires exact literal struct type match for `let` struct destructuring"
                    );
                }
                for (field_name, binding_name) in fields {
                    if binding_name == "_" {
                        continue;
                    }
                    let Some((_, field_expr)) =
                        value_fields.iter().find(|(field, _)| field == field_name)
                    else {
                        bail!("native backend requires struct literal fields to cover every bound pattern field");
                    };
                    let field_value =
                        llvm_emit_expr(field_expr, ctx, string_literal_ids, task_ref_ids)?;
                    let slot = format!(
                        "%slot_{}_{}",
                        native_mangle_symbol(binding_name),
                        ctx.next_value
                    );
                    ctx.declare_alloca(&slot, &field_value.ty);
                    ctx.code.push_str(&format!(
                        "  store {} {}, ptr {slot}\n",
                        field_value.ty, field_value.value
                    ));
                    ctx.slots.insert(binding_name.clone(), slot);
                    ctx.slot_tys
                        .insert(binding_name.clone(), field_value.ty.clone());
                }
            } else if let ast::Expr::Ident(name) = value {
                for (field_name, binding_name) in fields {
                    if binding_name == "_" {
                        continue;
                    }
                    if let Some(slot) = ctx.slots.get(&format!("{name}.{field_name}")).cloned() {
                        let ty = ctx
                            .slot_tys
                            .get(&format!("{name}.{field_name}"))
                            .cloned()
                            .unwrap_or_else(|| "i32".to_string());
                        ctx.slots.insert(binding_name.clone(), slot);
                        ctx.slot_tys.insert(binding_name.clone(), ty);
                    } else {
                        let item_binding = ctx
                            .aggregate_bindings
                            .get(name)
                            .and_then(|binding| binding.items.get(field_name).cloned())
                            .or_else(|| llvm_struct_field_binding_for_local(name, field_name, ctx))
                            .ok_or_else(|| anyhow!("native backend requires struct-bound aggregate metadata for `let` struct destructuring"))?;
                        let handle = llvm_emit_expr(value, ctx, string_literal_ids, task_ref_ids)?;
                        let extracted = llvm_emit_aggregate_get(
                            ctx,
                            &handle,
                            item_binding.index,
                            &item_binding.ty,
                        );
                        let slot = format!(
                            "%slot_{}_{}",
                            native_mangle_symbol(binding_name),
                            ctx.next_value
                        );
                        ctx.declare_alloca(&slot, &extracted.ty);
                        ctx.code.push_str(&format!(
                            "  store {} {}, ptr {slot}\n",
                            extracted.ty, extracted.value
                        ));
                        ctx.slots.insert(binding_name.clone(), slot);
                        ctx.slot_tys.insert(binding_name.clone(), extracted.ty);
                    }
                }
            } else {
                bail!("native backend requires struct initializer or struct-bound local for `let` struct destructuring");
            }
        }
        ast::Pattern::Variant {
            enum_name,
            variant,
            bindings,
            named_bindings,
        } => {
            let key = format!("{enum_name}::{variant}");
            let tag = variant_tag_for_key(&key, &ctx.variant_tags);
            let (cmp_ty, cmp_value) = if rendered.ty == "i64" {
                let tag_value = ctx.value();
                ctx.code.push_str(&format!(
                    "  {tag_value} = call i32 @{}(i64 {})\n",
                    NATIVE_AGG_TAG_SYMBOL, rendered.value
                ));
                ("i32".to_string(), tag_value)
            } else {
                (rendered.ty.clone(), rendered.value.clone())
            };
            let cmp = ctx.value();
            ctx.code
                .push_str(&format!("  {cmp} = icmp eq {cmp_ty} {cmp_value}, {tag}\n"));
            if let ast::Expr::EnumInit {
                enum_name: value_enum,
                variant: value_variant,
                payload,
                named_payload,
                ..
            } = value
            {
                if value_enum == enum_name
                    && value_variant == variant
                    && payload.len() == bindings.len()
                {
                    for (binding_name, payload_expr) in bindings.iter().zip(payload.iter()) {
                        let payload_value =
                            llvm_emit_expr(payload_expr, ctx, string_literal_ids, task_ref_ids)?;
                        let slot = format!(
                            "%slot_{}_{}",
                            native_mangle_symbol(binding_name),
                            ctx.next_value
                        );
                        ctx.declare_alloca(&slot, &payload_value.ty);
                        ctx.code.push_str(&format!(
                            "  store {} {}, ptr {slot}\n",
                            payload_value.ty, payload_value.value
                        ));
                        ctx.slots.insert(binding_name.clone(), slot);
                        ctx.slot_tys
                            .insert(binding_name.clone(), payload_value.ty.clone());
                    }
                    for (field_name, binding_name) in named_bindings {
                        if binding_name == "_" {
                            continue;
                        }
                        let Some((_, field_expr)) =
                            named_payload.iter().find(|(field, _)| field == field_name)
                        else {
                            bail!("native backend requires enum literal named payload fields to cover every bound pattern field");
                        };
                        let field_value =
                            llvm_emit_expr(field_expr, ctx, string_literal_ids, task_ref_ids)?;
                        let slot = format!(
                            "%slot_{}_{}",
                            native_mangle_symbol(binding_name),
                            ctx.next_value
                        );
                        ctx.declare_alloca(&slot, &field_value.ty);
                        ctx.code.push_str(&format!(
                            "  store {} {}, ptr {slot}\n",
                            field_value.ty, field_value.value
                        ));
                        ctx.slots.insert(binding_name.clone(), slot);
                        ctx.slot_tys
                            .insert(binding_name.clone(), field_value.ty.clone());
                    }
                }
            } else if let ast::Expr::Ident(name) = value {
                for (index, binding_name) in bindings.iter().enumerate() {
                    let key = format!("{name}.__payload{index}");
                    if let Some(slot) = ctx.slots.get(&key).cloned() {
                        let ty = ctx
                            .slot_tys
                            .get(&key)
                            .cloned()
                            .unwrap_or_else(|| "i32".to_string());
                        ctx.slots.insert(binding_name.clone(), slot);
                        ctx.slot_tys.insert(binding_name.clone(), ty);
                    } else {
                        let payload_key = format!("__payload{index}");
                        let item_binding = ctx
                            .aggregate_bindings
                            .get(name)
                            .and_then(|binding| binding.items.get(&payload_key).cloned())
                            .or_else(|| {
                                llvm_enum_payload_binding_for_local(
                                    name,
                                    enum_name,
                                    variant,
                                    index,
                                    ctx,
                                )
                            })
                            .ok_or_else(|| anyhow!("native backend requires enum-bound local payloads for `let` variant destructuring"))?;
                        let handle = llvm_emit_expr(value, ctx, string_literal_ids, task_ref_ids)?;
                        let extracted = llvm_emit_aggregate_get(
                            ctx,
                            &handle,
                            item_binding.index,
                            &item_binding.ty,
                        );
                        let slot = format!(
                            "%slot_{}_{}",
                            native_mangle_symbol(binding_name),
                            ctx.next_value
                        );
                        ctx.declare_alloca(&slot, &extracted.ty);
                        ctx.code.push_str(&format!(
                            "  store {} {}, ptr {slot}\n",
                            extracted.ty, extracted.value
                        ));
                        ctx.slots.insert(binding_name.clone(), slot);
                        ctx.slot_tys.insert(binding_name.clone(), extracted.ty);
                    }
                }
                for (field_name, binding_name) in named_bindings {
                    if binding_name == "_" {
                        continue;
                    }
                    let key = format!("{name}.{field_name}");
                    if let Some(slot) = ctx.slots.get(&key).cloned() {
                        let ty = ctx
                            .slot_tys
                            .get(&key)
                            .cloned()
                            .unwrap_or_else(|| "i32".to_string());
                        ctx.slots.insert(binding_name.clone(), slot);
                        ctx.slot_tys.insert(binding_name.clone(), ty);
                    } else {
                        let item_binding = ctx
                            .aggregate_bindings
                            .get(name)
                            .and_then(|binding| binding.items.get(field_name).cloned())
                            .or_else(|| {
                                llvm_enum_named_binding_for_local(
                                    name,
                                    enum_name,
                                    variant,
                                    field_name,
                                    ctx,
                                )
                            })
                            .ok_or_else(|| anyhow!("native backend requires enum-bound local named payloads for `let` variant destructuring"))?;
                        let handle = llvm_emit_expr(value, ctx, string_literal_ids, task_ref_ids)?;
                        let extracted = llvm_emit_aggregate_get(
                            ctx,
                            &handle,
                            item_binding.index,
                            &item_binding.ty,
                        );
                        let slot = format!(
                            "%slot_{}_{}",
                            native_mangle_symbol(binding_name),
                            ctx.next_value
                        );
                        ctx.declare_alloca(&slot, &extracted.ty);
                        ctx.code.push_str(&format!(
                            "  store {} {}, ptr {slot}\n",
                            extracted.ty, extracted.value
                        ));
                        ctx.slots.insert(binding_name.clone(), slot);
                        ctx.slot_tys.insert(binding_name.clone(), extracted.ty);
                    }
                }
            }
        }
        ast::Pattern::Or(patterns) => {
            if let Some(matched) = patterns.iter().find(|pattern| {
                pattern_matches_resolved_scrutinee(pattern, value, &ctx.variant_tags)
            }) {
                return llvm_emit_let_pattern(
                    matched,
                    value,
                    ctx,
                    string_literal_ids,
                    task_ref_ids,
                );
            }
            if patterns.iter().any(pattern_has_variant_payload_bindings)
                || patterns.iter().any(pattern_has_struct_field_bindings)
            {
                bail!(
                    "native backend requires resolvable initializer for payload or struct-field bindings in `let` or-patterns"
                );
            }
        }
    }
    Ok(())
}

pub(super) fn llvm_emit_linear_stmts(
    body: &[ast::Stmt],
    ctx: &mut LlvmFuncCtx,
    string_literal_ids: &HashMap<String, i32>,
    task_ref_ids: &HashMap<String, i32>,
) -> Result<bool> {
    let mut deferred = Vec::<ast::Expr>::new();
    for stmt in body {
        match stmt {
            ast::Stmt::Let {
                name,
                value,
                mutable,
                ..
            } => {
                if let Some(const_value) = eval_const_string_expr(value, &ctx.const_strings) {
                    ctx.const_strings.insert(name.clone(), const_value);
                    ctx.array_slots.remove(name);
                    ctx.direct_values.remove(name);
                    continue;
                }
                if let ast::Expr::ArrayLiteral(items) = value {
                    let storage = format!("%slot_{}_arr_{}", name, ctx.next_value);
                    let len = items.len();
                    let lowered_items = items
                        .iter()
                        .map(|item| llvm_emit_expr(item, ctx, string_literal_ids, task_ref_ids))
                        .collect::<Result<Vec<_>>>()?;
                    let element_ty = lowered_items
                        .first()
                        .map(|value| value.ty.clone())
                        .unwrap_or_else(|| "i32".to_string());
                    ctx.declare_alloca(&storage, &format!("[{len} x {element_ty}]"));
                    for (idx, item) in items.iter().enumerate() {
                        let item_value = llvm_emit_expr_as(
                            item,
                            ctx,
                            string_literal_ids,
                            task_ref_ids,
                            &element_ty,
                        )?;
                        let element_ptr = ctx.value();
                        ctx.code.push_str(&format!(
                            "  {element_ptr} = getelementptr inbounds [{len} x {element_ty}], ptr {storage}, i32 0, i64 {idx}\n  store {element_ty} {}, ptr {element_ptr}\n",
                            item_value.value
                        ));
                    }
                    ctx.array_slots.insert(
                        name.clone(),
                        LlvmArrayBinding {
                            storage: storage.clone(),
                            len,
                            element_ty: element_ty.clone(),
                            element_bits: 32,
                            element_align: 4,
                            element_stride: 4,
                        },
                    );
                    ctx.slots.insert(name.clone(), storage);
                    ctx.slot_tys
                        .insert(name.clone(), format!("[{len} x {element_ty}]"));
                    ctx.direct_values.remove(name);
                    continue;
                }
                if let ast::Expr::Ident(source) = value {
                    if let Some(source_ty) = ctx.local_types.get(source).cloned() {
                        ctx.local_types.insert(name.clone(), source_ty);
                    }
                    if let Some(binding) = ctx.aggregate_bindings.get(source).cloned() {
                        ctx.aggregate_bindings.insert(name.clone(), binding);
                    }
                    if let Some(source_binding) = ctx.array_slots.get(source).cloned() {
                        ctx.array_slots.insert(name.clone(), source_binding);
                        ctx.direct_values.remove(name);
                        continue;
                    }
                }
                if let ast::Expr::Closure {
                    params,
                    return_type,
                    body,
                } = value
                {
                    let captures = llvm_snapshot_closure_captures(ctx);
                    ctx.closures.insert(
                        name.clone(),
                        LlvmClosureBinding {
                            params: params.clone(),
                            return_type: return_type.clone(),
                            body: (**body).clone(),
                            captures,
                        },
                    );
                    ctx.direct_values.remove(name);
                    continue;
                }
                let rendered = llvm_emit_expr(value, ctx, string_literal_ids, task_ref_ids)?;
                let slot = format!("%slot_{}_{}", name, ctx.next_value);
                ctx.declare_alloca(&slot, &rendered.ty);
                ctx.code.push_str(&format!(
                    "  store {} {}, ptr {slot}\n",
                    rendered.ty, rendered.value
                ));
                ctx.slots.insert(name.clone(), slot.clone());
                ctx.slot_tys.insert(name.clone(), rendered.ty.clone());
                if !*mutable {
                    ctx.direct_values.insert(name.clone(), rendered.clone());
                } else {
                    ctx.direct_values.remove(name);
                }
                if let Some(local_ty) = ctx.local_types.get(name) {
                    if let Some(binding) = llvm_array_binding_from_type(&slot, local_ty) {
                        ctx.array_slots.insert(name.clone(), binding);
                    }
                }
                let _ = llvm_record_aggregate_binding(
                    name,
                    value,
                    ctx,
                    string_literal_ids,
                    task_ref_ids,
                );
                if let ast::Expr::StructInit { fields, .. } = value {
                    for (field, field_expr) in fields {
                        let field_value =
                            llvm_emit_expr(field_expr, ctx, string_literal_ids, task_ref_ids)?;
                        let field_slot = format!("%slot_{}_{}_{}", name, field, ctx.next_value);
                        ctx.declare_alloca(&field_slot, &field_value.ty);
                        ctx.code.push_str(&format!(
                            "  store {} {}, ptr {field_slot}\n",
                            field_value.ty, field_value.value
                        ));
                        ctx.slots.insert(format!("{name}.{field}"), field_slot);
                        ctx.slot_tys
                            .insert(format!("{name}.{field}"), field_value.ty.clone());
                    }
                }
                if let ast::Expr::Tuple(items) = value {
                    for (index, item_expr) in items.iter().enumerate() {
                        let item_value =
                            llvm_emit_expr(item_expr, ctx, string_literal_ids, task_ref_ids)?;
                        let item_slot =
                            format!("%slot_{}_tuple_{}_{}", name, index, ctx.next_value);
                        ctx.declare_alloca(&item_slot, &item_value.ty);
                        ctx.code.push_str(&format!(
                            "  store {} {}, ptr {item_slot}\n",
                            item_value.ty, item_value.value
                        ));
                        ctx.slots
                            .insert(format!("{name}.__tuple{index}"), item_slot);
                        ctx.slot_tys
                            .insert(format!("{name}.__tuple{index}"), item_value.ty.clone());
                    }
                }
                if let ast::Expr::EnumInit {
                    enum_name: _,
                    variant: _,
                    payload,
                    named_payload,
                } = value
                {
                    for (index, payload_expr) in payload.iter().enumerate() {
                        let payload_value =
                            llvm_emit_expr(payload_expr, ctx, string_literal_ids, task_ref_ids)?;
                        let payload_slot =
                            format!("%slot_{}_payload_{}_{}", name, index, ctx.next_value);
                        ctx.declare_alloca(&payload_slot, &payload_value.ty);
                        ctx.code.push_str(&format!(
                            "  store {} {}, ptr {payload_slot}\n",
                            payload_value.ty, payload_value.value
                        ));
                        ctx.slots
                            .insert(format!("{name}.__payload{index}"), payload_slot);
                        ctx.slot_tys
                            .insert(format!("{name}.__payload{index}"), payload_value.ty.clone());
                    }
                    for (field, field_expr) in named_payload {
                        let field_value =
                            llvm_emit_expr(field_expr, ctx, string_literal_ids, task_ref_ids)?;
                        let field_slot = format!("%slot_{}_{}_{}", name, field, ctx.next_value);
                        ctx.declare_alloca(&field_slot, &field_value.ty);
                        ctx.code.push_str(&format!(
                            "  store {} {}, ptr {field_slot}\n",
                            field_value.ty, field_value.value
                        ));
                        ctx.slots.insert(format!("{name}.{field}"), field_slot);
                        ctx.slot_tys
                            .insert(format!("{name}.{field}"), field_value.ty.clone());
                    }
                }
                if let ast::Expr::Range {
                    start,
                    end,
                    inclusive,
                } = value
                {
                    let start_value = llvm_emit_expr(start, ctx, string_literal_ids, task_ref_ids)?;
                    let end_value = llvm_emit_expr(end, ctx, string_literal_ids, task_ref_ids)?;
                    let inclusive_value = LlvmValue {
                        value: if *inclusive {
                            "1".to_string()
                        } else {
                            "0".to_string()
                        },
                        ty: "i8".to_string(),
                    };
                    for (field, rendered) in [
                        ("start", start_value),
                        ("end", end_value),
                        ("inclusive", inclusive_value),
                    ] {
                        let field_slot = format!("%slot_{}_{}_{}", name, field, ctx.next_value);
                        ctx.declare_alloca(&field_slot, &rendered.ty);
                        ctx.code.push_str(&format!(
                            "  store {} {}, ptr {field_slot}\n",
                            rendered.ty, rendered.value
                        ));
                        ctx.slots.insert(format!("{name}.{field}"), field_slot);
                        ctx.slot_tys
                            .insert(format!("{name}.{field}"), rendered.ty.clone());
                    }
                }
                if !matches!(ctx.local_types.get(name), Some(ast::Type::Array { .. })) {
                    ctx.array_slots.remove(name);
                }
                ctx.const_strings.remove(name);
            }
            ast::Stmt::LetPattern { pattern, value, .. } => {
                llvm_emit_let_pattern(pattern, value, ctx, string_literal_ids, task_ref_ids)?;
            }
            ast::Stmt::Assign { target, value } => {
                if let Some(const_value) = eval_const_string_expr(value, &ctx.const_strings) {
                    ctx.const_strings.insert(target.clone(), const_value);
                    ctx.array_slots.remove(target);
                    continue;
                }
                if let ast::Expr::ArrayLiteral(items) = value {
                    let storage = format!("%slot_{}_arr_{}", target, ctx.next_value);
                    let len = items.len();
                    let lowered_items = items
                        .iter()
                        .map(|item| llvm_emit_expr(item, ctx, string_literal_ids, task_ref_ids))
                        .collect::<Result<Vec<_>>>()?;
                    let element_ty = lowered_items
                        .first()
                        .map(|value| value.ty.clone())
                        .unwrap_or_else(|| "i32".to_string());
                    ctx.declare_alloca(&storage, &format!("[{len} x {element_ty}]"));
                    for (idx, item) in items.iter().enumerate() {
                        let item_value = llvm_emit_expr_as(
                            item,
                            ctx,
                            string_literal_ids,
                            task_ref_ids,
                            &element_ty,
                        )?;
                        let element_ptr = ctx.value();
                        ctx.code.push_str(&format!(
                            "  {element_ptr} = getelementptr inbounds [{len} x {element_ty}], ptr {storage}, i32 0, i64 {idx}\n  store {element_ty} {}, ptr {element_ptr}\n",
                            item_value.value
                        ));
                    }
                    ctx.array_slots.insert(
                        target.clone(),
                        LlvmArrayBinding {
                            storage: storage.clone(),
                            len,
                            element_ty: element_ty.clone(),
                            element_bits: 32,
                            element_align: 4,
                            element_stride: 4,
                        },
                    );
                    ctx.slots.insert(target.clone(), storage);
                    ctx.slot_tys
                        .insert(target.clone(), format!("[{len} x {element_ty}]"));
                    ctx.direct_values.remove(target);
                    continue;
                }
                if let ast::Expr::Ident(source) = value {
                    if let Some(source_ty) = ctx.local_types.get(source).cloned() {
                        ctx.local_types.insert(target.clone(), source_ty);
                    }
                    if let Some(binding) = ctx.aggregate_bindings.get(source).cloned() {
                        ctx.aggregate_bindings.insert(target.clone(), binding);
                    }
                    if let Some(source_binding) = ctx.array_slots.get(source).cloned() {
                        ctx.array_slots.insert(target.clone(), source_binding);
                        continue;
                    }
                }
                let rendered_value = llvm_emit_expr(value, ctx, string_literal_ids, task_ref_ids)?;
                if let ast::Expr::Closure {
                    params,
                    return_type,
                    body,
                } = value
                {
                    let captures = llvm_snapshot_closure_captures(ctx);
                    ctx.closures.insert(
                        target.clone(),
                        LlvmClosureBinding {
                            params: params.clone(),
                            return_type: return_type.clone(),
                            body: (**body).clone(),
                            captures,
                        },
                    );
                    continue;
                }
                if let Some(symbol) = ctx.mutable_globals.get(target).cloned() {
                    let stored = llvm_cast_value(ctx, rendered_value.clone(), "i32")?;
                    ctx.code
                        .push_str(&format!("  store i32 {}, ptr @{symbol}\n", stored.value));
                    ctx.direct_values.remove(target);
                    continue;
                }
                let slot = ctx
                    .slots
                    .entry(target.clone())
                    .or_insert_with(|| format!("%slot_{}_{}", target, ctx.next_value))
                    .clone();
                ctx.declare_alloca(&slot, &rendered_value.ty);
                ctx.code.push_str(&format!(
                    "  store {} {}, ptr {slot}\n",
                    rendered_value.ty, rendered_value.value
                ));
                ctx.slot_tys
                    .insert(target.clone(), rendered_value.ty.clone());
                if let Some(local_ty) = ctx.local_types.get(target) {
                    if let Some(binding) = llvm_array_binding_from_type(&slot, local_ty) {
                        ctx.array_slots.insert(target.clone(), binding);
                    }
                }
                ctx.direct_values.remove(target);
                let _ = llvm_record_aggregate_binding(
                    target,
                    value,
                    ctx,
                    string_literal_ids,
                    task_ref_ids,
                );
                if let ast::Expr::StructInit { fields, .. } = value {
                    for (field, field_expr) in fields {
                        let field_value =
                            llvm_emit_expr(field_expr, ctx, string_literal_ids, task_ref_ids)?;
                        let field_slot = format!("%slot_{}_{}_{}", target, field, ctx.next_value);
                        ctx.declare_alloca(&field_slot, &field_value.ty);
                        ctx.code.push_str(&format!(
                            "  store {} {}, ptr {field_slot}\n",
                            field_value.ty, field_value.value
                        ));
                        ctx.slots.insert(format!("{target}.{field}"), field_slot);
                        ctx.slot_tys
                            .insert(format!("{target}.{field}"), field_value.ty.clone());
                    }
                }
                if let ast::Expr::Tuple(items) = value {
                    for (index, item_expr) in items.iter().enumerate() {
                        let item_value =
                            llvm_emit_expr(item_expr, ctx, string_literal_ids, task_ref_ids)?;
                        let item_slot =
                            format!("%slot_{}_tuple_{}_{}", target, index, ctx.next_value);
                        ctx.declare_alloca(&item_slot, &item_value.ty);
                        ctx.code.push_str(&format!(
                            "  store {} {}, ptr {item_slot}\n",
                            item_value.ty, item_value.value
                        ));
                        ctx.slots
                            .insert(format!("{target}.__tuple{index}"), item_slot);
                        ctx.slot_tys
                            .insert(format!("{target}.__tuple{index}"), item_value.ty.clone());
                    }
                }
                if let ast::Expr::EnumInit {
                    enum_name: _,
                    variant: _,
                    payload,
                    named_payload,
                } = value
                {
                    for (index, payload_expr) in payload.iter().enumerate() {
                        let payload_value =
                            llvm_emit_expr(payload_expr, ctx, string_literal_ids, task_ref_ids)?;
                        let payload_slot =
                            format!("%slot_{}_payload_{}_{}", target, index, ctx.next_value);
                        ctx.declare_alloca(&payload_slot, &payload_value.ty);
                        ctx.code.push_str(&format!(
                            "  store {} {}, ptr {payload_slot}\n",
                            payload_value.ty, payload_value.value
                        ));
                        ctx.slots
                            .insert(format!("{target}.__payload{index}"), payload_slot);
                        ctx.slot_tys.insert(
                            format!("{target}.__payload{index}"),
                            payload_value.ty.clone(),
                        );
                    }
                    for (field, field_expr) in named_payload {
                        let field_value =
                            llvm_emit_expr(field_expr, ctx, string_literal_ids, task_ref_ids)?;
                        let field_slot = format!("%slot_{}_{}_{}", target, field, ctx.next_value);
                        ctx.declare_alloca(&field_slot, &field_value.ty);
                        ctx.code.push_str(&format!(
                            "  store {} {}, ptr {field_slot}\n",
                            field_value.ty, field_value.value
                        ));
                        ctx.slots.insert(format!("{target}.{field}"), field_slot);
                        ctx.slot_tys
                            .insert(format!("{target}.{field}"), field_value.ty.clone());
                    }
                }
                if let ast::Expr::Range {
                    start,
                    end,
                    inclusive,
                } = value
                {
                    let start_value =
                        llvm_emit_expr(start.as_ref(), ctx, string_literal_ids, task_ref_ids)?;
                    let end_value =
                        llvm_emit_expr(end.as_ref(), ctx, string_literal_ids, task_ref_ids)?;
                    let inclusive_value = LlvmValue {
                        value: if *inclusive {
                            "1".to_string()
                        } else {
                            "0".to_string()
                        },
                        ty: "i8".to_string(),
                    };
                    for (field, rendered) in [
                        ("start", start_value),
                        ("end", end_value),
                        ("inclusive", inclusive_value),
                    ] {
                        let field_slot = format!("%slot_{}_{}_{}", target, field, ctx.next_value);
                        ctx.declare_alloca(&field_slot, &rendered.ty);
                        ctx.code.push_str(&format!(
                            "  store {} {}, ptr {field_slot}\n",
                            rendered.ty, rendered.value
                        ));
                        ctx.slots.insert(format!("{target}.{field}"), field_slot);
                        ctx.slot_tys
                            .insert(format!("{target}.{field}"), rendered.ty.clone());
                    }
                }
                ctx.array_slots.remove(target);
                ctx.const_strings.remove(target);
                ctx.closures.remove(target);
            }
            ast::Stmt::CompoundAssign { target, op, value } => {
                let combined_expr = ast::Expr::Binary {
                    op: *op,
                    left: Box::new(ast::Expr::Ident(target.clone())),
                    right: Box::new(value.clone()),
                };
                let value = llvm_emit_expr(&combined_expr, ctx, string_literal_ids, task_ref_ids)?;
                if let Some(symbol) = ctx.mutable_globals.get(target).cloned() {
                    let stored = llvm_cast_value(ctx, value.clone(), "i32")?;
                    ctx.code
                        .push_str(&format!("  store i32 {}, ptr @{symbol}\n", stored.value));
                    ctx.direct_values.remove(target);
                    continue;
                }
                let slot = ctx
                    .slots
                    .entry(target.clone())
                    .or_insert_with(|| format!("%slot_{}_{}", target, ctx.next_value))
                    .clone();
                ctx.declare_alloca(&slot, &value.ty);
                ctx.code.push_str(&format!(
                    "  store {} {}, ptr {slot}\n",
                    value.ty, value.value
                ));
                ctx.slot_tys.insert(target.clone(), value.ty.clone());
                ctx.direct_values.remove(target);
                ctx.array_slots.remove(target);
                ctx.const_strings.remove(target);
                ctx.closures.remove(target);
            }
            ast::Stmt::Defer(expr) => {
                deferred.push(expr.clone());
            }
            ast::Stmt::Expr(expr) | ast::Stmt::Requires(expr) | ast::Stmt::Ensures(expr) => {
                let _ = llvm_emit_expr(expr, ctx, string_literal_ids, task_ref_ids);
            }
            ast::Stmt::Return(value) => {
                match value {
                    Some(expr) => {
                        let value = llvm_emit_expr(expr, ctx, string_literal_ids, task_ref_ids)?;
                        let function_return_ty = ctx.function_return_ty.clone();
                        let value = llvm_cast_value(ctx, value, &function_return_ty)?;
                        for expr in deferred.iter().rev() {
                            let _ = llvm_emit_expr(expr, ctx, string_literal_ids, task_ref_ids);
                        }
                        ctx.code
                            .push_str(&format!("  ret {} {}\n", value.ty, value.value));
                    }
                    None => {
                        for expr in deferred.iter().rev() {
                            let _ = llvm_emit_expr(expr, ctx, string_literal_ids, task_ref_ids);
                        }
                        if ctx.function_return_ty == "void" {
                            ctx.code.push_str("  ret void\n");
                        } else {
                            let fallback = llvm_zero_literal(&ctx.function_return_ty, 0);
                            ctx.code.push_str(&format!(
                                "  ret {} {}\n",
                                ctx.function_return_ty, fallback
                            ));
                        }
                    }
                }
                return Ok(true);
            }
            ast::Stmt::If { .. }
            | ast::Stmt::While { .. }
            | ast::Stmt::For { .. }
            | ast::Stmt::ForIn { .. }
            | ast::Stmt::Loop { .. }
            | ast::Stmt::Break(_)
            | ast::Stmt::Continue
            | ast::Stmt::Match { .. } => {
                bail!("llvm linear emission received non-linear control-flow statement");
            }
        }
    }
    for expr in deferred.iter().rev() {
        let _ = llvm_emit_expr(expr, ctx, string_literal_ids, task_ref_ids);
    }
    Ok(false)
}

pub(super) fn llvm_emit_condition_value(
    expr: &ast::Expr,
    ctx: &mut LlvmFuncCtx,
    string_literal_ids: &HashMap<String, i32>,
    task_ref_ids: &HashMap<String, i32>,
) -> Result<String> {
    match expr {
        ast::Expr::Group(inner) | ast::Expr::Await(inner) => {
            llvm_emit_condition_value(inner, ctx, string_literal_ids, task_ref_ids)
        }
        ast::Expr::Binary { op, left, right } => {
            let lhs = llvm_emit_expr(left, ctx, string_literal_ids, task_ref_ids)?;
            let rhs = llvm_emit_expr_as(right, ctx, string_literal_ids, task_ref_ids, &lhs.ty)?;
            let pred = ctx.value();
            let cc = match op {
                ast::BinaryOp::Eq => Some(("eq", "oeq")),
                ast::BinaryOp::Neq => Some(("ne", "une")),
                ast::BinaryOp::Lt => Some(("slt", "olt")),
                ast::BinaryOp::Lte => Some(("sle", "ole")),
                ast::BinaryOp::Gt => Some(("sgt", "ogt")),
                ast::BinaryOp::Gte => Some(("sge", "oge")),
                _ => None,
            };
            if let Some(cc) = cc {
                if llvm_is_float_ty(&lhs.ty) {
                    ctx.code.push_str(&format!(
                        "  {pred} = fcmp {} {} {}, {}\n",
                        cc.1, lhs.ty, lhs.value, rhs.value
                    ));
                } else {
                    ctx.code.push_str(&format!(
                        "  {pred} = icmp {} {} {}, {}\n",
                        cc.0, lhs.ty, lhs.value, rhs.value
                    ));
                }
                return Ok(pred);
            }
            let value = llvm_emit_expr(expr, ctx, string_literal_ids, task_ref_ids)?;
            Ok(llvm_emit_truthy_pred(ctx, &value))
        }
        _ => {
            let value = llvm_emit_expr(expr, ctx, string_literal_ids, task_ref_ids)?;
            Ok(llvm_emit_truthy_pred(ctx, &value))
        }
    }
}

pub(super) fn llvm_emit_binary_expr(
    op: ast::BinaryOp,
    left: &ast::Expr,
    right: &ast::Expr,
    ctx: &mut LlvmFuncCtx,
    string_literal_ids: &HashMap<String, i32>,
    task_ref_ids: &HashMap<String, i32>,
) -> Result<LlvmValue> {
    let lhs = llvm_emit_expr(left, ctx, string_literal_ids, task_ref_ids)?;
    Ok(match op {
        ast::BinaryOp::Add => {
            let rhs = llvm_emit_expr_as(right, ctx, string_literal_ids, task_ref_ids, &lhs.ty)?;
            let out = ctx.value();
            let op = if llvm_is_float_ty(&lhs.ty) {
                "fadd"
            } else {
                "add"
            };
            ctx.code.push_str(&format!(
                "  {out} = {op} {} {}, {}\n",
                lhs.ty, lhs.value, rhs.value
            ));
            llvm_assert_finite(
                ctx,
                LlvmValue {
                    value: out,
                    ty: lhs.ty,
                },
            )?
        }
        ast::BinaryOp::Sub => {
            let rhs = llvm_emit_expr_as(right, ctx, string_literal_ids, task_ref_ids, &lhs.ty)?;
            let out = ctx.value();
            let op = if llvm_is_float_ty(&lhs.ty) {
                "fsub"
            } else {
                "sub"
            };
            ctx.code.push_str(&format!(
                "  {out} = {op} {} {}, {}\n",
                lhs.ty, lhs.value, rhs.value
            ));
            llvm_assert_finite(
                ctx,
                LlvmValue {
                    value: out,
                    ty: lhs.ty,
                },
            )?
        }
        ast::BinaryOp::Mul => {
            let rhs = llvm_emit_expr_as(right, ctx, string_literal_ids, task_ref_ids, &lhs.ty)?;
            let out = ctx.value();
            let op = if llvm_is_float_ty(&lhs.ty) {
                "fmul"
            } else {
                "mul"
            };
            ctx.code.push_str(&format!(
                "  {out} = {op} {} {}, {}\n",
                lhs.ty, lhs.value, rhs.value
            ));
            llvm_assert_finite(
                ctx,
                LlvmValue {
                    value: out,
                    ty: lhs.ty,
                },
            )?
        }
        ast::BinaryOp::Div => {
            let rhs = llvm_emit_expr_as(right, ctx, string_literal_ids, task_ref_ids, &lhs.ty)?;
            let out = ctx.value();
            let op = if llvm_is_float_ty(&lhs.ty) {
                "fdiv"
            } else {
                "sdiv"
            };
            ctx.code.push_str(&format!(
                "  {out} = {op} {} {}, {}\n",
                lhs.ty, lhs.value, rhs.value
            ));
            llvm_assert_finite(
                ctx,
                LlvmValue {
                    value: out,
                    ty: lhs.ty,
                },
            )?
        }
        ast::BinaryOp::Mod => {
            let rhs = llvm_emit_expr_as(right, ctx, string_literal_ids, task_ref_ids, &lhs.ty)?;
            let out = ctx.value();
            ctx.code.push_str(&format!(
                "  {out} = srem {} {}, {}\n",
                lhs.ty, lhs.value, rhs.value
            ));
            LlvmValue {
                value: out,
                ty: lhs.ty,
            }
        }
        ast::BinaryOp::BitAnd => {
            let rhs = llvm_emit_expr_as(right, ctx, string_literal_ids, task_ref_ids, &lhs.ty)?;
            let out = ctx.value();
            ctx.code.push_str(&format!(
                "  {out} = and {} {}, {}\n",
                lhs.ty, lhs.value, rhs.value
            ));
            LlvmValue {
                value: out,
                ty: lhs.ty,
            }
        }
        ast::BinaryOp::BitOr => {
            let rhs = llvm_emit_expr_as(right, ctx, string_literal_ids, task_ref_ids, &lhs.ty)?;
            let out = ctx.value();
            ctx.code.push_str(&format!(
                "  {out} = or {} {}, {}\n",
                lhs.ty, lhs.value, rhs.value
            ));
            LlvmValue {
                value: out,
                ty: lhs.ty,
            }
        }
        ast::BinaryOp::BitXor => {
            let rhs = llvm_emit_expr_as(right, ctx, string_literal_ids, task_ref_ids, &lhs.ty)?;
            let out = ctx.value();
            ctx.code.push_str(&format!(
                "  {out} = xor {} {}, {}\n",
                lhs.ty, lhs.value, rhs.value
            ));
            LlvmValue {
                value: out,
                ty: lhs.ty,
            }
        }
        ast::BinaryOp::Shl => {
            let rhs = llvm_emit_expr_as(right, ctx, string_literal_ids, task_ref_ids, &lhs.ty)?;
            let out = ctx.value();
            ctx.code.push_str(&format!(
                "  {out} = shl {} {}, {}\n",
                lhs.ty, lhs.value, rhs.value
            ));
            LlvmValue {
                value: out,
                ty: lhs.ty,
            }
        }
        ast::BinaryOp::Shr => {
            let rhs = llvm_emit_expr_as(right, ctx, string_literal_ids, task_ref_ids, &lhs.ty)?;
            let out = ctx.value();
            ctx.code.push_str(&format!(
                "  {out} = ashr {} {}, {}\n",
                lhs.ty, lhs.value, rhs.value
            ));
            LlvmValue {
                value: out,
                ty: lhs.ty,
            }
        }
        ast::BinaryOp::And | ast::BinaryOp::Or => {
            let lhs_pred = llvm_emit_truthy_pred(ctx, &lhs);
            let rhs_label = ctx.label("logical.rhs");
            let short_label = ctx.label("logical.short");
            let merge_label = ctx.label("logical.merge");
            let result_slot = format!("%slot_logical_{}", ctx.next_value);
            ctx.next_value += 1;
            ctx.code.push_str(&format!("  {result_slot} = alloca i8\n"));
            match op {
                ast::BinaryOp::And => {
                    ctx.code.push_str(&format!(
                        "  br i1 {lhs_pred}, label %{rhs_label}, label %{short_label}\n"
                    ));
                    ctx.code.push_str(&format!("{short_label}:\n"));
                    ctx.code
                        .push_str(&format!("  store i8 0, ptr {result_slot}\n"));
                    ctx.code.push_str(&format!("  br label %{merge_label}\n"));
                }
                ast::BinaryOp::Or => {
                    ctx.code.push_str(&format!(
                        "  br i1 {lhs_pred}, label %{short_label}, label %{rhs_label}\n"
                    ));
                    ctx.code.push_str(&format!("{short_label}:\n"));
                    ctx.code
                        .push_str(&format!("  store i8 1, ptr {result_slot}\n"));
                    ctx.code.push_str(&format!("  br label %{merge_label}\n"));
                }
                _ => unreachable!(),
            }
            ctx.code.push_str(&format!("{rhs_label}:\n"));
            let rhs = llvm_emit_expr(right, ctx, string_literal_ids, task_ref_ids)?;
            let rhs_pred = llvm_emit_truthy_pred(ctx, &rhs);
            let rhs_i8 = ctx.value();
            ctx.code
                .push_str(&format!("  {rhs_i8} = zext i1 {rhs_pred} to i8\n"));
            ctx.code
                .push_str(&format!("  store i8 {rhs_i8}, ptr {result_slot}\n"));
            ctx.code.push_str(&format!("  br label %{merge_label}\n"));
            ctx.code.push_str(&format!("{merge_label}:\n"));
            let out = ctx.value();
            ctx.code
                .push_str(&format!("  {out} = load i8, ptr {result_slot}\n"));
            LlvmValue {
                value: out,
                ty: "i8".to_string(),
            }
        }
        ast::BinaryOp::Eq
        | ast::BinaryOp::Neq
        | ast::BinaryOp::Lt
        | ast::BinaryOp::Lte
        | ast::BinaryOp::Gt
        | ast::BinaryOp::Gte => {
            let rhs = llvm_emit_expr_as(right, ctx, string_literal_ids, task_ref_ids, &lhs.ty)?;
            let pred = ctx.value();
            if llvm_is_float_ty(&lhs.ty) {
                let cmp = match op {
                    ast::BinaryOp::Eq => "oeq",
                    ast::BinaryOp::Neq => "une",
                    ast::BinaryOp::Lt => "olt",
                    ast::BinaryOp::Lte => "ole",
                    ast::BinaryOp::Gt => "ogt",
                    ast::BinaryOp::Gte => "oge",
                    _ => unreachable!(),
                };
                ctx.code.push_str(&format!(
                    "  {pred} = fcmp {cmp} {} {}, {}\n",
                    lhs.ty, lhs.value, rhs.value
                ));
            } else {
                let cmp = match op {
                    ast::BinaryOp::Eq => "eq",
                    ast::BinaryOp::Neq => "ne",
                    ast::BinaryOp::Lt => "slt",
                    ast::BinaryOp::Lte => "sle",
                    ast::BinaryOp::Gt => "sgt",
                    ast::BinaryOp::Gte => "sge",
                    _ => unreachable!(),
                };
                ctx.code.push_str(&format!(
                    "  {pred} = icmp {cmp} {} {}, {}\n",
                    lhs.ty, lhs.value, rhs.value
                ));
            }
            llvm_bool_from_pred(ctx, &pred)
        }
    })
}

pub(super) fn llvm_emit_complex_expr(
    expr: &ast::Expr,
    ctx: &mut LlvmFuncCtx,
    string_literal_ids: &HashMap<String, i32>,
    task_ref_ids: &HashMap<String, i32>,
) -> Option<Result<LlvmValue>> {
    match expr {
        ast::Expr::If {
            condition,
            then_expr,
            else_expr,
        } => Some((|| {
            let pred = llvm_emit_condition_value(condition, ctx, string_literal_ids, task_ref_ids)?;
            let then_label = ctx.label("if.then");
            let else_label = ctx.label("if.else");
            let merge_label = ctx.label("if.merge");
            ctx.code.push_str(&format!(
                "  br i1 {pred}, label %{then_label}, label %{else_label}\n"
            ));

            ctx.code.push_str(&format!("{then_label}:\n"));
            let then_value = llvm_emit_expr(then_expr, ctx, string_literal_ids, task_ref_ids)?;
            ctx.code.push_str(&format!("  br label %{merge_label}\n"));

            ctx.code.push_str(&format!("{else_label}:\n"));
            let else_value = llvm_emit_expr(else_expr, ctx, string_literal_ids, task_ref_ids)?;
            let else_value = llvm_cast_value(ctx, else_value, &then_value.ty)?;
            ctx.code.push_str(&format!("  br label %{merge_label}\n"));

            ctx.code.push_str(&format!("{merge_label}:\n"));
            let out = ctx.value();
            ctx.code.push_str(&format!(
                "  {out} = phi {} [ {}, %{then_label} ], [ {}, %{else_label} ]\n",
                then_value.ty, then_value.value, else_value.value
            ));
            Ok(LlvmValue {
                value: out,
                ty: then_value.ty,
            })
        })()),
        ast::Expr::ObjectLiteral(fields) => Some((|| {
            let map_symbol = native_mangle_symbol(
                native_runtime_import_for_callee("map.new")
                    .expect("map.new runtime import must exist")
                    .symbol,
            );
            let set_symbol = native_mangle_symbol(
                native_runtime_import_for_callee("map.set")
                    .expect("map.set runtime import must exist")
                    .symbol,
            );
            let map_handle = ctx.value();
            ctx.code
                .push_str(&format!("  {map_handle} = call i32 @{map_symbol}()\n"));
            for (key, value) in fields {
                let key_id = string_literal_ids.get(key).copied().unwrap_or(0);
                let rendered = llvm_emit_expr(value, ctx, string_literal_ids, task_ref_ids)?;
                let rendered = llvm_cast_value(ctx, rendered, "i32")?;
                let status = ctx.value();
                ctx.code.push_str(&format!(
                    "  {status} = call i32 @{set_symbol}(i32 {map_handle}, i32 {key_id}, i32 {})\n",
                    rendered.value
                ));
            }
            Ok(LlvmValue {
                value: map_handle,
                ty: "i32".to_string(),
            })
        })()),
        ast::Expr::Index { base, index } => Some((|| {
            let index_value = if let Some((base_name, offset)) =
                canonicalize_array_index_window(index)
            {
                if let Some(slot) = ctx.slots.get(&base_name).cloned() {
                    let base_loaded = ctx.value();
                    ctx.code
                        .push_str(&format!("  {base_loaded} = load i32, ptr {slot}\n"));
                    if offset == 0 {
                        base_loaded
                    } else {
                        let adjusted = ctx.value();
                        let op = if offset >= 0 { "add" } else { "sub" };
                        let rhs = offset.unsigned_abs();
                        ctx.code
                            .push_str(&format!("  {adjusted} = {op} i32 {base_loaded}, {rhs}\n"));
                        adjusted
                    }
                } else {
                    llvm_emit_expr_as(index, ctx, string_literal_ids, task_ref_ids, "i32")?.value
                }
            } else {
                llvm_emit_expr_as(index, ctx, string_literal_ids, task_ref_ids, "i32")?.value
            };
            if let ast::Expr::Ident(name) = base.as_ref() {
                if let Some(binding) = ctx.array_slots.get(name).cloned() {
                    return llvm_emit_array_index_from_binding(binding, index, &index_value, ctx);
                }
            }
            let base_value = llvm_emit_expr(base, ctx, string_literal_ids, task_ref_ids)?;
            let temp_array_slot = format!("%slot_array_index_{}", ctx.next_value);
            ctx.next_value += 1;
            if let Some(binding) = llvm_array_binding_from_ir_type(&temp_array_slot, &base_value.ty)
            {
                ctx.declare_alloca(&binding.storage, &base_value.ty);
                ctx.code.push_str(&format!(
                    "  store {} {}, ptr {}\n",
                    base_value.ty, base_value.value, binding.storage
                ));
                return llvm_emit_array_index_from_binding(binding, index, &index_value, ctx);
            }
            Ok(base_value)
        })()),
        ast::Expr::Call { callee, args } => Some((|| {
            if let Some(value) = eval_const_i32_call(callee, args, &ctx.const_strings) {
                return Ok(LlvmValue {
                    value: value.to_string(),
                    ty: "i32".to_string(),
                });
            }
            if let Some(value) = eval_const_string_call(callee, args, &ctx.const_strings) {
                if let Some(id) = string_literal_ids.get(&value).copied() {
                    return Ok(LlvmValue {
                        value: id.to_string(),
                        ty: "i32".to_string(),
                    });
                }
            }
            if let Some(value) =
                llvm_emit_simd_intrinsic_call(callee, args, ctx, string_literal_ids, task_ref_ids)?
            {
                return Ok(value);
            }
            if callee == "str.concat" && args.len() >= 2 {
                let mut acc = llvm_emit_expr(&args[0], ctx, string_literal_ids, task_ref_ids)?;
                for arg in args.iter().skip(1) {
                    let rhs =
                        llvm_emit_expr_as(arg, ctx, string_literal_ids, task_ref_ids, &acc.ty)?;
                    let symbol = ctx
                        .extern_link_symbols
                        .get("str.concat")
                        .map(|value| value.as_str())
                        .unwrap_or("fz_native_str_concat2");
                    let symbol = native_mangle_symbol(symbol);
                    let val = ctx.value();
                    ctx.code.push_str(&format!(
                        "  {val} = call {} @{symbol}({} {}, {} {})\n",
                        acc.ty, acc.ty, acc.value, rhs.ty, rhs.value
                    ));
                    acc = LlvmValue {
                        value: val,
                        ty: acc.ty.clone(),
                    };
                }
                return llvm_assert_finite(ctx, acc);
            }
            if let Some(binding) = ctx.closures.get(callee).cloned() {
                return llvm_emit_inlined_closure_call(
                    binding,
                    args,
                    ctx,
                    string_literal_ids,
                    task_ref_ids,
                );
            }
            let signature = ctx.function_sigs.get(callee).cloned();
            let mut rendered_args = Vec::with_capacity(args.len());
            for (index, arg) in args.iter().enumerate() {
                let value = if signature
                    .as_ref()
                    .is_some_and(|sig| llvm_is_extern_c_borrowed_ptr_param(sig, index))
                    && llvm_expr_is_fzy_str(arg, ctx)
                {
                    llvm_emit_borrowed_str_ptr_arg(arg, ctx, string_literal_ids, task_ref_ids)?
                } else {
                    llvm_emit_expr(arg, ctx, string_literal_ids, task_ref_ids)?
                };
                let value = if let Some(sig) = &signature {
                    if let Some(target_ty) = sig.params.get(index) {
                        llvm_cast_value(ctx, value, target_ty)?
                    } else {
                        value
                    }
                } else {
                    llvm_cast_value(ctx, value, "i32")?
                };
                rendered_args.push(format!("{} {}", value.ty, value.value));
            }
            let args = rendered_args.join(", ");
            let symbol = native_runtime_import_for_callee(callee)
                .or_else(|| native_data_plane_import_for_callee(callee))
                .map(|import| import.symbol)
                .unwrap_or(callee.as_str());
            let symbol = ctx
                .extern_link_symbols
                .get(callee)
                .map(|value| value.as_str())
                .unwrap_or(symbol);
            let symbol = native_mangle_symbol(symbol);
            let return_ty = signature
                .and_then(|sig| sig.ret)
                .unwrap_or_else(|| "i32".to_string());
            if return_ty == "void" {
                ctx.code
                    .push_str(&format!("  call void @{symbol}({args})\n"));
                Ok(LlvmValue {
                    value: "0".to_string(),
                    ty: "i32".to_string(),
                })
            } else {
                let val = ctx.value();
                ctx.code
                    .push_str(&format!("  {val} = call {return_ty} @{symbol}({args})\n"));
                llvm_assert_finite(
                    ctx,
                    LlvmValue {
                        value: val,
                        ty: return_ty,
                    },
                )
            }
        })()),
        ast::Expr::UnsafeBlock { body, .. } => Some((|| {
            let terminated = llvm_emit_linear_stmts(body, ctx, string_literal_ids, task_ref_ids)?;
            if terminated {
                let continuation = ctx.label("unsafe.cont");
                ctx.code.push_str(&format!("{continuation}:\n"));
            }
            Ok(LlvmValue {
                value: "0".to_string(),
                ty: "i32".to_string(),
            })
        })()),
        _ => None,
    }
}

pub(super) fn llvm_emit_simple_expr(
    expr: &ast::Expr,
    ctx: &mut LlvmFuncCtx,
    string_literal_ids: &HashMap<String, i32>,
    task_ref_ids: &HashMap<String, i32>,
) -> Option<Result<LlvmValue>> {
    match expr {
        ast::Expr::Ident(name) => Some(Ok(if let Some(direct) = ctx.direct_values.get(name) {
            direct.clone()
        } else if let Some(value) = ctx.const_strings.get(name).cloned() {
            LlvmValue {
                value: string_literal_ids
                    .get(&value)
                    .copied()
                    .unwrap_or(0)
                    .to_string(),
                ty: "i32".to_string(),
            }
        } else if let Some(value) =
            resolve_native_global_const_i32_expr(expr, &ctx.current_namespace, &ctx.globals)
        {
            LlvmValue {
                value: value.to_string(),
                ty: "i32".to_string(),
            }
        } else if let Some(slot) = ctx.slots.get(name).cloned() {
            let ty = ctx
                .slot_tys
                .get(name)
                .cloned()
                .unwrap_or_else(|| "i32".to_string());
            let val = ctx.value();
            ctx.code
                .push_str(&format!("  {val} = load {ty}, ptr {slot}\n"));
            LlvmValue { value: val, ty }
        } else if let Some(symbol) = ctx.mutable_globals.get(name).cloned() {
            let val = ctx.value();
            ctx.code
                .push_str(&format!("  {val} = load i32, ptr @{symbol}\n"));
            LlvmValue {
                value: val,
                ty: "i32".to_string(),
            }
        } else if let Some(value) = ctx.globals.get(name).copied() {
            LlvmValue {
                value: value.to_string(),
                ty: "i32".to_string(),
            }
        } else if let Some(task_ref) = task_ref_ids.get(name).copied() {
            LlvmValue {
                value: task_ref.to_string(),
                ty: "i32".to_string(),
            }
        } else {
            LlvmValue {
                value: "0".to_string(),
                ty: "i32".to_string(),
            }
        })),
        ast::Expr::Discard(inner) => Some((|| {
            let _ = llvm_emit_expr(inner, ctx, string_literal_ids, task_ref_ids)?;
            Ok(LlvmValue {
                value: "0".to_string(),
                ty: "i32".to_string(),
            })
        })()),
        ast::Expr::Closure {
            params,
            return_type,
            body,
        } => Some(Ok({
            let captures = llvm_snapshot_closure_captures(ctx);
            let name = format!("__closure_{}", ctx.next_value);
            ctx.closures.insert(
                name,
                LlvmClosureBinding {
                    params: params.clone(),
                    return_type: return_type.clone(),
                    body: (**body).clone(),
                    captures,
                },
            );
            LlvmValue {
                value: "0".to_string(),
                ty: "i32".to_string(),
            }
        })),
        ast::Expr::Unary { op, expr } => Some((|| {
            let value = llvm_emit_expr(expr, ctx, string_literal_ids, task_ref_ids)?;
            Ok(match op {
                ast::UnaryOp::Plus => value,
                ast::UnaryOp::Neg => {
                    let out = ctx.value();
                    if llvm_is_float_ty(&value.ty) {
                        ctx.code.push_str(&format!(
                            "  {out} = fsub {} 0.0, {}\n",
                            value.ty, value.value
                        ));
                        llvm_assert_finite(
                            ctx,
                            LlvmValue {
                                value: out,
                                ty: value.ty,
                            },
                        )?
                    } else {
                        ctx.code
                            .push_str(&format!("  {out} = sub {} 0, {}\n", value.ty, value.value));
                        LlvmValue {
                            value: out,
                            ty: value.ty,
                        }
                    }
                }
                ast::UnaryOp::BitNot => {
                    let out = ctx.value();
                    ctx.code
                        .push_str(&format!("  {out} = xor {} {}, -1\n", value.ty, value.value));
                    LlvmValue {
                        value: out,
                        ty: value.ty,
                    }
                }
                ast::UnaryOp::Not => {
                    let pred = llvm_emit_truthy_pred(ctx, &value);
                    let out = ctx.value();
                    ctx.code
                        .push_str(&format!("  {out} = xor i1 {pred}, true\n"));
                    llvm_bool_from_pred(ctx, &out)
                }
            })
        })()),
        ast::Expr::FieldAccess { base, field } => Some((|| {
            if let Some(value) =
                resolve_native_global_const_i32_expr(expr, &ctx.current_namespace, &ctx.globals)
            {
                return Ok(LlvmValue {
                    value: value.to_string(),
                    ty: "i32".to_string(),
                });
            }
            if let Some(field_expr) = resolve_field_expr(base, field) {
                return llvm_emit_expr(&field_expr, ctx, string_literal_ids, task_ref_ids);
            }
            if let ast::Expr::Ident(name) = base.as_ref() {
                if let Some(slot) = ctx.slots.get(&format!("{name}.{field}")).cloned() {
                    let ty = ctx
                        .slot_tys
                        .get(&format!("{name}.{field}"))
                        .cloned()
                        .unwrap_or_else(|| "i32".to_string());
                    let val = ctx.value();
                    ctx.code
                        .push_str(&format!("  {val} = load {ty}, ptr {slot}\n"));
                    return Ok(LlvmValue { value: val, ty });
                }
                if let Some(binding) = ctx.aggregate_bindings.get(name).cloned() {
                    if let Some(item) = binding.items.get(field) {
                        let handle = llvm_emit_expr(base, ctx, string_literal_ids, task_ref_ids)?;
                        return Ok(llvm_emit_aggregate_get(ctx, &handle, item.index, &item.ty));
                    }
                }
                if let Some(item) = llvm_struct_field_binding_for_local(name, field, ctx) {
                    let handle = llvm_emit_expr(base, ctx, string_literal_ids, task_ref_ids)?;
                    return Ok(llvm_emit_aggregate_get(ctx, &handle, item.index, &item.ty));
                }
            }
            if let Some(task_ref_name) = expr_task_ref_name(expr) {
                if let Some(task_ref) = task_ref_ids.get(&task_ref_name).copied() {
                    return Ok(LlvmValue {
                        value: task_ref.to_string(),
                        ty: "i32".to_string(),
                    });
                }
            }
            let base_value = llvm_emit_expr(base, ctx, string_literal_ids, task_ref_ids)?;
            if base_value.ty == "i64" {
                let tag_value = ctx.value();
                ctx.code.push_str(&format!(
                    "  {tag_value} = call i32 @{}(i64 {})\n",
                    NATIVE_AGG_TAG_SYMBOL, base_value.value
                ));
                let _ = tag_value;
            }
            Ok(base_value)
        })()),
        ast::Expr::Tuple(items) => Some((|| {
            let mut rendered = Vec::with_capacity(items.len());
            for item in items {
                rendered.push(llvm_emit_expr(item, ctx, string_literal_ids, task_ref_ids)?);
            }
            Ok(llvm_emit_aggregate_handle(0, &rendered, ctx))
        })()),
        ast::Expr::ArrayLiteral(items) => Some(llvm_emit_array_literal_value(
            items,
            ctx,
            string_literal_ids,
            task_ref_ids,
        )),
        ast::Expr::StructInit { fields, .. } => Some((|| {
            let mut rendered = Vec::with_capacity(fields.len());
            for (_, value) in fields {
                rendered.push(llvm_emit_expr(
                    value,
                    ctx,
                    string_literal_ids,
                    task_ref_ids,
                )?);
            }
            Ok(llvm_emit_aggregate_handle(0, &rendered, ctx))
        })()),
        ast::Expr::EnumInit {
            enum_name,
            variant,
            payload,
            named_payload,
        } => Some((|| {
            let key = format!("{enum_name}::{variant}");
            let tag = variant_tag_for_key(&key, &ctx.variant_tags);
            let mut rendered = Vec::with_capacity(payload.len() + named_payload.len());
            for value in payload {
                rendered.push(llvm_emit_expr(
                    value,
                    ctx,
                    string_literal_ids,
                    task_ref_ids,
                )?);
            }
            for (_, value) in named_payload {
                rendered.push(llvm_emit_expr(
                    value,
                    ctx,
                    string_literal_ids,
                    task_ref_ids,
                )?);
            }
            Ok(llvm_emit_aggregate_handle(tag, &rendered, ctx))
        })()),
        _ => None,
    }
}

pub(super) fn llvm_ir_type_for_ast_type(ty: &ast::Type) -> String {
    let pointer_ty = if std::mem::size_of::<usize>() == 8 {
        "i64".to_string()
    } else {
        "i32".to_string()
    };
    match ty {
        ast::Type::Void | ast::Type::Never => "void".to_string(),
        ast::Type::Bool => "i8".to_string(),
        ast::Type::ISize | ast::Type::USize => {
            if std::mem::size_of::<usize>() == 8 {
                "i64".to_string()
            } else {
                "i32".to_string()
            }
        }
        ast::Type::Int { bits, .. } => format!("i{bits}"),
        ast::Type::Float { bits: 32 } => "float".to_string(),
        ast::Type::Float { bits: 64 } => "double".to_string(),
        ast::Type::Array { elem, len } => {
            format!("[{len} x {}]", llvm_ir_type_for_ast_type(elem))
        }
        ast::Type::Ptr { .. } | ast::Type::Ref { .. } | ast::Type::Slice(_) => pointer_ty,
        ast::Type::SimdVector(shape) => match shape.element {
            ast::SimdElement::I32 | ast::SimdElement::U32 => format!("<{} x i32>", shape.lanes),
            ast::SimdElement::F32 => format!("<{} x float>", shape.lanes),
        },
        ast::Type::SimdMask(shape) => format!("<{} x i1>", shape.lanes),
        ast::Type::Char => "i32".to_string(),
        ast::Type::Tuple(_) | ast::Type::Named { .. } => pointer_ty,
        _ => "i32".to_string(),
    }
}

pub(super) fn llvm_is_float_ty(ty: &str) -> bool {
    ty == "float" || ty == "double"
}

pub(super) fn llvm_float_literal(value: f64) -> String {
    let mut rendered = value.to_string();
    if !rendered.contains('.') && !rendered.contains('e') && !rendered.contains('E') {
        rendered.push_str(".0");
    }
    rendered
}

pub(super) fn llvm_zero_literal(ty: &str, int_fallback: i32) -> String {
    if llvm_is_float_ty(ty) {
        "0.0".to_string()
    } else {
        int_fallback.to_string()
    }
}

pub(super) fn llvm_emit_truthy_pred(ctx: &mut LlvmFuncCtx, value: &LlvmValue) -> String {
    let pred = ctx.value();
    if llvm_is_float_ty(&value.ty) {
        ctx.code.push_str(&format!(
            "  {pred} = fcmp une {} {}, 0.0\n",
            value.ty, value.value
        ));
    } else {
        ctx.code.push_str(&format!(
            "  {pred} = icmp ne {} {}, 0\n",
            value.ty, value.value
        ));
    }
    pred
}

pub(super) fn llvm_bool_from_pred(ctx: &mut LlvmFuncCtx, pred: &str) -> LlvmValue {
    let out = ctx.value();
    ctx.code
        .push_str(&format!("  {out} = zext i1 {pred} to i8\n"));
    LlvmValue {
        value: out,
        ty: "i8".to_string(),
    }
}

pub(super) fn llvm_cast_value(
    ctx: &mut LlvmFuncCtx,
    value: LlvmValue,
    target_ty: &str,
) -> Result<LlvmValue> {
    if value.ty == target_ty {
        return Ok(value);
    }
    let out = ctx.value();
    match (value.ty.as_str(), target_ty) {
        ("i8", "i32") | ("i8", "i64") | ("i32", "i64") => {
            ctx.code.push_str(&format!(
                "  {out} = sext {} {} to {target_ty}\n",
                value.ty, value.value
            ));
        }
        ("i64", "i32") | ("i32", "i8") | ("i64", "i8") => {
            ctx.code.push_str(&format!(
                "  {out} = trunc {} {} to {target_ty}\n",
                value.ty, value.value
            ));
        }
        ("i8", "float") | ("i32", "float") | ("i64", "float") => {
            ctx.code.push_str(&format!(
                "  {out} = sitofp {} {} to float\n",
                value.ty, value.value
            ));
        }
        ("i8", "double") | ("i32", "double") | ("i64", "double") => {
            ctx.code.push_str(&format!(
                "  {out} = sitofp {} {} to double\n",
                value.ty, value.value
            ));
        }
        ("float", "i32") | ("float", "i64") | ("double", "i32") | ("double", "i64") => {
            let value = llvm_assert_finite(ctx, value)?;
            ctx.code.push_str(&format!(
                "  {out} = fptosi {} {} to {target_ty}\n",
                value.ty, value.value
            ));
        }
        ("float", "double") => {
            ctx.code.push_str(&format!(
                "  {out} = fpext float {} to double\n",
                value.value
            ));
        }
        ("double", "float") => {
            ctx.code.push_str(&format!(
                "  {out} = fptrunc double {} to float\n",
                value.value
            ));
        }
        _ => {
            return Err(anyhow!(
                "unsupported llvm cast from `{}` to `{target_ty}`",
                value.ty
            ));
        }
    }
    Ok(LlvmValue {
        value: out,
        ty: target_ty.to_string(),
    })
}

pub(super) fn llvm_assert_finite(ctx: &mut LlvmFuncCtx, value: LlvmValue) -> Result<LlvmValue> {
    if !llvm_is_float_ty(&value.ty) {
        return Ok(value);
    }
    let neg_limit = if value.ty == "float" {
        "-3.4028234663852886e+38"
    } else {
        "-1.7976931348623157e+308"
    };
    let pos_limit = if value.ty == "float" {
        "3.4028234663852886e+38"
    } else {
        "1.7976931348623157e+308"
    };
    let lower = ctx.value();
    let upper = ctx.value();
    let finite = ctx.value();
    let ok_label = ctx.label("float.finite");
    let trap_label = ctx.label("float.trap");
    ctx.code.push_str(&format!(
        "  {lower} = fcmp oge {} {}, {neg_limit}\n",
        value.ty, value.value
    ));
    ctx.code.push_str(&format!(
        "  {upper} = fcmp ole {} {}, {pos_limit}\n",
        value.ty, value.value
    ));
    ctx.code
        .push_str(&format!("  {finite} = and i1 {lower}, {upper}\n"));
    ctx.code.push_str(&format!(
        "  br i1 {finite}, label %{ok_label}, label %{trap_label}\n"
    ));
    ctx.code.push_str(&format!("{trap_label}:\n"));
    ctx.code
        .push_str("  call void @llvm.trap()\n  unreachable\n");
    ctx.code.push_str(&format!("{ok_label}:\n"));
    Ok(value)
}

pub(super) fn lower_llvm_ir(fir: &fir::FirModule, enforce_contract_checks: bool) -> Result<String> {
    let plan = build_native_canonical_plan(fir, enforce_contract_checks);
    if fir.typed_functions.is_empty() {
        let ret = plan
            .forced_main_return
            .or(fir.entry_return_const_i32)
            .unwrap_or(0);
        return Ok(format!(
            "; ModuleID = '{name}'\ndefine i32 @main() {{\nentry:\n  ret i32 {ret}\n}}\n",
            name = fir.name
        ));
    }

    let mut out = format!("; ModuleID = '{}'\n", fir.name);
    out.push_str("declare void @llvm.trap()\n");
    let used_imports = collect_used_native_runtime_imports(fir);
    for import in &used_imports {
        match import.callee {
            "alloc" => {
                let _ = writeln!(
                    &mut out,
                    "declare {} @{}({})",
                    llvm_pointer_int_type(),
                    import.symbol,
                    llvm_pointer_int_type()
                );
            }
            "free" => {
                let _ = writeln!(
                    &mut out,
                    "declare void @{}({})",
                    import.symbol,
                    llvm_pointer_int_type()
                );
            }
            "gpu.device_memory_bytes" => {
                let _ = writeln!(&mut out, "declare i64 @{}(i32)", import.symbol);
            }
            "gpu.slice" => {
                let _ = writeln!(
                    &mut out,
                    "declare {} @{}(i32, i32, i32)",
                    llvm_pointer_int_type(),
                    import.symbol
                );
            }
            _ => {
                let mut params = String::new();
                for index in 0..import.arity {
                    if index > 0 {
                        params.push_str(", ");
                    }
                    params.push_str("i32");
                }
                let _ = writeln!(&mut out, "declare i32 @{}({})", import.symbol, params);
            }
        }
    }
    let used_data_plane_imports = collect_used_native_data_plane_imports(fir);
    for import in &used_data_plane_imports {
        let mut params = String::new();
        for index in 0..import.arity {
            if index > 0 {
                params.push_str(", ");
            }
            params.push_str("i32");
        }
        let _ = writeln!(&mut out, "declare i32 @{}({})", import.symbol, params);
    }
    let _ = writeln!(&mut out, "declare i64 @{}(i32, i32)", NATIVE_AGG_NEW_SYMBOL);
    let _ = writeln!(
        &mut out,
        "declare i32 @{}(i64, i32, i64)",
        NATIVE_AGG_SET_I64_SYMBOL
    );
    let _ = writeln!(
        &mut out,
        "declare i64 @{}(i64, i32)",
        NATIVE_AGG_GET_I64_SYMBOL
    );
    let _ = writeln!(&mut out, "declare i32 @{}(i64)", NATIVE_AGG_TAG_SYMBOL);
    let _ = writeln!(
        &mut out,
        "declare {} @{}(i32)",
        llvm_pointer_int_type(),
        NATIVE_STR_PTR_SYMBOL
    );
    let extern_imports = collect_extern_c_imports(fir);
    let mut extern_link_symbols = fir
        .typed_functions
        .iter()
        .filter(|function| is_extern_c_abi_function(function))
        .map(|function| {
            (
                function.name.clone(),
                function
                    .link_name
                    .clone()
                    .unwrap_or_else(|| function.name.clone()),
            )
        })
        .collect::<HashMap<_, _>>();
    extern_link_symbols.insert(
        NATIVE_AGG_NEW.to_string(),
        NATIVE_AGG_NEW_SYMBOL.to_string(),
    );
    extern_link_symbols.insert(
        NATIVE_AGG_SET_I64.to_string(),
        NATIVE_AGG_SET_I64_SYMBOL.to_string(),
    );
    extern_link_symbols.insert(
        NATIVE_AGG_GET_I64.to_string(),
        NATIVE_AGG_GET_I64_SYMBOL.to_string(),
    );
    extern_link_symbols.insert(
        NATIVE_AGG_TAG.to_string(),
        NATIVE_AGG_TAG_SYMBOL.to_string(),
    );
    extern_link_symbols.insert(
        NATIVE_STR_PTR.to_string(),
        NATIVE_STR_PTR_SYMBOL.to_string(),
    );
    let mut function_sigs = HashMap::<String, LlvmFunctionSig>::new();
    for function in &fir.typed_functions {
        function_sigs.insert(
            function.name.clone(),
            LlvmFunctionSig {
                params: function
                    .params
                    .iter()
                    .map(|param| llvm_ir_type_for_ast_type(&param.ty))
                    .collect(),
                ret: (!matches!(function.return_type, ast::Type::Void | ast::Type::Never))
                    .then(|| llvm_ir_type_for_ast_type(&function.return_type)),
                param_names: function
                    .params
                    .iter()
                    .map(|param| param.name.clone())
                    .collect(),
                is_extern_c_import: is_extern_c_import_decl(function),
            },
        );
    }
    function_sigs.insert(
        NATIVE_AGG_NEW.to_string(),
        LlvmFunctionSig {
            params: vec!["i32".to_string(), "i32".to_string()],
            ret: Some("i64".to_string()),
            param_names: Vec::new(),
            is_extern_c_import: false,
        },
    );
    function_sigs.insert(
        NATIVE_AGG_SET_I64.to_string(),
        LlvmFunctionSig {
            params: vec!["i64".to_string(), "i32".to_string(), "i64".to_string()],
            ret: Some("i32".to_string()),
            param_names: Vec::new(),
            is_extern_c_import: false,
        },
    );
    function_sigs.insert(
        NATIVE_AGG_GET_I64.to_string(),
        LlvmFunctionSig {
            params: vec!["i64".to_string(), "i32".to_string()],
            ret: Some("i64".to_string()),
            param_names: Vec::new(),
            is_extern_c_import: false,
        },
    );
    function_sigs.insert(
        NATIVE_AGG_TAG.to_string(),
        LlvmFunctionSig {
            params: vec!["i64".to_string()],
            ret: Some("i32".to_string()),
            param_names: Vec::new(),
            is_extern_c_import: false,
        },
    );
    function_sigs.insert(
        "alloc".to_string(),
        LlvmFunctionSig {
            params: vec![llvm_pointer_int_type().to_string()],
            ret: Some(llvm_pointer_int_type().to_string()),
            param_names: Vec::new(),
            is_extern_c_import: false,
        },
    );
    function_sigs.insert(
        "free".to_string(),
        LlvmFunctionSig {
            params: vec![llvm_pointer_int_type().to_string()],
            ret: None,
            param_names: Vec::new(),
            is_extern_c_import: false,
        },
    );
    function_sigs.insert(
        NATIVE_STR_PTR.to_string(),
        LlvmFunctionSig {
            params: vec!["i32".to_string()],
            ret: Some(llvm_pointer_int_type().to_string()),
            param_names: Vec::new(),
            is_extern_c_import: false,
        },
    );
    for import in &extern_imports {
        let params = import
            .params
            .iter()
            .map(|param| llvm_ir_type_for_ast_type(&param.ty))
            .collect::<Vec<_>>()
            .join(", ");
        let symbol = import.link_name.as_deref().unwrap_or(import.name.as_str());
        let symbol = native_mangle_symbol(symbol);
        let ret = llvm_ir_type_for_ast_type(&import.return_type);
        let _ = writeln!(&mut out, "declare {ret} @{}({})", symbol, params);
    }
    if !used_imports.is_empty() || !used_data_plane_imports.is_empty() || !extern_imports.is_empty()
    {
        out.push('\n');
    }
    let mut mutable_global_symbols = HashMap::<String, String>::new();
    let mut mutable_globals_sorted = plan
        .mutable_static_i32
        .iter()
        .map(|(name, value)| (name.clone(), *value))
        .collect::<Vec<_>>();
    mutable_globals_sorted.sort_by(|a, b| a.0.cmp(&b.0));
    for (name, value) in &mutable_globals_sorted {
        let symbol = llvm_static_symbol_name(name);
        let _ = writeln!(&mut out, "@{symbol} = global i32 {value}");
        mutable_global_symbols.insert(name.clone(), symbol);
    }
    if !mutable_global_symbols.is_empty() {
        out.push('\n');
    }
    for function in &fir.typed_functions {
        if is_extern_c_import_decl(function) {
            continue;
        }
        if let Some(data_ops) = plan.data_ops_by_function.get(&function.name) {
            for op in data_ops {
                let _ = writeln!(&mut out, "; canonical.dataop {}", render_native_data_op(op));
            }
        }
        let lowered = match plan.cfg_by_function.get(&function.name) {
            Some(Ok(cfg)) => llvm_emit_function(
                function,
                plan.forced_main_return.filter(|_| function.name == "main"),
                &plan.global_const_i32,
                &plan.variant_tags,
                &mutable_global_symbols,
                &fir.struct_defs,
                &fir.enum_defs,
                &plan.string_literal_ids,
                &plan.task_ref_ids,
                &extern_link_symbols,
                &function_sigs,
                cfg,
            )
            .map_err(|error| {
                anyhow!(
                    "llvm backend failed lowering canonical cfg for `{}`: {}",
                    function.name,
                    error
                )
            })?,
            Some(Err(error)) => {
                return Err(anyhow!(
                    "canonical cfg unavailable for `{}`: {}",
                    function.name,
                    error
                ));
            }
            None => {
                return Err(anyhow!(
                    "canonical cfg unavailable for `{}`: missing entry",
                    function.name
                ));
            }
        };
        out.push_str(&lowered);
        out.push('\n');
    }
    Ok(out)
}

pub(super) fn llvm_emit_function(
    function: &hir::TypedFunction,
    forced_return: Option<i32>,
    globals: &HashMap<String, i32>,
    variant_tags: &HashMap<String, i32>,
    mutable_globals: &HashMap<String, String>,
    struct_defs: &HashMap<String, ast::Struct>,
    enum_defs: &HashMap<String, ast::Enum>,
    string_literal_ids: &HashMap<String, i32>,
    task_ref_ids: &HashMap<String, i32>,
    extern_link_symbols: &HashMap<String, String>,
    function_sigs: &HashMap<String, LlvmFunctionSig>,
    cfg: &ControlFlowCfg,
) -> Result<String> {
    let params = function
        .params
        .iter()
        .enumerate()
        .map(|(i, param)| format!("{} %arg{i}", llvm_ir_type_for_ast_type(&param.ty)))
        .collect::<Vec<_>>()
        .join(", ");
    let return_ty = llvm_ir_type_for_ast_type(&function.return_type);
    let wrapped_indices = collect_wrapped_index_candidates(&function.body);
    let mut ctx = LlvmFuncCtx::new(
        &function.name,
        globals.clone(),
        variant_tags.clone(),
        mutable_globals.clone(),
        function.local_types.clone(),
        struct_defs.clone(),
        enum_defs.clone(),
        return_ty.clone(),
        wrapped_indices,
        extern_link_symbols.clone(),
        function_sigs.clone(),
    );
    let mut out = format!(
        "define {return_ty} @{}({params}) {{\nentry:\n",
        native_link_symbol_for_function(function),
    );
    for (index, param) in function.params.iter().enumerate() {
        let slot = format!("%slot_{}", param.name);
        let param_ty = llvm_ir_type_for_ast_type(&param.ty);
        ctx.declare_alloca(&slot, &param_ty);
        ctx.code
            .push_str(&format!("  store {param_ty} %arg{index}, ptr {slot}\n"));
        ctx.slots.insert(param.name.clone(), slot.clone());
        ctx.slot_tys.insert(param.name.clone(), param_ty);
        if let Some(binding) = llvm_array_binding_from_type(&slot, &param.ty) {
            ctx.array_slots.insert(param.name.clone(), binding);
        }
    }
    let labels = cfg
        .blocks
        .iter()
        .enumerate()
        .map(|(id, _)| (id, format!("bb{id}")))
        .collect::<HashMap<_, _>>();
    let entry = labels
        .get(&cfg.entry)
        .ok_or_else(|| anyhow!("missing llvm label for cfg entry block {}", cfg.entry))?;
    if cfg.entry != 0 {
        ctx.code.push_str(&format!("  br label %{entry}\n"));
    }
    for (block_id, block) in cfg.blocks.iter().enumerate() {
        ctx.direct_values.clear();
        let label = labels
            .get(&block_id)
            .ok_or_else(|| anyhow!("missing llvm label for cfg block {}", block_id))?;
        if !(block_id == cfg.entry && cfg.entry == 0) {
            ctx.code.push_str(&format!("{label}:\n"));
        }
        let linear_terminated =
            llvm_emit_linear_stmts(&block.stmts, &mut ctx, string_literal_ids, task_ref_ids)?;
        if linear_terminated {
            continue;
        }
        match &block.terminator {
            ControlFlowTerminator::Return(Some(expr)) => {
                let value = llvm_emit_expr(expr, &mut ctx, string_literal_ids, task_ref_ids)?;
                let value = llvm_cast_value(&mut ctx, value, &return_ty)?;
                ctx.code
                    .push_str(&format!("  ret {} {}\n", value.ty, value.value));
            }
            ControlFlowTerminator::Return(None) => {
                let fallback = forced_return.unwrap_or(0);
                if return_ty == "void" {
                    ctx.code.push_str("  ret void\n");
                } else {
                    let fallback = llvm_zero_literal(&return_ty, fallback);
                    ctx.code
                        .push_str(&format!("  ret {return_ty} {fallback}\n"));
                }
            }
            ControlFlowTerminator::Jump { target, .. } => {
                let target_label = labels
                    .get(target)
                    .ok_or_else(|| anyhow!("missing llvm label for cfg jump target {target}"))?;
                ctx.code.push_str(&format!("  br label %{target_label}\n"));
            }
            ControlFlowTerminator::Branch {
                condition,
                then_target,
                else_target,
            } => {
                let pred = llvm_emit_condition_value(
                    condition,
                    &mut ctx,
                    string_literal_ids,
                    task_ref_ids,
                )?;
                let then_label = labels.get(then_target).ok_or_else(|| {
                    anyhow!("missing llvm label for cfg branch target {}", then_target)
                })?;
                let else_label = labels.get(else_target).ok_or_else(|| {
                    anyhow!("missing llvm label for cfg branch target {}", else_target)
                })?;
                ctx.code.push_str(&format!(
                    "  br i1 {pred}, label %{then_label}, label %{else_label}\n"
                ));
            }
            ControlFlowTerminator::Switch {
                scrutinee,
                cases,
                default_target,
            } => {
                let mut value =
                    llvm_emit_expr(scrutinee, &mut ctx, string_literal_ids, task_ref_ids)?;
                let aggregate_switch = match scrutinee {
                    ast::Expr::Ident(name) => {
                        ctx.aggregate_bindings.contains_key(name)
                            || llvm_local_is_aggregate(name, &ctx)
                    }
                    ast::Expr::EnumInit { .. }
                    | ast::Expr::StructInit { .. }
                    | ast::Expr::Tuple(_) => true,
                    _ => false,
                };
                if aggregate_switch && value.ty == "i64" {
                    let tag_value = ctx.value();
                    ctx.code.push_str(&format!(
                        "  {tag_value} = call i32 @{}(i64 {})\n",
                        NATIVE_AGG_TAG_SYMBOL, value.value
                    ));
                    value = LlvmValue {
                        value: tag_value,
                        ty: "i32".to_string(),
                    };
                }
                let default_label = labels.get(default_target).ok_or_else(|| {
                    anyhow!(
                        "missing llvm label for cfg switch default target {}",
                        default_target
                    )
                })?;
                ctx.code.push_str(&format!(
                    "  switch {} {}, label %{default_label} [\n",
                    value.ty, value.value
                ));
                for (case_value, target) in cases {
                    let target_label = labels.get(target).ok_or_else(|| {
                        anyhow!("missing llvm label for cfg switch target {}", target)
                    })?;
                    ctx.code.push_str(&format!(
                        "    {} {case_value}, label %{target_label}\n",
                        value.ty
                    ));
                }
                ctx.code.push_str("  ]\n");
            }
            ControlFlowTerminator::Unreachable => {
                ctx.code.push_str("  unreachable\n");
            }
        }
    }
    out.push_str(&ctx.alloca_prologue);
    out.push_str(&ctx.code);
    out.push_str("}\n");
    Ok(out)
}

pub(super) fn llvm_emit_expr_as(
    expr: &ast::Expr,
    ctx: &mut LlvmFuncCtx,
    string_literal_ids: &HashMap<String, i32>,
    task_ref_ids: &HashMap<String, i32>,
    target_ty: &str,
) -> Result<LlvmValue> {
    let value = llvm_emit_expr(expr, ctx, string_literal_ids, task_ref_ids)?;
    llvm_cast_value(ctx, value, target_ty)
}

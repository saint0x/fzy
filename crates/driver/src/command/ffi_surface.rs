use super::*;

pub(super) fn render_c_header(
    package_name: &str,
    module: &ast::Module,
    exports: &[&ast::Function],
    repr_c_aliases: &BTreeMap<String, String>,
    callback_types: &[interop::CallbackTypeDef],
) -> String {
    let guard = format!("FOZZY_{}_H", package_name.to_ascii_uppercase());
    let mut header = String::new();
    header.push_str("#ifndef ");
    header.push_str(&guard);
    header.push_str("\n#define ");
    header.push_str(&guard);
    header.push_str("\n\n#include <stdbool.h>\n#include <stddef.h>\n#include <stdint.h>\n#include <sys/types.h>\n\n#ifdef __cplusplus\nextern \"C\" {\n#endif\n\n");
    header.push_str("typedef int32_t (*fz_callback_i32_v0)(int32_t arg);\n");
    header.push_str("int32_t fz_host_init(void);\n");
    header.push_str("int32_t fz_host_shutdown(void);\n");
    header.push_str("int32_t fz_host_cleanup(void);\n");
    header.push_str("int32_t fz_host_last_error_code(void);\n");
    header.push_str("int32_t fz_host_last_error_class(void);\n");
    header.push_str("const char* fz_host_last_error_message(void);\n");
    header
        .push_str("int32_t fz_host_register_callback_i32(int32_t slot, fz_callback_i32_v0 cb);\n");
    header.push_str("int32_t fz_host_invoke_callback_i32(int32_t slot, int32_t arg);\n\n");
    if exports.iter().any(|function| function.is_async) {
        header.push_str("typedef uint64_t fz_async_handle_t;\n\n");
    }
    header.push_str(&render_callback_type_defs(callback_types, repr_c_aliases));
    header.push_str(&render_repr_c_type_defs(module, repr_c_aliases));
    if !header.ends_with("\n\n") {
        header.push('\n');
    }
    for function in exports {
        let symbol = ffi_symbol_name(function);
        if function.is_async {
            let params = render_c_params(function, repr_c_aliases, callback_types);
            let start_params = if params == "void" {
                "fz_async_handle_t* handle_out".to_string()
            } else {
                format!("{params}, fz_async_handle_t* handle_out")
            };
            header.push_str(&format!(
                "/* {} uses an eager synchronous start shim and stores the result in an async handle. */\n",
                symbol
            ));
            header.push_str(&format!(
                "int32_t {}_async_start({});\n",
                symbol, start_params
            ));
            header.push_str(&format!(
                "int32_t {}_async_poll(fz_async_handle_t handle, int32_t* done_out);\n",
                symbol
            ));
            header.push_str(&format!(
                "int32_t {}_async_await(fz_async_handle_t handle, int32_t* result_out);\n",
                symbol
            ));
            header.push_str(&format!(
                "int32_t {}_async_drop(fz_async_handle_t handle);\n",
                symbol
            ));
        } else {
            header.push_str(&format!(
                "{} {}({});\n",
                render_c_surface_type(&function.return_type, repr_c_aliases, callback_types),
                symbol,
                render_c_params(function, repr_c_aliases, callback_types)
            ));
        }
    }
    if exports.is_empty() {
        header.push_str("/* no exported extern \"C\" functions found */\n");
    }
    header.push_str("\n#ifdef __cplusplus\n}\n#endif\n\n#endif\n");
    header
}

pub(super) fn render_repr_c_type_defs(
    module: &ast::Module,
    repr_c_aliases: &BTreeMap<String, String>,
) -> String {
    let mut out = String::new();
    for item in &module.items {
        match item {
            ast::Item::Struct(item) if is_repr_c(item.repr.as_deref()) => {
                let c_name = repr_c_aliases
                    .get(&item.name)
                    .cloned()
                    .unwrap_or_else(|| sanitize_c_identifier(&item.name));
                out.push_str(&format!("typedef struct {} {{\n", c_name));
                for field in &item.fields {
                    out.push_str(&format!(
                        "    {} {};\n",
                        render_c_surface_type(&field.ty, repr_c_aliases, &[]),
                        field.name
                    ));
                }
                out.push_str(&format!("}} {};\n\n", c_name));
            }
            ast::Item::Enum(item) if is_repr_c(item.repr.as_deref()) => {
                let c_name = repr_c_aliases
                    .get(&item.name)
                    .cloned()
                    .unwrap_or_else(|| sanitize_c_identifier(&item.name));
                out.push_str(&format!("typedef enum {} {{\n", c_name));
                for (idx, variant) in item.variants.iter().enumerate() {
                    out.push_str(&format!("    {}_{} = {},\n", c_name, variant.name, idx));
                }
                out.push_str(&format!("}} {};\n\n", c_name));
            }
            _ => {}
        }
    }
    out
}

pub(super) fn validate_ffi_contracts(
    module: &ast::Module,
    imports: &[&ast::Function],
    exports: &[&ast::Function],
    repr_c_names: &BTreeSet<String>,
    manifest: Option<&manifest::Manifest>,
) -> Result<()> {
    let has_c_symbols = module.items.iter().any(|item| {
        matches!(
            item,
            ast::Item::Function(function)
                if function.is_extern
                    && function
                        .abi
                        .as_deref()
                        .is_some_and(|abi| abi.eq_ignore_ascii_case("c"))
        )
    });
    let project_default = manifest
        .and_then(|value| value.ffi.panic_boundary.as_deref())
        .filter(|mode| *mode == "abort" || *mode == "error");
    if has_c_symbols && manifest.is_some() && project_default.is_none() {
        bail!(
            "project defines C interop symbols but fozzy.toml is missing [ffi] panic_boundary = \"abort\"|\"error\""
        );
    }
    let mut panic_mode: Option<&str> = None;
    for function in exports {
        let symbol = ffi_symbol_name(function);
        let mode = function.ffi_panic.as_deref().or(project_default).ok_or_else(|| {
            anyhow!(
                "ffi panic contract missing on export `{}`: set [ffi].panic_boundary in fozzy.toml or add #[ffi_panic(...)] override",
                symbol
            )
        })?;
        if mode != "abort" && mode != "error" {
            bail!(
                "invalid ffi panic mode `{}` on export `{}`; expected `abort` or `error`",
                mode,
                symbol
            );
        }
        if let Some(expected) = panic_mode {
            if expected != mode {
                bail!(
                    "ffi panic contract mismatch across exports: expected `{}` but `{}` uses `{}`",
                    expected,
                    symbol,
                    mode
                );
            }
        } else {
            panic_mode = Some(mode);
        }
    }
    for (function, kind) in imports
        .iter()
        .map(|function| (*function, "import"))
        .chain(exports.iter().map(|function| (*function, "export")))
    {
        let symbol = ffi_symbol_name(function);
        if function.is_async && kind == "export" {
            if function.body.is_empty() {
                bail!(
                    "extern async export `{}` must define a body; declaration-only async exports are not allowed",
                    symbol
                );
            }
            if !is_i32_type(&function.return_type) {
                bail!(
                    "extern async export `{}` must return `i32` for async-handle-v1 ABI",
                    symbol
                );
            }
        }
        if function.is_async && kind == "import" {
            bail!(
                "extern C import `{}` cannot be async; async-handle ABI is export-only in native ship v0",
                symbol
            );
        }
        if !is_ffi_stable_type(&function.return_type, repr_c_names) {
            bail!(
                "extern {kind} `{}` uses unstable return type `{}`",
                symbol,
                function.return_type
            );
        }
        for param in &function.params {
            if !is_ffi_stable_type(&param.ty, repr_c_names) {
                bail!(
                    "extern {kind} `{}` param `{}` uses unstable type `{}`",
                    symbol,
                    param.name,
                    param.ty
                );
            }
            if matches!(param.ty, ast::Type::Ptr { .. }) {
                let tagged = param.name.ends_with("_owned")
                    || param.name.ends_with("_borrowed")
                    || param.name.ends_with("_out")
                    || param.name.ends_with("_inout");
                let ctx_param = param.name.ends_with("_ctx") || param.name.ends_with("_context");
                if !tagged && !ctx_param {
                    bail!(
                        "extern {kind} `{}` pointer param `{}` must declare ownership transfer tag suffix (`_owned`, `_borrowed`, `_out`, `_inout`)",
                        symbol,
                        param.name
                    );
                }
                if !ctx_param && !has_len_pair(function, &param.name) {
                    bail!(
                        "extern {kind} `{}` pointer param `{}` must declare paired length parameter (`{}_len` or `len`)",
                        symbol,
                        param.name,
                        pointer_base_name(&param.name),
                    );
                }
            }
            if matches!(param.ty, ast::Type::Function { .. }) {
                let prev_is_anchor = function
                    .params
                    .iter()
                    .position(|candidate| candidate.name == param.name)
                    .and_then(|index| index.checked_sub(1))
                    .and_then(|index| function.params.get(index))
                    .is_some_and(|candidate| {
                        candidate.name.ends_with("_ctx") || candidate.name.ends_with("_context")
                    });
                let next_is_anchor = function
                    .params
                    .iter()
                    .position(|candidate| candidate.name == param.name)
                    .and_then(|index| function.params.get(index + 1))
                    .is_some_and(|candidate| {
                        candidate.name.ends_with("_ctx") || candidate.name.ends_with("_context")
                    });
                if !(prev_is_anchor || next_is_anchor) {
                    bail!(
                        "extern {kind} `{}` callback param `{}` requires adjacent `*_ctx` or `*_context` anchor",
                        symbol,
                        param.name
                    );
                }
            }
        }
    }
    Ok(())
}

#[derive(Debug, Clone)]
pub(super) struct ReprCLayout {
    pub(super) name: String,
    pub(super) kind: &'static str,
    pub(super) size: usize,
    pub(super) align: usize,
    pub(super) fields: Vec<ReprCFieldLayout>,
    pub(super) variants: Vec<ReprCVariantLayout>,
    pub(super) storage: Option<&'static str>,
}

#[derive(Debug, Clone)]
pub(super) struct ReprCFieldLayout {
    pub(super) name: String,
    pub(super) ty: ast::Type,
    pub(super) offset: usize,
    pub(super) size: usize,
    pub(super) align: usize,
}

#[derive(Debug, Clone)]
pub(super) struct ReprCVariantLayout {
    pub(super) name: String,
    pub(super) value: u64,
}

pub(super) fn collect_repr_c_layouts(module: &ast::Module) -> Result<Vec<ReprCLayout>> {
    let mut layouts = Vec::new();
    for item in &module.items {
        match item {
            ast::Item::Struct(item) if is_repr_c(item.repr.as_deref()) => {
                let mut offset = 0usize;
                let mut struct_align = 1usize;
                let mut fields = Vec::with_capacity(item.fields.len());
                for field in &item.fields {
                    let (size, align) = ffi_type_layout(&field.ty).ok_or_else(|| {
                        anyhow!(
                            "repr(C) struct `{}` field `{}` uses unsupported layout type `{}`",
                            item.name,
                            field.name,
                            field.ty
                        )
                    })?;
                    let field_offset = align_up(offset, align);
                    fields.push(ReprCFieldLayout {
                        name: field.name.clone(),
                        ty: field.ty.clone(),
                        offset: field_offset,
                        size,
                        align,
                    });
                    offset = field_offset + size;
                    struct_align = struct_align.max(align);
                }
                let size = align_up(offset, struct_align);
                layouts.push(ReprCLayout {
                    name: item.name.clone(),
                    kind: "struct",
                    size,
                    align: struct_align,
                    fields,
                    variants: Vec::new(),
                    storage: None,
                });
            }
            ast::Item::Enum(item) if is_repr_c(item.repr.as_deref()) => {
                if item
                    .variants
                    .iter()
                    .any(|variant| !variant.payload.is_empty())
                {
                    bail!(
                        "repr(C) enum `{}` has payload variants; only C-style fieldless enums are supported",
                        item.name
                    );
                }
                layouts.push(ReprCLayout {
                    name: item.name.clone(),
                    kind: "enum",
                    size: 4,
                    align: 4,
                    fields: Vec::new(),
                    variants: item
                        .variants
                        .iter()
                        .enumerate()
                        .map(|(index, variant)| ReprCVariantLayout {
                            name: variant.name.clone(),
                            value: index as u64,
                        })
                        .collect(),
                    storage: Some("int32_t"),
                });
            }
            _ => {}
        }
    }
    Ok(layouts)
}

pub(super) fn is_repr_c(repr: Option<&str>) -> bool {
    repr.is_some_and(|repr| repr.to_ascii_lowercase().contains('c'))
}

pub(super) fn abi_identity_fields() -> (String, String, String) {
    let target_triple = std::env::var("TARGET")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| {
            format!(
                "{}-unknown-{}",
                std::env::consts::ARCH,
                std::env::consts::OS
            )
        });
    let data_layout_descriptor = format!(
        "target={target_triple};endian={};ptr_width={};usize={};usize_align={}",
        if cfg!(target_endian = "little") {
            "little"
        } else {
            "big"
        },
        std::mem::size_of::<usize>() * 8,
        std::mem::size_of::<usize>(),
        std::mem::align_of::<usize>()
    );
    let compiler_descriptor = ProcessCommand::new("rustc")
        .arg("-vV")
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_string())
        .unwrap_or_else(|| "rustc:unknown".to_string());
    (
        target_triple,
        sha256_hex(data_layout_descriptor.as_bytes()),
        sha256_hex(compiler_descriptor.as_bytes()),
    )
}

pub(super) fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex_encode(hasher.finalize().as_slice())
}

pub(super) fn ffi_type_layout(ty: &ast::Type) -> Option<(usize, usize)> {
    match ty {
        ast::Type::Void => Some((0, 1)),
        ast::Type::Bool => Some((1, 1)),
        ast::Type::Char => Some((4, 4)),
        ast::Type::ISize | ast::Type::USize => {
            Some((std::mem::size_of::<usize>(), std::mem::align_of::<usize>()))
        }
        ast::Type::Int { bits, .. } => {
            let bytes = (*bits as usize) / 8;
            Some((bytes.max(1), bytes.max(1)))
        }
        ast::Type::Float { bits } => {
            let bytes = (*bits as usize) / 8;
            Some((bytes.max(1), bytes.max(1)))
        }
        ast::Type::Ptr { .. } => {
            Some((std::mem::size_of::<usize>(), std::mem::align_of::<usize>()))
        }
        _ => None,
    }
}

pub(super) fn align_up(value: usize, align: usize) -> usize {
    if align == 0 {
        return value;
    }
    let rem = value % align;
    if rem == 0 {
        value
    } else {
        value + (align - rem)
    }
}

pub(super) fn detect_ffi_panic_boundary(
    exports: &[&ast::Function],
    manifest: Option<&manifest::Manifest>,
) -> Result<&'static str> {
    let project_default = manifest
        .and_then(|value| value.ffi.panic_boundary.as_deref())
        .filter(|mode| *mode == "abort" || *mode == "error");
    if let Some(mode) = project_default {
        return Ok(if mode == "error" { "error" } else { "abort" });
    }
    for function in exports {
        if let Some(mode) = function.ffi_panic.as_deref() {
            if mode == "abort" {
                return Ok("abort");
            }
            if mode == "error" {
                return Ok("error");
            }
        }
    }
    Ok("abort-or-translate")
}

pub(super) fn pointer_base_name(name: &str) -> String {
    for suffix in ["_borrowed", "_owned", "_out", "_inout"] {
        if let Some(stripped) = name.strip_suffix(suffix) {
            return stripped.to_string();
        }
    }
    name.to_string()
}

pub(super) fn has_len_pair(function: &ast::Function, pointer_param_name: &str) -> bool {
    let base = pointer_base_name(pointer_param_name);
    let expected = format!("{base}_len");
    function.params.iter().any(|candidate| {
        matches!(candidate.ty, ast::Type::USize)
            && (candidate.name == "len"
                || candidate.name == expected
                || candidate.name == format!("{base}_bytes"))
    })
}

pub(super) fn is_i32_type(ty: &ast::Type) -> bool {
    matches!(
        ty,
        ast::Type::Int {
            signed: true,
            bits: 32
        }
    )
}

pub(super) fn callback_typedef_for<'a>(
    ty: &ast::Type,
    callback_types: &'a [interop::CallbackTypeDef],
) -> Option<&'a str> {
    let key = ty.to_string();
    callback_types
        .iter()
        .find(|candidate| candidate.signature_key == key)
        .map(|candidate| candidate.typedef_name.as_str())
}

pub(super) fn render_callback_type_defs(
    callback_types: &[interop::CallbackTypeDef],
    repr_c_aliases: &BTreeMap<String, String>,
) -> String {
    let mut out = String::new();
    for callback in callback_types {
        let ast::Type::Function { params, ret } = &callback.ty else {
            continue;
        };
        let rendered_params = if params.is_empty() {
            "void".to_string()
        } else {
            params
                .iter()
                .enumerate()
                .map(|(index, param)| {
                    format!(
                        "{} arg{}",
                        render_c_surface_type(param, repr_c_aliases, callback_types),
                        index
                    )
                })
                .collect::<Vec<_>>()
                .join(", ")
        };
        out.push_str(&format!(
            "typedef {} (*{})({});\n",
            render_c_surface_type(ret.as_ref(), repr_c_aliases, callback_types),
            callback.typedef_name,
            rendered_params
        ));
    }
    if !out.is_empty() {
        out.push('\n');
    }
    out
}

pub(super) fn render_c_surface_type(
    ty: &ast::Type,
    repr_c_aliases: &BTreeMap<String, String>,
    callback_types: &[interop::CallbackTypeDef],
) -> String {
    match ty {
        ast::Type::Function { .. } => callback_typedef_for(ty, callback_types)
            .map(str::to_string)
            .unwrap_or_else(|| "void*".to_string()),
        ast::Type::Named { name, .. } => repr_c_aliases
            .get(name)
            .cloned()
            .unwrap_or_else(|| sanitize_c_identifier(name)),
        ast::Type::Ptr { mutable, to } => {
            let rendered = render_c_surface_type(to, repr_c_aliases, callback_types);
            if *mutable {
                format!("{rendered}*")
            } else {
                format!("const {rendered}*")
            }
        }
        _ => to_c_type(ty),
    }
}

pub(super) fn render_c_params(
    function: &ast::Function,
    repr_c_aliases: &BTreeMap<String, String>,
    callback_types: &[interop::CallbackTypeDef],
) -> String {
    let params = function
        .params
        .iter()
        .map(|param| {
            format!(
                "{} {}",
                render_c_surface_type(&param.ty, repr_c_aliases, callback_types),
                param.name
            )
        })
        .collect::<Vec<_>>()
        .join(", ");
    if params.is_empty() {
        "void".to_string()
    } else {
        params
    }
}

pub(super) fn ffi_ownership_kind(name: &str) -> &'static str {
    if name.ends_with("_owned") {
        "owned"
    } else if name.ends_with("_out") {
        "out"
    } else if name.ends_with("_inout") {
        "inout"
    } else {
        "borrowed"
    }
}

pub(super) fn ffi_param_contract(
    function: &ast::Function,
    param: &ast::Param,
    callback_types: &[interop::CallbackTypeDef],
) -> serde_json::Value {
    let mut lifetime_anchor = serde_json::Value::Null;
    let mut ownership = "value";
    let mut nullability = "n/a";
    let mut mutability = "const";
    let mut view = serde_json::Value::Null;
    let mut callback = serde_json::Value::Null;
    if let ast::Type::Ptr { mutable, .. } = &param.ty {
        ownership = ffi_ownership_kind(&param.name);
        nullability = if param.name.contains("_nullable") {
            "nullable"
        } else {
            "non_null"
        };
        mutability = if *mutable { "mut" } else { "const" };
        let base = pointer_base_name(&param.name);
        lifetime_anchor = serde_json::json!(format!("loan:{base}"));
        let len_name = format!("{base}_len");
        if function.params.iter().any(|p| p.name == len_name) {
            view = serde_json::json!({
                "kind": "ptr_len",
                "lengthParam": len_name,
            });
        } else if function.params.iter().any(|p| p.name == "len") {
            view = serde_json::json!({
                "kind": "ptr_len",
                "lengthParam": "len",
            });
        }
    } else if matches!(param.ty, ast::Type::Function { .. }) {
        ownership = "callback";
        nullability = "non_null";
        callback = serde_json::json!({
            "typedef": callback_typedef_for(&param.ty, callback_types).unwrap_or("unsupported_callback"),
            "signature": param.ty.to_string(),
        });
    }
    serde_json::json!({
        "ownership": ownership,
        "nullability": nullability,
        "mutability": mutability,
        "lifetimeAnchor": lifetime_anchor,
        "view": view,
        "callback": callback,
    })
}

pub(super) fn ffi_return_contract(ty: &ast::Type) -> serde_json::Value {
    let (ownership, nullability, mutability) = match ty {
        ast::Type::Ptr { mutable, .. } => {
            ("owned", "non_null", if *mutable { "mut" } else { "const" })
        }
        _ => ("value", "n/a", "const"),
    };
    serde_json::json!({
        "ownership": ownership,
        "nullability": nullability,
        "mutability": mutability,
    })
}

pub(super) fn ffi_callback_bindings(
    function: &ast::Function,
    callback_types: &[interop::CallbackTypeDef],
) -> Vec<serde_json::Value> {
    let mut out = Vec::new();
    for param in &function.params {
        if !matches!(param.ty, ast::Type::Function { .. }) {
            continue;
        }
        let base = param
            .name
            .trim_end_matches("_callback")
            .trim_end_matches("_cb")
            .trim_end_matches("_handler")
            .trim_end_matches("_fn");
        let context_name = function
            .params
            .iter()
            .find(|candidate| {
                candidate.name == format!("{base}_ctx")
                    || candidate.name == format!("{base}_context")
                    || candidate.name == "cb_ctx"
                    || candidate.name == "callback_ctx"
            })
            .map(|candidate| candidate.name.clone())
            .unwrap_or_else(|| "missing_ctx".to_string());
        out.push(serde_json::json!({
            "callbackParam": param.name,
            "contextParam": context_name,
            "bindingId": format!("cbctx:{base}"),
            "typedef": callback_typedef_for(&param.ty, callback_types).unwrap_or("unsupported_callback"),
            "signature": param.ty.to_string(),
            "obligation": "context_outlives_callback_registration",
        }));
    }
    out
}

pub(super) fn ffi_async_contract(function: &ast::Function) -> serde_json::Value {
    if !function.is_async {
        return serde_json::Value::Null;
    }
    let symbol = ffi_symbol_name(function);
    serde_json::json!({
        "model": "async-handle-sync-start-v1",
        "startSymbol": format!("{}_async_start", symbol),
        "pollSymbol": format!("{}_async_poll", symbol),
        "awaitSymbol": format!("{}_async_await", symbol),
        "dropSymbol": format!("{}_async_drop", symbol),
        "resultType": to_c_type(&function.return_type),
        "startMode": "synchronous-execute-then-store",
    })
}

pub(super) fn ffi_symbol_name(function: &ast::Function) -> &str {
    function
        .link_name
        .as_deref()
        .unwrap_or(function.name.as_str())
}

pub(super) fn is_ffi_stable_type(ty: &ast::Type, repr_c_names: &BTreeSet<String>) -> bool {
    match ty {
        ast::Type::Never
        | ast::Type::Void
        | ast::Type::Bool
        | ast::Type::Char
        | ast::Type::Float { .. }
        | ast::Type::ISize
        | ast::Type::USize
        | ast::Type::Int { .. } => true,
        ast::Type::Ptr { to, .. } => is_ffi_stable_type(to, repr_c_names),
        ast::Type::Named { name, args } => args.is_empty() && repr_c_names.contains(name),
        ast::Type::Function { params, ret } => {
            params
                .iter()
                .all(|param| is_ffi_stable_type(param, repr_c_names))
                && is_ffi_stable_type(ret, repr_c_names)
        }
        ast::Type::BigInt
        | ast::Type::BigUint
        | ast::Type::Decimal128
        | ast::Type::Str
        | ast::Type::Bytes
        | ast::Type::Uuid
        | ast::Type::DynTrait(_)
        | ast::Type::Map { .. }
        | ast::Type::Set(_)
        | ast::Type::Deque(_)
        | ast::Type::Ring(_)
        | ast::Type::Slice(_)
        | ast::Type::Result { .. }
        | ast::Type::Option(_)
        | ast::Type::Vec(_)
        | ast::Type::Future(_)
        | ast::Type::Path
        | ast::Type::PathBuf
        | ast::Type::Url
        | ast::Type::SocketAddr
        | ast::Type::Duration
        | ast::Type::Instant
        | ast::Type::Decimal
        | ast::Type::DateTimeTz
        | ast::Type::ExitStatus
        | ast::Type::SimdVector(_)
        | ast::Type::SimdMask(_)
        | ast::Type::Tuple(_)
        | ast::Type::Ref { .. }
        | ast::Type::Array { .. }
        | ast::Type::TypeVar(_) => false,
    }
}

pub(super) fn to_c_type(ty: &ast::Type) -> String {
    match ty {
        ast::Type::Ptr { mutable, to } => {
            if *mutable {
                format!("{}*", to_c_type(to))
            } else {
                format!("const {}*", to_c_type(to))
            }
        }
        ast::Type::Void => "void".to_string(),
        ast::Type::Bool => "bool".to_string(),
        ast::Type::ISize => "ssize_t".to_string(),
        ast::Type::USize => "size_t".to_string(),
        ast::Type::Int {
            signed: true,
            bits: 8,
        } => "int8_t".to_string(),
        ast::Type::Int {
            signed: true,
            bits: 16,
        } => "int16_t".to_string(),
        ast::Type::Int {
            signed: true,
            bits: 32,
        } => "int32_t".to_string(),
        ast::Type::Int {
            signed: true,
            bits: 64,
        } => "int64_t".to_string(),
        ast::Type::Int {
            signed: true,
            bits: 128,
        } => "__int128_t".to_string(),
        ast::Type::Int {
            signed: false,
            bits: 8,
        } => "uint8_t".to_string(),
        ast::Type::Int {
            signed: false,
            bits: 16,
        } => "uint16_t".to_string(),
        ast::Type::Int {
            signed: false,
            bits: 32,
        } => "uint32_t".to_string(),
        ast::Type::Int {
            signed: false,
            bits: 64,
        } => "uint64_t".to_string(),
        ast::Type::Int {
            signed: false,
            bits: 128,
        } => "__uint128_t".to_string(),
        ast::Type::Float { bits: 32 } => "float".to_string(),
        ast::Type::Float { bits: 64 } => "double".to_string(),
        ast::Type::Char => "uint32_t".to_string(),
        ast::Type::Str => "const char*".to_string(),
        ast::Type::Named { name, .. } => name.clone(),
        _ => "void*".to_string(),
    }
}

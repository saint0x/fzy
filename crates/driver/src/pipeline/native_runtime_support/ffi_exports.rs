use std::collections::{BTreeMap, BTreeSet};

use super::super::*;

#[derive(Debug, Clone)]
pub(crate) struct NativeAsyncExport {
    pub(crate) name: String,
    pub(crate) mangled_symbol: String,
    pub(crate) params: Vec<(String, String)>,
}

#[derive(Debug, Clone)]
pub(crate) struct NativeSyncExport {
    pub(crate) public_symbol: String,
    pub(crate) impl_symbol: String,
    pub(crate) params: Vec<NativeExportParam>,
    pub(crate) return_type: NativeExportReturn,
}

#[derive(Debug, Clone)]
pub(crate) struct NativeExportParam {
    pub(crate) name: String,
    pub(crate) ty: NativeFfiType,
}

#[derive(Debug, Clone)]
pub(crate) enum NativeExportReturn {
    Void,
    Type(NativeFfiType),
}

#[derive(Debug, Clone)]
pub(crate) enum NativeFfiType {
    Scalar { c_type: String },
    ReprCStruct(NativeReprCStruct),
    ReprCEnum(NativeReprCEnum),
}

#[derive(Debug, Clone)]
pub(crate) struct NativeReprCStruct {
    pub(crate) name: String,
    pub(crate) fields: Vec<NativeReprCField>,
}

#[derive(Debug, Clone)]
pub(crate) struct NativeReprCField {
    pub(crate) name: String,
    pub(crate) c_type: String,
}

#[derive(Debug, Clone)]
pub(crate) struct NativeReprCEnum {
    pub(crate) name: String,
    pub(crate) variants: Vec<NativeReprCEnumVariant>,
}

#[derive(Debug, Clone)]
pub(crate) struct NativeReprCEnumVariant {
    pub(crate) name: String,
    pub(crate) value: i32,
}

#[derive(Debug, Clone)]
pub(crate) struct NativeRuntimeShimPlan {
    pub(crate) lowered_fir: fir::FirModule,
    pub(crate) async_exports: Vec<NativeAsyncExport>,
    pub(crate) sync_exports: Vec<NativeSyncExport>,
}

pub(crate) fn is_extern_c_import_decl(function: &hir::TypedFunction) -> bool {
    function.is_extern
        && function
            .abi
            .as_deref()
            .is_some_and(|abi| abi.eq_ignore_ascii_case("c"))
        && function.body.is_empty()
}

pub(crate) fn collect_extern_c_imports(fir: &fir::FirModule) -> Vec<&hir::TypedFunction> {
    fir.typed_functions
        .iter()
        .filter(|function| is_extern_c_import_decl(function))
        .collect()
}

pub(crate) fn is_extern_c_abi_function(function: &hir::TypedFunction) -> bool {
    function.is_extern
        && function
            .abi
            .as_deref()
            .is_some_and(|abi| abi.eq_ignore_ascii_case("c"))
}

pub(crate) fn native_link_symbol_for_function(function: &hir::TypedFunction) -> String {
    let base = if is_extern_c_abi_function(function) {
        function
            .link_name
            .clone()
            .unwrap_or_else(|| function.name.clone())
    } else {
        function.name.clone()
    };
    native_mangle_symbol(&base)
}

pub(crate) fn build_native_runtime_shim_plan(
    fir: &fir::FirModule,
) -> Result<NativeRuntimeShimPlan> {
    let repr_c_types = collect_repr_c_types(fir)?;
    let mut lowered_fir = fir.clone();
    let mut sync_exports = Vec::new();

    for function in &fir.typed_functions {
        if function.is_async || !is_extern_c_abi_function(function) || function.body.is_empty() {
            continue;
        }
        let Some(export) = build_sync_export(function, &repr_c_types)? else {
            continue;
        };
        let lowered_function = lowered_fir
            .typed_functions
            .iter_mut()
            .find(|candidate| candidate.name == function.name)
            .ok_or_else(|| anyhow!("missing lowered function for `{}`", function.name))?;
        lowered_function.link_name = Some(export.impl_symbol.clone());
        sync_exports.push(export);
    }

    let async_exports = collect_async_c_exports(&lowered_fir);
    Ok(NativeRuntimeShimPlan {
        lowered_fir,
        async_exports,
        sync_exports,
    })
}

pub(crate) fn collect_async_c_exports(fir: &fir::FirModule) -> Vec<NativeAsyncExport> {
    fir.typed_functions
        .iter()
        .filter(|function| {
            function.is_async
                && is_extern_c_abi_function(function)
                && !function.body.is_empty()
                && matches!(
                    function.return_type,
                    ast::Type::Int {
                        signed: true,
                        bits: 32
                    }
                )
        })
        .map(|function| NativeAsyncExport {
            name: native_link_symbol_for_function(function),
            mangled_symbol: native_link_symbol_for_function(function),
            params: function
                .params
                .iter()
                .map(|param| {
                    (
                        ffi_signature_type_to_c_type(&param.ty),
                        native_mangle_symbol(&param.name),
                    )
                })
                .collect(),
        })
        .collect()
}

fn build_sync_export(
    function: &hir::TypedFunction,
    repr_c_types: &BTreeMap<String, NativeFfiType>,
) -> Result<Option<NativeSyncExport>> {
    let mut needs_wrapper = false;
    let mut params = Vec::with_capacity(function.params.len());
    for param in &function.params {
        let ty = native_ffi_type_for_signature(&param.ty, repr_c_types);
        if !matches!(ty, NativeFfiType::Scalar { .. }) {
            needs_wrapper = true;
        }
        params.push(NativeExportParam {
            name: native_mangle_symbol(&param.name),
            ty,
        });
    }
    let return_type = match &function.return_type {
        ast::Type::Void => NativeExportReturn::Void,
        other => {
            let ty = native_ffi_type_for_signature(other, repr_c_types);
            if !matches!(ty, NativeFfiType::Scalar { .. }) {
                needs_wrapper = true;
            }
            NativeExportReturn::Type(ty)
        }
    };
    if !needs_wrapper {
        return Ok(None);
    }
    let public_symbol = native_link_symbol_for_function(function);
    Ok(Some(NativeSyncExport {
        public_symbol: public_symbol.clone(),
        impl_symbol: format!("{public_symbol}__fz_ffi_impl"),
        params,
        return_type,
    }))
}

fn collect_repr_c_types(fir: &fir::FirModule) -> Result<BTreeMap<String, NativeFfiType>> {
    let mut out = BTreeMap::new();
    for item in fir.struct_defs.values() {
        if !is_repr_c(item.repr.as_deref()) {
            continue;
        }
        let mut fields = Vec::with_capacity(item.fields.len());
        for field in &item.fields {
            ensure_repr_c_field_supported(&field.ty).ok_or_else(|| {
                anyhow!(
                    "repr(C) struct `{}` field `{}` uses unsupported layout type `{}`",
                    item.name,
                    field.name,
                    field.ty
                )
            })?;
            fields.push(NativeReprCField {
                name: field.name.clone(),
                c_type: ffi_signature_type_to_c_type(&field.ty),
            });
        }
        out.insert(
            item.name.clone(),
            NativeFfiType::ReprCStruct(NativeReprCStruct {
                name: item.name.clone(),
                fields,
            }),
        );
    }
    for item in fir.enum_defs.values() {
        if !is_repr_c(item.repr.as_deref()) {
            continue;
        }
        if item
            .variants
            .iter()
            .any(|variant| !variant.payload.is_empty() || !variant.named_payload.is_empty())
        {
            bail!(
                "repr(C) enum `{}` has payload variants; only C-style fieldless enums are supported",
                item.name
            );
        }
        out.insert(
            item.name.clone(),
            NativeFfiType::ReprCEnum(NativeReprCEnum {
                name: item.name.clone(),
                variants: item
                    .variants
                    .iter()
                    .enumerate()
                    .map(|(index, variant)| NativeReprCEnumVariant {
                        name: variant.name.clone(),
                        value: index as i32,
                    })
                    .collect(),
            }),
        );
    }
    Ok(out)
}

fn native_ffi_type_for_signature(
    ty: &ast::Type,
    repr_c_types: &BTreeMap<String, NativeFfiType>,
) -> NativeFfiType {
    match ty {
        ast::Type::Named { name, args } if args.is_empty() => repr_c_types
            .get(name)
            .cloned()
            .unwrap_or_else(|| NativeFfiType::Scalar {
                c_type: ffi_signature_type_to_c_type(ty),
            }),
        _ => NativeFfiType::Scalar {
            c_type: ffi_signature_type_to_c_type(ty),
        },
    }
}

fn ensure_repr_c_field_supported(ty: &ast::Type) -> Option<()> {
    match ty {
        ast::Type::Void
        | ast::Type::Bool
        | ast::Type::Char
        | ast::Type::ISize
        | ast::Type::USize
        | ast::Type::Int { .. }
        | ast::Type::Float { .. }
        | ast::Type::Ptr { .. } => Some(()),
        _ => None,
    }
}

fn is_repr_c(repr: Option<&str>) -> bool {
    repr.is_some_and(|repr| repr.to_ascii_lowercase().contains('c'))
}

pub(crate) fn collect_sync_repr_c_type_names(
    sync_exports: &[NativeSyncExport],
) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    for export in sync_exports {
        for param in &export.params {
            match &param.ty {
                NativeFfiType::ReprCStruct(layout) => {
                    names.insert(layout.name.clone());
                }
                NativeFfiType::ReprCEnum(layout) => {
                    names.insert(layout.name.clone());
                }
                NativeFfiType::Scalar { .. } => {}
            }
        }
        if let NativeExportReturn::Type(ty) = &export.return_type {
            match ty {
                NativeFfiType::ReprCStruct(layout) => {
                    names.insert(layout.name.clone());
                }
                NativeFfiType::ReprCEnum(layout) => {
                    names.insert(layout.name.clone());
                }
                NativeFfiType::Scalar { .. } => {}
            }
        }
    }
    names
}

pub(crate) fn ffi_signature_type_to_c_type(ty: &ast::Type) -> String {
    match ty {
        ast::Type::Ptr { mutable, to } => {
            if *mutable {
                format!("{}*", ffi_signature_type_to_c_type(to))
            } else {
                format!("const {}*", ffi_signature_type_to_c_type(to))
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

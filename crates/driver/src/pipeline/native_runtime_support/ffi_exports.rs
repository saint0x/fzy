use super::super::*;

#[derive(Debug, Clone)]
pub(crate) struct NativeAsyncExport {
    pub(crate) name: String,
    pub(crate) mangled_symbol: String,
    pub(crate) params: Vec<(String, String)>,
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

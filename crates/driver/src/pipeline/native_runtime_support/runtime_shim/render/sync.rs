use super::super::super::ffi_exports::{
    collect_sync_repr_c_type_names, NativeExportParam, NativeExportReturn, NativeFfiType,
    NativeReprCEnum, NativeReprCStruct, NativeSyncExport,
};
use super::*;

fn render_repr_c_type_defs(sync_exports: &[NativeSyncExport]) -> String {
    let type_names = collect_sync_repr_c_type_names(sync_exports);
    if type_names.is_empty() {
        return String::new();
    }
    let mut rendered = String::new();
    let mut seen = std::collections::BTreeSet::new();
    for export in sync_exports {
        for ty in export
            .params
            .iter()
            .map(|param| &param.ty)
            .chain(match &export.return_type {
                NativeExportReturn::Void => None.into_iter(),
                NativeExportReturn::Type(ty) => Some(ty).into_iter(),
            })
        {
            match ty {
                NativeFfiType::ReprCStruct(layout) if seen.insert(layout.name.clone()) => {
                    let _ = writeln!(&mut rendered, "typedef struct {} {{", layout.name);
                    for field in &layout.fields {
                        let _ = writeln!(&mut rendered, "  {} {};", field.c_type, field.name);
                    }
                    let _ = writeln!(&mut rendered, "}} {};\n", layout.name);
                }
                NativeFfiType::ReprCEnum(layout) if seen.insert(layout.name.clone()) => {
                    let _ = writeln!(&mut rendered, "typedef enum {} {{", layout.name);
                    for variant in &layout.variants {
                        let _ = writeln!(
                            &mut rendered,
                            "  {}_{} = {},",
                            layout.name, variant.name, variant.value
                        );
                    }
                    let _ = writeln!(&mut rendered, "}} {};\n", layout.name);
                }
                _ => {}
            }
        }
    }
    rendered
}

fn render_sync_export_helper_code(sync_exports: &[NativeSyncExport]) -> String {
    let mut out = String::new();
    let mut emitted_structs = std::collections::BTreeSet::new();
    let mut emitted_enums = std::collections::BTreeSet::new();
    for export in sync_exports {
        for ty in export
            .params
            .iter()
            .map(|param| &param.ty)
            .chain(match &export.return_type {
                NativeExportReturn::Void => None.into_iter(),
                NativeExportReturn::Type(ty) => Some(ty).into_iter(),
            })
        {
            match ty {
                NativeFfiType::ReprCStruct(layout)
                    if emitted_structs.insert(layout.name.clone()) =>
                {
                    render_struct_bridge_helpers(layout, &mut out);
                }
                NativeFfiType::ReprCEnum(layout) if emitted_enums.insert(layout.name.clone()) => {
                    render_enum_bridge_helpers(layout, &mut out);
                }
                _ => {}
            }
        }
    }
    out
}

fn render_struct_bridge_helpers(layout: &NativeReprCStruct, out: &mut String) {
    let _ = writeln!(
        out,
        "static uint64_t fz_encode_{}({} value) {{",
        layout.name, layout.name
    );
    let _ = writeln!(
        out,
        "  uint64_t handle = fz_native_agg_new(0, {});",
        layout.fields.len()
    );
    out.push_str("  if (handle == 0) {\n    return 0;\n  }\n");
    for (index, field) in layout.fields.iter().enumerate() {
        let _ = writeln!(
            out,
            "  (void)fz_native_agg_set_i64(handle, {}, (uint64_t)value.{});",
            index, field.name
        );
    }
    out.push_str("  return handle;\n}\n\n");

    let _ = writeln!(
        out,
        "static {} fz_decode_{}(uint64_t handle) {{",
        layout.name, layout.name
    );
    let _ = writeln!(out, "  {} value = {{0}};", layout.name);
    out.push_str("  if (handle == 0) {\n    return value;\n  }\n");
    for (index, field) in layout.fields.iter().enumerate() {
        let _ = writeln!(
            out,
            "  value.{} = ({})fz_native_agg_get_i64(handle, {});",
            field.name, field.c_type, index
        );
    }
    out.push_str("  return value;\n}\n\n");
}

fn render_enum_bridge_helpers(layout: &NativeReprCEnum, out: &mut String) {
    let _ = writeln!(
        out,
        "static uint64_t fz_encode_{}({} value) {{",
        layout.name, layout.name
    );
    out.push_str("  return fz_native_agg_new((int32_t)value, 0);\n}\n\n");
    let _ = writeln!(
        out,
        "static {} fz_decode_{}(uint64_t handle) {{",
        layout.name, layout.name
    );
    let _ = writeln!(
        out,
        "  return ({})fz_native_agg_tag(handle);\n}}\n",
        layout.name
    );
}

fn native_public_c_type(ty: &NativeFfiType) -> &str {
    match ty {
        NativeFfiType::Scalar { c_type } => c_type.as_str(),
        NativeFfiType::ReprCStruct(layout) => layout.name.as_str(),
        NativeFfiType::ReprCEnum(layout) => layout.name.as_str(),
    }
}

fn native_internal_c_type(ty: &NativeFfiType) -> &str {
    match ty {
        NativeFfiType::Scalar { c_type } => c_type.as_str(),
        NativeFfiType::ReprCStruct(_) | NativeFfiType::ReprCEnum(_) => "uint64_t",
    }
}

fn render_sync_export_signature_params(params: &[NativeExportParam]) -> String {
    if params.is_empty() {
        "void".to_string()
    } else {
        params
            .iter()
            .map(|param| format!("{} {}", native_public_c_type(&param.ty), param.name))
            .collect::<Vec<_>>()
            .join(", ")
    }
}

fn render_sync_export_impl_params(params: &[NativeExportParam]) -> String {
    if params.is_empty() {
        "void".to_string()
    } else {
        params
            .iter()
            .map(|param| format!("{} {}", native_internal_c_type(&param.ty), param.name))
            .collect::<Vec<_>>()
            .join(", ")
    }
}

pub(super) fn render_sync_export_shim_code(sync_exports: &[NativeSyncExport]) -> String {
    if sync_exports.is_empty() {
        return String::new();
    }

    let mut out = String::new();
    out.push_str(&render_repr_c_type_defs(sync_exports));
    out.push_str(&render_sync_export_helper_code(sync_exports));

    for export in sync_exports {
        let public_return = match &export.return_type {
            NativeExportReturn::Void => "void".to_string(),
            NativeExportReturn::Type(ty) => native_public_c_type(ty).to_string(),
        };
        let impl_return = match &export.return_type {
            NativeExportReturn::Void => "void".to_string(),
            NativeExportReturn::Type(ty) => native_internal_c_type(ty).to_string(),
        };
        let public_params = render_sync_export_signature_params(&export.params);
        let impl_params = render_sync_export_impl_params(&export.params);
        let _ = writeln!(
            &mut out,
            "extern {} {}({});",
            impl_return, export.impl_symbol, impl_params
        );
        let _ = writeln!(
            &mut out,
            "{} {}({}) {{",
            public_return, export.public_symbol, public_params
        );

        let mut call_args = Vec::with_capacity(export.params.len());
        let mut repr_c_param_names = Vec::new();
        for param in &export.params {
            match &param.ty {
                NativeFfiType::Scalar { .. } => {
                    call_args.push(param.name.clone());
                }
                NativeFfiType::ReprCStruct(layout) => {
                    let handle_name = format!("{}_handle", param.name);
                    let _ = writeln!(
                        &mut out,
                        "  uint64_t {} = fz_encode_{}({});",
                        handle_name, layout.name, param.name
                    );
                    call_args.push(handle_name.clone());
                    repr_c_param_names.push(handle_name);
                }
                NativeFfiType::ReprCEnum(layout) => {
                    let handle_name = format!("{}_handle", param.name);
                    let _ = writeln!(
                        &mut out,
                        "  uint64_t {} = fz_encode_{}({});",
                        handle_name, layout.name, param.name
                    );
                    call_args.push(handle_name.clone());
                    repr_c_param_names.push(handle_name);
                }
            }
        }

        let call_expr = if call_args.is_empty() {
            format!("{}()", export.impl_symbol)
        } else {
            format!("{}({})", export.impl_symbol, call_args.join(", "))
        };
        match &export.return_type {
            NativeExportReturn::Void => {
                let _ = writeln!(&mut out, "  {};", call_expr);
                for handle_name in repr_c_param_names {
                    let _ = writeln!(
                        &mut out,
                        "  if ({} != 0) {{ fz_native_agg_drop({}); }}",
                        handle_name, handle_name
                    );
                }
                out.push_str("}\n\n");
            }
            NativeExportReturn::Type(NativeFfiType::Scalar { .. }) => {
                let _ = writeln!(&mut out, "  {} result = {};", public_return, call_expr);
                for handle_name in repr_c_param_names {
                    let _ = writeln!(
                        &mut out,
                        "  if ({} != 0) {{ fz_native_agg_drop({}); }}",
                        handle_name, handle_name
                    );
                }
                out.push_str("  return result;\n}\n\n");
            }
            NativeExportReturn::Type(NativeFfiType::ReprCStruct(layout)) => {
                out.push_str("  uint64_t result_handle = ");
                out.push_str(&call_expr);
                out.push_str(";\n");
                for handle_name in &repr_c_param_names {
                    let _ = writeln!(
                        &mut out,
                        "  if ({} != 0 && {} != result_handle) {{ fz_native_agg_drop({}); }}",
                        handle_name, handle_name, handle_name
                    );
                }
                let _ = writeln!(
                    &mut out,
                    "  {} result = fz_decode_{}(result_handle);",
                    layout.name, layout.name
                );
                out.push_str(
                    "  if (result_handle != 0) { fz_native_agg_drop(result_handle); }\n  return result;\n}\n\n",
                );
            }
            NativeExportReturn::Type(NativeFfiType::ReprCEnum(layout)) => {
                out.push_str("  uint64_t result_handle = ");
                out.push_str(&call_expr);
                out.push_str(";\n");
                for handle_name in &repr_c_param_names {
                    let _ = writeln!(
                        &mut out,
                        "  if ({} != 0 && {} != result_handle) {{ fz_native_agg_drop({}); }}",
                        handle_name, handle_name, handle_name
                    );
                }
                let _ = writeln!(
                    &mut out,
                    "  {} result = fz_decode_{}(result_handle);",
                    layout.name, layout.name
                );
                out.push_str(
                    "  if (result_handle != 0) { fz_native_agg_drop(result_handle); }\n  return result;\n}\n\n",
                );
            }
        }
    }

    out
}

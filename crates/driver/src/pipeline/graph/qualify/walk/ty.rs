use super::*;

pub(crate) fn qualify_pattern(
    pattern: &mut ast::Pattern,
    namespace: &str,
    local_types: &HashSet<String>,
    module_aliases: &HashMap<String, String>,
) {
    match pattern {
        ast::Pattern::Variant { enum_name, .. } => {
            *enum_name = super::super::text::qualify_type_name(
                enum_name,
                namespace,
                local_types,
                module_aliases,
            );
        }
        ast::Pattern::Tuple(items) => {
            for item in items {
                qualify_pattern(item, namespace, local_types, module_aliases);
            }
        }
        ast::Pattern::Or(patterns) => {
            for pattern in patterns {
                qualify_pattern(pattern, namespace, local_types, module_aliases);
            }
        }
        ast::Pattern::Wildcard
        | ast::Pattern::Ident(_)
        | ast::Pattern::Int(_)
        | ast::Pattern::Bool(_)
        | ast::Pattern::Struct { .. } => {}
    }
}

pub(crate) fn qualify_generic_params(
    params: &mut [ast::GenericParam],
    namespace: &str,
    local_types: &HashSet<String>,
    module_aliases: &HashMap<String, String>,
) {
    for param in params {
        for bound in &mut param.bounds {
            *bound = super::super::text::qualify_type_name(
                bound, namespace, local_types, module_aliases,
            );
        }
    }
}

pub(crate) fn qualify_type(
    ty: &mut ast::Type,
    namespace: &str,
    local_types: &HashSet<String>,
    module_aliases: &HashMap<String, String>,
) {
    match ty {
        ast::Type::Ptr { to, .. } | ast::Type::Ref { to, .. } => {
            qualify_type(to, namespace, local_types, module_aliases)
        }
        ast::Type::Slice(inner)
        | ast::Type::Set(inner)
        | ast::Type::Deque(inner)
        | ast::Type::Ring(inner)
        | ast::Type::Option(inner)
        | ast::Type::Vec(inner)
        | ast::Type::Future(inner) => qualify_type(inner, namespace, local_types, module_aliases),
        ast::Type::Array { elem, .. } => qualify_type(elem, namespace, local_types, module_aliases),
        ast::Type::Result { ok, err } => {
            qualify_type(ok, namespace, local_types, module_aliases);
            qualify_type(err, namespace, local_types, module_aliases);
        }
        ast::Type::Map { key, value } => {
            qualify_type(key, namespace, local_types, module_aliases);
            qualify_type(value, namespace, local_types, module_aliases);
        }
        ast::Type::Function { params, ret } => {
            for param in params {
                qualify_type(param, namespace, local_types, module_aliases);
            }
            qualify_type(ret, namespace, local_types, module_aliases);
        }
        ast::Type::Tuple(items) => {
            for item in items {
                qualify_type(item, namespace, local_types, module_aliases);
            }
        }
        ast::Type::Named { name, args } => {
            *name = super::super::text::qualify_type_name(name, namespace, local_types, module_aliases);
            for arg in args {
                qualify_type(arg, namespace, local_types, module_aliases);
            }
        }
        ast::Type::Never
        | ast::Type::Void
        | ast::Type::Bool
        | ast::Type::ISize
        | ast::Type::USize
        | ast::Type::Int { .. }
        | ast::Type::BigInt
        | ast::Type::BigUint
        | ast::Type::Float { .. }
        | ast::Type::Decimal128
        | ast::Type::Char
        | ast::Type::Str
        | ast::Type::Bytes
        | ast::Type::Uuid
        | ast::Type::Path
        | ast::Type::PathBuf
        | ast::Type::Url
        | ast::Type::SocketAddr
        | ast::Type::Duration
        | ast::Type::Instant
        | ast::Type::Decimal
        | ast::Type::DateTimeTz
        | ast::Type::ExitStatus
        | ast::Type::DynTrait(_)
        | ast::Type::TypeVar(_)
        | ast::Type::SimdVector(_)
        | ast::Type::SimdMask(_) => {}
    }
}

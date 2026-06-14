use super::*;

pub(crate) fn pattern_to_expr(
    scrutinee_name: &str,
    pattern: &ast::Pattern,
    variant_tags: &HashMap<String, i32>,
) -> ast::Expr {
    match pattern {
        ast::Pattern::Wildcard | ast::Pattern::Ident(_) => ast::Expr::Bool(true),
        ast::Pattern::Int(value) => ast::Expr::Binary {
            op: ast::BinaryOp::Eq,
            left: Box::new(ast::Expr::Ident(scrutinee_name.to_string())),
            right: Box::new(ast::Expr::Int(*value)),
        },
        ast::Pattern::Bool(value) => ast::Expr::Binary {
            op: ast::BinaryOp::Eq,
            left: Box::new(ast::Expr::Ident(scrutinee_name.to_string())),
            right: Box::new(ast::Expr::Bool(*value)),
        },
        ast::Pattern::Variant {
            enum_name, variant, ..
        } => {
            let key = format!("{enum_name}::{variant}");
            ast::Expr::Binary {
                op: ast::BinaryOp::Eq,
                left: Box::new(ast::Expr::Ident(scrutinee_name.to_string())),
                right: Box::new(ast::Expr::Int(
                    super::variant_tag_for_key(&key, variant_tags) as i128
                )),
            }
        }
        ast::Pattern::Struct { .. } => ast::Expr::Bool(true),
        ast::Pattern::Tuple(_) => ast::Expr::Bool(true),
        ast::Pattern::Or(patterns) => {
            let mut iter = patterns.iter();
            let first = iter
                .next()
                .map(|pattern| pattern_to_expr(scrutinee_name, pattern, variant_tags))
                .unwrap_or(ast::Expr::Bool(true));
            iter.fold(first, |acc, pattern| ast::Expr::Binary {
                op: ast::BinaryOp::Or,
                left: Box::new(acc),
                right: Box::new(pattern_to_expr(scrutinee_name, pattern, variant_tags)),
            })
        }
    }
}

pub(crate) fn pattern_is_catchall(pattern: &ast::Pattern) -> bool {
    matches!(pattern, ast::Pattern::Wildcard | ast::Pattern::Ident(_))
}

pub(crate) fn pattern_switch_values(
    pattern: &ast::Pattern,
    variant_tags: &HashMap<String, i32>,
) -> Option<Vec<i32>> {
    match pattern {
        ast::Pattern::Int(value) => i32::try_from(*value).ok().map(|v| vec![v]),
        ast::Pattern::Bool(value) => Some(vec![if *value { 1 } else { 0 }]),
        ast::Pattern::Variant {
            enum_name, variant, ..
        } => {
            let key = format!("{enum_name}::{variant}");
            Some(vec![super::variant_tag_for_key(&key, variant_tags)])
        }
        ast::Pattern::Or(patterns) => {
            let mut out = Vec::new();
            for pattern in patterns {
                let mut values = pattern_switch_values(pattern, variant_tags)?;
                out.append(&mut values);
            }
            Some(out)
        }
        ast::Pattern::Wildcard
        | ast::Pattern::Ident(_)
        | ast::Pattern::Tuple(_)
        | ast::Pattern::Struct { .. } => None,
    }
}

pub(crate) fn pattern_has_variant_payload_bindings(pattern: &ast::Pattern) -> bool {
    match pattern {
        ast::Pattern::Variant {
            bindings,
            named_bindings,
            ..
        } => !bindings.is_empty() || !named_bindings.is_empty(),
        ast::Pattern::Or(patterns) => patterns.iter().any(pattern_has_variant_payload_bindings),
        ast::Pattern::Wildcard
        | ast::Pattern::Int(_)
        | ast::Pattern::Bool(_)
        | ast::Pattern::Tuple(_)
        | ast::Pattern::Struct { .. }
        | ast::Pattern::Ident(_) => false,
    }
}

pub(crate) fn pattern_has_struct_field_bindings(pattern: &ast::Pattern) -> bool {
    match pattern {
        ast::Pattern::Struct { fields, .. } => fields.iter().any(|(_, binding)| binding != "_"),
        ast::Pattern::Or(patterns) => patterns.iter().any(pattern_has_struct_field_bindings),
        ast::Pattern::Wildcard
        | ast::Pattern::Int(_)
        | ast::Pattern::Bool(_)
        | ast::Pattern::Tuple(_)
        | ast::Pattern::Ident(_)
        | ast::Pattern::Variant { .. } => false,
    }
}

pub(crate) fn pattern_has_tuple_bindings(items: &[ast::Pattern]) -> bool {
    items.iter().any(|item| match item {
        ast::Pattern::Wildcard => false,
        ast::Pattern::Int(_) | ast::Pattern::Bool(_) | ast::Pattern::Ident(_) => true,
        ast::Pattern::Tuple(nested) => pattern_has_tuple_bindings(nested),
        ast::Pattern::Struct { fields, .. } => fields.iter().any(|(_, binding)| binding != "_"),
        ast::Pattern::Variant {
            bindings,
            named_bindings,
            ..
        } => !bindings.is_empty() || !named_bindings.is_empty(),
        ast::Pattern::Or(patterns) => {
            patterns.iter().any(pattern_has_variant_payload_bindings)
                || patterns.iter().any(pattern_has_struct_field_bindings)
                || patterns.iter().any(|pattern| match pattern {
                    ast::Pattern::Tuple(nested) => pattern_has_tuple_bindings(nested),
                    ast::Pattern::Ident(_) | ast::Pattern::Int(_) | ast::Pattern::Bool(_) => true,
                    _ => false,
                })
        }
    })
}

pub(crate) fn pattern_matches_resolved_scrutinee(
    pattern: &ast::Pattern,
    scrutinee: &ast::Expr,
    variant_tags: &HashMap<String, i32>,
) -> bool {
    match pattern {
        ast::Pattern::Wildcard | ast::Pattern::Ident(_) => true,
        ast::Pattern::Int(expected) => {
            matches!(scrutinee, ast::Expr::Int(actual) if actual == expected)
        }
        ast::Pattern::Bool(expected) => {
            matches!(scrutinee, ast::Expr::Bool(actual) if actual == expected)
        }
        ast::Pattern::Variant {
            enum_name, variant, ..
        } => {
            if let ast::Expr::EnumInit {
                enum_name: value_enum,
                variant: value_variant,
                ..
            } = scrutinee
            {
                value_enum == enum_name && value_variant == variant
            } else if let ast::Expr::Int(value) = scrutinee {
                i32::try_from(*value).ok().is_some_and(|actual| {
                    let key = format!("{enum_name}::{variant}");
                    actual == super::variant_tag_for_key(&key, variant_tags)
                })
            } else {
                false
            }
        }
        ast::Pattern::Struct { name, .. } => matches!(
            scrutinee,
            ast::Expr::StructInit {
                name: value_name,
                ..
            } if value_name == name
        ),
        ast::Pattern::Tuple(items) => match scrutinee {
            ast::Expr::Tuple(values) => {
                items.len() == values.len()
                    && items.iter().zip(values.iter()).all(|(pattern, value)| {
                        pattern_matches_resolved_scrutinee(pattern, value, variant_tags)
                    })
            }
            _ => false,
        },
        ast::Pattern::Or(patterns) => patterns
            .iter()
            .any(|pattern| pattern_matches_resolved_scrutinee(pattern, scrutinee, variant_tags)),
    }
}

use super::clif::variant_tag_for_key;
use super::*;

#[path = "pattern/breaks.rs"]
mod breaks;
#[path = "pattern/matching.rs"]
mod matching;
#[path = "pattern/resolve.rs"]
mod resolve;

pub(crate) use self::breaks::body_contains_break_at_depth;
pub(crate) use self::matching::{
    pattern_has_struct_field_bindings, pattern_has_tuple_bindings,
    pattern_has_variant_payload_bindings, pattern_is_catchall, pattern_matches_resolved_scrutinee,
    pattern_switch_values, pattern_to_expr,
};
pub(crate) use self::resolve::resolve_pattern_source_expr;

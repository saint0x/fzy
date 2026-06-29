use super::clif::{ast_signature_type_to_clif_type, pointer_sized_clif_type};
use super::native_runtime_tables::native_runtime_imports;
use super::*;

#[path = "native_backend_support/diag.rs"]
mod diag;
#[path = "native_backend_support/imports.rs"]
mod imports;
#[path = "native_backend_support/scan.rs"]
mod scan;

pub(super) use self::diag::*;
pub(super) use self::imports::*;
pub(super) use self::scan::*;

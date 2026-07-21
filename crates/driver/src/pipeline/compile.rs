use super::*;

#[path = "compile/build.rs"]
mod build;
#[path = "compile/check.rs"]
mod check;
#[path = "compile/parse.rs"]
mod parse;

pub use self::build::{
    compile_file, compile_file_incremental_with_backend, compile_file_with_backend,
    compile_library_incremental_with_backend, compile_library_with_backend,
};
pub use self::check::{check_file, emit_ir, verify_file, verify_file_with_root_source};
pub(crate) use self::check::{
    is_supported_source_file, kernel_ir_diagnostics, normalize_diagnostics_for_path,
};
pub use self::parse::{lower_fir_cached, parse_program, parse_program_with_root_source};
pub(crate) use self::parse::{
    lower_fir_cached_shared, lower_fir_cached_shared_telemetry, lower_fir_cached_with_metadata,
    parse_program_shared, parse_program_shared_with_root_source_telemetry,
    parse_program_with_metadata,
};

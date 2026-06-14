use super::*;
use std::path::Path;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use diagnostics::Severity;

use super::native_runtime_support::{render_native_runtime_shim, NativeAsyncExport};
use super::native_runtime_tables::native_runtime_contract_for_callee;

#[path = "tests/part_01.rs"]
mod part_01;
#[path = "tests/part_02.rs"]
mod part_02;
#[path = "tests/part_03.rs"]
mod part_03;
#[path = "tests/part_04.rs"]
mod part_04;
#[path = "tests/part_05.rs"]
mod part_05;
#[path = "tests/part_06.rs"]
mod part_06;
#[path = "tests/part_07.rs"]
mod part_07;
#[path = "tests/part_08.rs"]
mod part_08;
#[path = "tests/part_09.rs"]
mod part_09;
#[path = "tests/part_10.rs"]
mod part_10;
#[path = "tests/part_11.rs"]
mod part_11;
#[path = "tests/part_12.rs"]
mod part_12;
#[path = "tests/part_13.rs"]
mod part_13;
#[path = "tests/part_14.rs"]
mod part_14;
#[path = "tests/part_15.rs"]
mod part_15;
#[path = "tests/part_16.rs"]
mod part_16;

use self::part_01::*;

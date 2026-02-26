use std::hint::black_box;
use core::Capability as FxCapability;
use stdlib::abi::AbiPairI32;
use stdlib::bytes::ByteBuf;
use stdlib::duration::DurationSpan;
use stdlib::error::ErrorCode;
use stdlib::resultx::{classify as resultx_classify, ErrorClass};
use stdlib::task::RetryPolicy;
use stdlib::text;

const ITERATIONS: i32 = 8_000_000;

#[inline(always)]
fn class_to_score(class: ErrorClass) -> i32 {
    match class {
        ErrorClass::Transport => 11,
        ErrorClass::Parse => 17,
        ErrorClass::Timeout => 23,
        ErrorClass::Policy => 31,
        ErrorClass::Internal => 43,
    }
}

fn resultx_workload() -> i32 {
    let codes = [
        ErrorCode::InvalidInput,
        ErrorCode::NotFound,
        ErrorCode::Conflict,
        ErrorCode::Timeout,
        ErrorCode::Io,
        ErrorCode::Internal,
        ErrorCode::InvalidInput,
    ];

    let mut i = 0;
    let mut idx = 0usize;
    let mut acc = 0i32;

    while i < ITERATIONS {
        // 4x unroll to reduce loop/index overhead and keep branch pattern stable.
        let c0 = black_box(codes[idx]);
        idx += 1;
        if idx == codes.len() {
            idx = 0;
        }
        acc = (acc + class_to_score(resultx_classify(c0))) % 251;

        let c1 = black_box(codes[idx]);
        idx += 1;
        if idx == codes.len() {
            idx = 0;
        }
        acc = (acc + class_to_score(resultx_classify(c1))) % 251;

        let c2 = black_box(codes[idx]);
        idx += 1;
        if idx == codes.len() {
            idx = 0;
        }
        acc = (acc + class_to_score(resultx_classify(c2))) % 251;

        let c3 = black_box(codes[idx]);
        idx += 1;
        if idx == codes.len() {
            idx = 0;
        }
        acc = (acc + class_to_score(resultx_classify(c3))) % 251;

        i += 4;
    }

    acc
}

fn text_workload() -> i32 {
    let mut i = 0;
    let mut acc = 0i32;
    while i < ITERATIONS {
        let raw = black_box("  alpha,beta,gamma  ");
        let trimmed = text::trim(raw);
        let replaced = text::replace(&trimmed, ",", "|");
        if text::contains(&replaced, "beta") {
            acc = (acc + 11) % 251;
        }
        if text::starts_with(&replaced, "alpha") {
            acc = (acc + 17) % 251;
        }
        if text::ends_with(&replaced, "gamma") {
            acc = (acc + 23) % 251;
        }
        acc = (acc + (trimmed.len() as i32 % 97)) % 251;
        i += 1;
    }
    acc
}

fn capability_workload() -> i32 {
    let values = ["time", "rng", "fs", "http", "proc", "mem", "thread", "bad"];
    let mut i = 0;
    let mut idx = 0usize;
    let mut acc = 0i32;
    while i < ITERATIONS {
        let name = black_box(values[idx]);
        idx += 1;
        if idx == values.len() {
            idx = 0;
        }
        let score = match FxCapability::parse(name) {
            Some(FxCapability::Time) => 3,
            Some(FxCapability::Random) => 5,
            Some(FxCapability::FileSystem) => 7,
            Some(FxCapability::Http) => 11,
            Some(FxCapability::Process) => 13,
            Some(FxCapability::Memory) => 17,
            Some(FxCapability::Thread) => 19,
            None => 23,
        };
        acc = (acc + score) % 251;
        i += 1;
    }
    acc
}

fn task_retry_workload() -> i32 {
    let policy = RetryPolicy {
        max_attempts: 7,
        initial_delay_ms: 3,
        max_delay_ms: 89,
        backoff_factor: 2,
    };
    let mut i = 0;
    let mut acc = 0i32;
    let mut attempt = 1usize;
    while i < ITERATIONS {
        let delay = policy.delay_for_attempt(attempt);
        acc = (acc + (delay as i32 % 251)) % 251;
        attempt += 1;
        if attempt > policy.max_attempts {
            attempt = 1;
        }
        i += 1;
    }
    acc
}

fn arithmetic_workload() -> i32 {
    let mut i = 0;
    let mut acc = 7i32;
    while i < ITERATIONS {
        // Represents a scratch, core-style hot loop kernel.
        let v = (i * 13 + acc * 7) % 1_000_003;
        let w = (v ^ 0x5a5a5a) & 0x00ff_ffff;
        acc = (acc + (w % 251)) % 251;
        i += 1;
    }
    acc
}

fn bytes_workload() -> i32 {
    let buf = ByteBuf::from_vec(vec![1, 2, 3, 4, 5, 6, 7, 8]);
    let mut i = 0;
    let mut acc = 0i32;
    let mut off = 0usize;
    while i < ITERATIONS {
        let v = buf.read_u32_le(off).expect("u32 read must succeed");
        acc = (acc + (v as i32 % 251)) % 251;
        off += 1;
        if off > 4 {
            off = 0;
        }
        i += 1;
    }
    acc
}

fn duration_workload() -> i32 {
    let a = DurationSpan::from_millis(3);
    let b = DurationSpan::from_millis(17);
    let mut i = 0;
    let mut acc = 0i32;
    while i < ITERATIONS {
        let c = a.checked_add(b).expect("add");
        let d = c.checked_sub(a).expect("sub");
        acc = (acc + (d.as_millis() as i32 % 251)) % 251;
        i += 1;
    }
    acc
}

fn abi_pair_workload() -> i32 {
    let mut i = 0;
    let mut acc = 0i32;
    while i < ITERATIONS {
        let pair = AbiPairI32 {
            left: i,
            right: acc,
        };
        acc = (acc + ((pair.left * 3 + pair.right * 5) % 251)) % 251;
        i += 1;
    }
    acc
}

fn c_interop_contract_workload() -> i32 {
    let ownership = ["owned", "borrowed", "out", "inout"];
    let nullability = ["non_null", "nullable"];
    let mutability_modes = ["const", "mut"];
    let panic_boundary = ["error", "abort"];

    let mut i = 0;
    let mut oi = 0usize;
    let mut ni = 0usize;
    let mut mi = 0usize;
    let mut pi = 0usize;
    let mut acc = 0i32;

    while i < ITERATIONS {
        let owner = black_box(ownership[oi]);
        let null = black_box(nullability[ni]);
        let mutability = black_box(mutability_modes[mi]);
        let panic = black_box(panic_boundary[pi]);

        let mut score = match owner {
            "owned" => 11,
            "borrowed" => 7,
            "out" => 13,
            _ => 17,
        };
        score += if null == "nullable" { 5 } else { 3 };
        score += if mutability == "mut" { 19 } else { 2 };
        score += if panic == "abort" { 23 } else { 29 };
        if owner == "owned" && panic == "abort" {
            score += 31;
        }
        if owner == "borrowed" && null == "non_null" {
            score += 37;
        }
        if owner == "inout" && mutability == "mut" {
            score += 41;
        }
        acc = (acc + score) % 251;

        oi += 1;
        if oi == ownership.len() {
            oi = 0;
        }
        ni += 1;
        if ni == nullability.len() {
            ni = 0;
        }
        mi += 1;
        if mi == mutability_modes.len() {
            mi = 0;
        }
        pi += 1;
        if pi == panic_boundary.len() {
            pi = 0;
        }
        i += 1;
    }

    acc
}

fn main() {
    let mode = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "resultx".to_string());
    let checksum = match mode.as_str() {
        "resultx" => resultx_workload(),
        "text" => text_workload(),
        "capability" => capability_workload(),
        "task_retry" => task_retry_workload(),
        "arithmetic" => arithmetic_workload(),
        "bytes" => bytes_workload(),
        "duration" => duration_workload(),
        "abi_pair" => abi_pair_workload(),
        "c_interop_contract" => c_interop_contract_workload(),
        other => {
            eprintln!(
                "unknown mode `{other}`; expected one of: resultx,text,capability,task_retry,arithmetic,bytes,duration,abi_pair,c_interop_contract"
            );
            std::process::exit(2);
        }
    };
    println!("checksum={checksum}");
}

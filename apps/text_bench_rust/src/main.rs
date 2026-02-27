use std::hint::black_box;

const ITERATIONS: i32 = 8_000_000;

#[derive(Clone, Copy)]
enum ErrorCode {
    InvalidInput,
    NotFound,
    Conflict,
    Timeout,
    Io,
    Internal,
}

#[derive(Clone, Copy)]
enum ErrorClass {
    Transport,
    Parse,
    Timeout,
    Policy,
    Internal,
}

#[derive(Clone, Copy)]
struct Pair {
    left: i32,
    right: i32,
}

#[inline(always)]
fn classify(code: ErrorCode) -> ErrorClass {
    match code {
        ErrorCode::Io => ErrorClass::Transport,
        ErrorCode::InvalidInput => ErrorClass::Parse,
        ErrorCode::Timeout => ErrorClass::Timeout,
        ErrorCode::Conflict => ErrorClass::Policy,
        ErrorCode::NotFound | ErrorCode::Internal => ErrorClass::Internal,
    }
}

#[inline(always)]
fn class_score(class: ErrorClass) -> i32 {
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
        let c0 = black_box(codes[idx]);
        idx += 1;
        if idx == codes.len() {
            idx = 0;
        }
        acc = (acc + class_score(classify(c0))) % 251;

        let c1 = black_box(codes[idx]);
        idx += 1;
        if idx == codes.len() {
            idx = 0;
        }
        acc = (acc + class_score(classify(c1))) % 251;

        let c2 = black_box(codes[idx]);
        idx += 1;
        if idx == codes.len() {
            idx = 0;
        }
        acc = (acc + class_score(classify(c2))) % 251;

        let c3 = black_box(codes[idx]);
        idx += 1;
        if idx == codes.len() {
            idx = 0;
        }
        acc = (acc + class_score(classify(c3))) % 251;

        i += 4;
    }

    acc
}

#[inline(always)]
fn core_trim(input: &str) -> &str {
    input.trim()
}

#[inline(always)]
fn core_replace(input: &str) -> String {
    input.replace(',', "|")
}

#[inline(always)]
fn core_contains(input: &str, part: &str) -> i32 {
    i32::from(input.contains(part))
}

#[inline(always)]
fn core_starts_with(input: &str, part: &str) -> i32 {
    i32::from(input.starts_with(part))
}

#[inline(always)]
fn core_ends_with(input: &str, part: &str) -> i32 {
    i32::from(input.ends_with(part))
}

#[inline(always)]
fn core_len(input: &str) -> i32 {
    input.len() as i32
}

fn text_workload() -> i32 {
    let mut i = 0;
    let mut acc = 0i32;

    while i < ITERATIONS {
        let raw = black_box("  alpha,beta,gamma  ");
        let trimmed = core_trim(raw);
        let replaced = core_replace(trimmed);

        if core_contains(&replaced, "beta") == 1 {
            acc = (acc + 11) % 251;
        }
        if core_starts_with(&replaced, "alpha") == 1 {
            acc = (acc + 17) % 251;
        }
        if core_ends_with(&replaced, "gamma") == 1 {
            acc = (acc + 23) % 251;
        }

        acc = (acc + (core_len(trimmed) % 97)) % 251;
        i += 1;
    }

    acc
}

#[inline(always)]
fn parse_capability(name: &str) -> i32 {
    match name {
        "time" => 3,
        "rng" => 5,
        "fs" => 7,
        "http" => 11,
        "proc" => 13,
        "mem" => 17,
        "thread" => 19,
        _ => 23,
    }
}

fn capability_workload() -> i32 {
    let names = ["time", "rng", "fs", "http", "proc", "mem", "thread", "bad"];
    let mut i = 0;
    let mut idx = 0usize;
    let mut acc = 0i32;

    while i < ITERATIONS {
        let name = black_box(names[idx]);
        idx += 1;
        if idx == names.len() {
            idx = 0;
        }
        acc = (acc + parse_capability(name)) % 251;
        i += 1;
    }

    acc
}

#[inline(always)]
fn delay_for_attempt(attempt: i32, initial: i32, max_delay: i32, factor: i32) -> i32 {
    let mut delay = initial;
    let mut i = 1;
    while i < attempt {
        delay *= factor;
        if delay > max_delay {
            delay = max_delay;
        }
        i += 1;
    }
    delay
}

fn task_retry_workload() -> i32 {
    let max_attempts = 7;
    let mut i = 0;
    let mut attempt = 1;
    let mut acc = 0i32;

    while i < ITERATIONS {
        let delay = delay_for_attempt(attempt, 3, 89, 2);
        acc = (acc + (delay % 251)) % 251;
        attempt += 1;
        if attempt > max_attempts {
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
        let v = (i * 13 + acc * 7) % 1_000_003;
        let w = (v ^ 5_921_370) & 16_777_215;
        acc = (acc + (w % 251)) % 251;
        i += 1;
    }

    acc
}

#[inline(always)]
fn read_u32_le(b0: i32, b1: i32, b2: i32, b3: i32) -> i32 {
    b0 + (b1 << 8) + (b2 << 16) + (b3 << 24)
}

fn bytes_workload() -> i32 {
    let bytes = [1, 2, 3, 4, 5, 6, 7, 8];
    let mut i = 0;
    let mut off = 0usize;
    let mut acc = 0i32;

    while i < ITERATIONS {
        let v = read_u32_le(bytes[off], bytes[off + 1], bytes[off + 2], bytes[off + 3]);
        acc = (acc + (v % 251)) % 251;
        off += 1;
        if off > 4 {
            off = 0;
        }
        i += 1;
    }

    acc
}

fn duration_workload() -> i32 {
    let a = 3;
    let b = 17;
    let mut i = 0;
    let mut acc = 0i32;

    while i < ITERATIONS {
        let c = a + b;
        let d = c - a;
        acc = (acc + (d % 251)) % 251;
        i += 1;
    }

    acc
}

fn abi_pair_workload() -> i32 {
    let mut i = 0;
    let mut acc = 0i32;

    while i < ITERATIONS {
        let pair = Pair {
            left: i,
            right: acc,
        };
        acc = (acc + ((pair.left * 3 + pair.right * 5) % 251)) % 251;
        i += 1;
    }

    acc
}

#[inline(always)]
fn owner_score(owner: &str) -> i32 {
    if owner == "owned" {
        return 11;
    }
    if owner == "borrowed" {
        return 7;
    }
    if owner == "out" {
        return 13;
    }
    17
}

fn c_interop_contract_workload() -> i32 {
    let ownership = ["owned", "borrowed", "out", "inout"];
    let nullability = ["non_null", "nullable"];
    let mutability = ["const", "mut"];
    let panic_boundary = ["error", "abort"];

    let mut i = 0;
    let mut oi = 0usize;
    let mut ni = 0usize;
    let mut mi = 0usize;
    let mut pi = 0usize;
    let mut acc = 0i32;

    while i < ITERATIONS {
        let owner = ownership[oi];
        let null = nullability[ni];
        let mutable_mode = mutability[mi];
        let panic = panic_boundary[pi];

        let mut score = owner_score(owner);
        score += if null == "nullable" { 5 } else { 3 };
        score += if mutable_mode == "mut" { 19 } else { 2 };
        score += if panic == "abort" { 23 } else { 29 };

        if owner == "owned" && panic == "abort" {
            score += 31;
        }
        if owner == "borrowed" && null == "non_null" {
            score += 37;
        }
        if owner == "inout" && mutable_mode == "mut" {
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
        if mi == mutability.len() {
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

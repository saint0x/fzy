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

#[inline(always)]
fn parse_method_score(name: &str) -> i32 {
    match name {
        "GET" => 11,
        "POST" => 13,
        "PUT" => 17,
        "DELETE" => 19,
        "PATCH" => 23,
        "HEAD" => 29,
        _ => 31,
    }
}

#[inline(always)]
fn status_score(status: i32) -> i32 {
    if (100..200).contains(&status) {
        return 7;
    }
    if (200..300).contains(&status) {
        return 11;
    }
    if (300..400).contains(&status) {
        return 17;
    }
    if (400..500).contains(&status) {
        return 23;
    }
    if (500..600).contains(&status) {
        return 29;
    }
    31
}

#[inline(always)]
fn route_score(method: &str, path: &str, query_len: i32, body_bytes: i32, timeout_ms: i32, max_body: i32) -> i32 {
    let mut safe_body = body_bytes;
    if safe_body < 0 {
        safe_body = 0;
    }
    if safe_body > max_body {
        safe_body = max_body;
    }
    let base = parse_method_score(method) * 131 + (path.len() as i32 * 17);
    (base + query_len * 7 + (safe_body % 251) + (timeout_ms % 97)) % 251
}

#[inline(always)]
fn http_transport_score(connection_mode: i32, requests_on_conn: i32) -> i32 {
    let handshake = if connection_mode == 1 { 37 } else { 19 };
    let teardown = if connection_mode == 1 { 17 } else { 9 };
    (handshake + teardown + (requests_on_conn % 13)) % 251
}

#[inline(always)]
fn http_request_score(method: &str, path: &str, status: i32, query_len: i32, body_bytes: i32) -> i32 {
    let route = route_score(method, path, query_len, body_bytes, 2500, 1_048_576);
    let class = status_score(status);
    (route + class) % 251
}

fn http_oneoff_workload() -> i32 {
    let methods = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"];
    let paths = ["/", "/v1/users", "/v1/orders", "/healthz"];
    let statuses = [200, 201, 204, 301, 404, 503];

    let mut i = 0;
    let mut mi = 0usize;
    let mut pi = 0usize;
    let mut si = 0usize;
    let mut acc = 0i32;

    while i < ITERATIONS {
        let method = methods[mi];
        let path = paths[pi];
        let status = statuses[si];
        let query_len = (i % 23) + 3;
        let body_bytes = (i * 7) % 2_000_000;

        let req = http_request_score(method, path, status, query_len, body_bytes);
        let transport = http_transport_score(1, 1);
        acc = (acc + req + transport) % 251;

        mi += 1;
        if mi == methods.len() {
            mi = 0;
        }
        pi += 1;
        if pi == paths.len() {
            pi = 0;
        }
        si += 1;
        if si == statuses.len() {
            si = 0;
        }
        i += 1;
    }

    acc
}

fn http_persistent_workload() -> i32 {
    let methods = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"];
    let paths = ["/", "/v1/users", "/v1/orders", "/healthz"];
    let statuses = [200, 201, 204, 301, 404, 503];

    let mut i = 0;
    let mut mi = 0usize;
    let mut pi = 0usize;
    let mut si = 0usize;
    let mut acc = 0i32;
    let mut left_on_conn = 0i32;

    while i < ITERATIONS {
        if left_on_conn == 0 {
            let conn_quota = (i % 8) + 1;
            left_on_conn = conn_quota;
            acc = (acc + http_transport_score(2, conn_quota)) % 251;
        }

        let method = methods[mi];
        let path = paths[pi];
        let status = statuses[si];
        let query_len = (i % 23) + 3;
        let body_bytes = (i * 7) % 2_000_000;

        let req = http_request_score(method, path, status, query_len, body_bytes);
        acc = (acc + req) % 251;

        left_on_conn -= 1;
        if left_on_conn == 0 {
            acc = (acc + 5) % 251;
        }

        mi += 1;
        if mi == methods.len() {
            mi = 0;
        }
        pi += 1;
        if pi == paths.len() {
            pi = 0;
        }
        si += 1;
        if si == statuses.len() {
            si = 0;
        }
        i += 1;
    }

    acc
}

#[inline(always)]
fn socket_kind_score(name: &str) -> i32 {
    if name == "stream" {
        return 11;
    }
    if name == "datagram" {
        return 17;
    }
    23
}

#[inline(always)]
fn ip_class_score(host: &str) -> i32 {
    if host.contains("::") {
        return 29;
    }
    if host.contains('.') {
        return 19;
    }
    if host == "localhost" {
        return 13;
    }
    31
}

#[inline(always)]
fn poll_signal_score(readable: i32, writable: i32, acceptable: i32, closed: i32) -> i32 {
    if closed == 1 {
        return 23;
    }
    if readable == 1 {
        return 11;
    }
    if writable == 1 {
        return 13;
    }
    if acceptable == 1 {
        return 17;
    }
    5
}

#[inline(always)]
fn deadline_score(now_ms: i32, deadline_ms: i32, cancelled: i32) -> i32 {
    if cancelled == 1 {
        return 31;
    }
    if now_ms > deadline_ms {
        return 29;
    }
    7
}

fn network_workload() -> i32 {
    let hosts = ["127.0.0.1", "localhost", "2001:db8::1", "api.service"];
    let kinds = ["stream", "datagram", "unix"];

    let mut i = 0;
    let mut hi = 0usize;
    let mut ki = 0usize;
    let mut acc = 0i32;

    while i < ITERATIONS {
        let host = hosts[hi];
        let kind = kinds[ki];
        let port = 1024 + (i % 32_000);
        let tls = i % 2;
        let ipv6 = i32::from(host.contains("::"));
        let closed = i32::from((i + 11) % 29 == 0);
        let cancelled = i32::from((i + 13) % 41 == 0);

        let endpoint_score = (socket_kind_score(kind) + ip_class_score(host) + (port % 97) + (tls * 37) + (ipv6 * 41)) % 251;
        let signal_score = poll_signal_score(i % 2, (i + 1) % 2, (i + 2) % 2, closed);
        let dscore = deadline_score(i % 5000, 2500, cancelled);
        acc = (acc + endpoint_score + signal_score + dscore) % 251;

        hi += 1;
        if hi == hosts.len() {
            hi = 0;
        }
        ki += 1;
        if ki == kinds.len() {
            ki = 0;
        }
        i += 1;
    }

    acc
}

#[inline(always)]
fn enqueue_depth(depth: i32, capacity: i32, policy: i32) -> i32 {
    if depth < capacity {
        return depth + 1;
    }
    if policy == 0 {
        return depth;
    }
    if policy == 1 {
        return capacity;
    }
    depth
}

#[inline(always)]
fn backpressure_score(depth: i32, capacity: i32) -> i32 {
    let watermark = (capacity * 3) / 4;
    if depth >= capacity {
        return 31;
    }
    if depth >= watermark {
        return 17;
    }
    3
}

#[inline(always)]
fn consume_depth(depth: i32, tick: i32) -> i32 {
    if tick % 3 == 0 {
        if depth <= 0 {
            return 0;
        }
        return depth - 1;
    }
    depth
}

fn concurrency_workload() -> i32 {
    let capacity = 64;
    let mut i = 0;
    let mut depth = 0i32;
    let mut policy = 0i32;
    let mut acc = 0i32;

    while i < ITERATIONS {
        depth = enqueue_depth(depth, capacity, policy);
        acc = (acc + backpressure_score(depth, capacity)) % 251;
        depth = consume_depth(depth, i);
        acc = (acc + depth) % 251;

        policy += 1;
        if policy == 3 {
            policy = 0;
        }
        i += 1;
    }

    acc
}

#[inline(always)]
fn classify_exit_score(exit_code: i32, timed_out: i32, cancelled: i32, signal: i32) -> i32 {
    if cancelled == 1 {
        return 29;
    }
    if timed_out == 1 {
        return 23;
    }
    if signal > 0 {
        return 31;
    }
    if exit_code == 0 {
        return 11;
    }
    19
}

#[inline(always)]
fn budget_score(argv_count: i32, env_count: i32, timeout_ms: i32, max_output_bytes: i32, max_children: i32) -> i32 {
    let mut score = (argv_count * 7) + (env_count * 5);
    score += max_children % 97;
    score += timeout_ms % 89;
    score += max_output_bytes % 83;
    score % 251
}

#[inline(always)]
fn retry_delay_ms(attempt: i32, base_ms: i32, max_ms: i32) -> i32 {
    let mut delay = if base_ms < 1 { 1 } else { base_ms };
    let mut i = 1;
    while i < attempt {
        delay *= 2;
        if delay > max_ms {
            delay = max_ms;
        }
        i += 1;
    }
    delay
}

fn process_workload() -> i32 {
    let mut i = 0;
    let mut attempt = 1i32;
    let mut acc = 0i32;

    while i < ITERATIONS {
        let exit_code = i % 5;
        let timed_out = i32::from(i % 17 == 0);
        let cancelled = i32::from(i % 29 == 0);
        let signal = if i % 41 == 0 { 9 } else { 0 };

        let a = classify_exit_score(exit_code, timed_out, cancelled, signal);
        let b = budget_score((i % 9) + 1, (i % 19) + 2, 30000, 1_048_576, 16);
        let c = retry_delay_ms(attempt, 4, 128);
        acc = (acc + a + b + c) % 251;

        attempt += 1;
        if attempt > 7 {
            attempt = 1;
        }
        i += 1;
    }

    acc
}

#[inline(always)]
fn redact_key_score(key: &str) -> i32 {
    match key {
        "secret" => 31,
        "token" => 29,
        "password" => 37,
        "api_key" => 41,
        "bearer" => 43,
        "jwt" => 47,
        "authorization" => 53,
        _ => 11,
    }
}

#[inline(always)]
fn auth_score(has_token: i32, expired: i32, scope_ok: i32, mfa_required: i32, mfa_present: i32) -> i32 {
    if has_token == 0 {
        return 17;
    }
    if expired == 1 {
        return 23;
    }
    if scope_ok == 0 {
        return 23;
    }
    if mfa_required == 1 && mfa_present == 0 {
        return 17;
    }
    11
}

#[inline(always)]
fn refill_tokens(tokens: i32, elapsed_ms: i32, refill_per_sec: i32, max_tokens: i32) -> i32 {
    let mut next = tokens;
    if elapsed_ms > 0 {
        next += (elapsed_ms * refill_per_sec) / 1000;
    }
    if next > max_tokens {
        next = max_tokens;
    }
    next
}

#[inline(always)]
fn consume_tokens(tokens: i32, cost: i32) -> i32 {
    if tokens < cost {
        return -1;
    }
    tokens - cost
}

fn security_workload() -> i32 {
    let keys = [
        "secret",
        "token",
        "password",
        "api_key",
        "bearer",
        "jwt",
        "authorization",
        "safe",
    ];

    let mut i = 0;
    let mut ki = 0usize;
    let mut tokens = 8i32;
    let mut acc = 0i32;

    while i < ITERATIONS {
        let key = keys[ki];
        let has_token = i32::from(i % 7 != 0);
        let expired = i32::from(i % 11 == 0);
        let scope_ok = i32::from(i % 13 != 0);
        let mfa_required = i32::from(i % 5 == 0);
        let mfa_present = i32::from(i % 3 == 0);

        tokens = refill_tokens(tokens, 250, 4, 16);
        let rem = consume_tokens(tokens, 1);
        if rem >= 0 {
            tokens = rem;
        }

        let a = redact_key_score(key);
        let b = auth_score(has_token, expired, scope_ok, mfa_required, mfa_present);
        acc = (acc + a + b + (tokens % 17)) % 251;

        ki += 1;
        if ki == keys.len() {
            ki = 0;
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
        "http_oneoff" => http_oneoff_workload(),
        "http_persistent" => http_persistent_workload(),
        "network" => network_workload(),
        "concurrency" => concurrency_workload(),
        "process" => process_workload(),
        "security" => security_workload(),
        other => {
            eprintln!(
                "unknown mode `{other}`; expected one of: resultx,text,capability,task_retry,arithmetic,bytes,duration,abi_pair,c_interop_contract,http,network,concurrency,process,security"
            );
            std::process::exit(2);
        }
    };
    println!("checksum={checksum}");
}

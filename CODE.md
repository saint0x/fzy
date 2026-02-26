# CODE.md

## 0) Local CLI shim

```bash
if ! command -v fz >/dev/null 2>&1; then
  fz() { cargo run -q -p fz -- "$@"; }
fi
```

## 1) Project conventions: module layout + entrypoint contract

```bash
tmpd="$(mktemp -d /tmp/code_project_layout.XXXXXX)"
mkdir -p "$tmpd/src/services" "$tmpd/src/runtime" "$tmpd/src/tests"

cat > "$tmpd/src/main.fzy" <<'FZY'
use core.time;
mod services;
mod runtime;
mod tests;

fn main() -> i32 {
    requires true
    services.boot_all()
    runtime.start()
    ensures true
    return 0
}
FZY

cat > "$tmpd/src/services/mod.fzy" <<'FZY'
mod auth;
mod store;

fn boot_all() -> i32 {
    auth.init()
    store.init()
    return 0
}
FZY

cat > "$tmpd/src/services/auth.fzy" <<'FZY'
pub fn init() -> i32 { return 0 }
FZY

cat > "$tmpd/src/services/store.fzy" <<'FZY'
pub fn init() -> i32 { return 0 }
FZY

cat > "$tmpd/src/runtime/mod.fzy" <<'FZY'
fn start() -> i32 { return 0 }
FZY

cat > "$tmpd/src/tests/mod.fzy" <<'FZY'
test "boot-smoke" { pulse() }
FZY

fz check "$tmpd/src/main.fzy" --json
```

## 2) Primitive literals + numeric/boolean/char/string semantics

```bash
cat > /tmp/code_primitives.fzy <<'FZY'
fn main() -> i32 {
    let i: i32 = 42
    let j: i32 = -7
    let big: i128 = 123456789
    let f: f64 = 3.14
    let c: char = 'z'
    let ok: bool = true
    let msg: str = "hello"

    discard big
    discard f
    discard c
    discard msg

    if ok then return i + j
    return 0
}
FZY

fz check /tmp/code_primitives.fzy --json
```

## 3) `let`, `let mut`, reassignment, compound assignment

```bash
cat > /tmp/code_bindings.fzy <<'FZY'
fn main() -> i32 {
    let mut total: i32 = 1
    total = total + 3
    total += 4
    total -= 2
    total *= 5
    total /= 2
    total %= 7
    return total
}
FZY

fz run /tmp/code_bindings.fzy --backend llvm --json
```

## 4) Operators: arithmetic, comparison, logical, bitwise, shifts, unary

```bash
cat > /tmp/code_operators.fzy <<'FZY'
fn main() -> i32 {
    let a: i32 = 12
    let b: i32 = 5

    let arith = (a + b) * (a - b) / (b | 1)
    let modu = arith % 9
    let cmp = (a > b) && (a != 0) || false

    let bits = (~a) ^ (b << 2)
    let shr = bits >> 1

    if cmp {
        return modu + shr
    }
    return 0 - shr
}
FZY

fz check /tmp/code_operators.fzy --json
```

## 5) Arrays + indexing + index expressions in calls

```bash
cat > /tmp/code_arrays_index.fzy <<'FZY'
fn add(x: i32, y: i32) -> i32 { return x + y }

fn main() -> i32 {
    let values = [3, 5, 8, 13, 21]
    let mut idx = 2
    idx += 1

    let picked = values[idx]
    let first = values[0]
    return add(picked, first)
}
FZY

fz run /tmp/code_arrays_index.fzy --backend cranelift --json
```

## 6) Loop flows: `while`, C-style `for`, `for in`, `loop`, break/continue

```bash
cat > /tmp/code_loops_full.fzy <<'FZY'
fn main() -> i32 {
    let mut total = 0
    let mut i = 0

    // while + continue + break
    while i < 10 {
        i += 1
        if i % 2 == 0 {
            continue
        }
        total += i
        if total > 15 {
            break
        }
    }

    // C-style for (init omitted; uses existing i)
    for ; i < 14; i += 1 {
        total += 1
    }

    // for-in exclusive range
    for n in 0..4 {
        total += n
    }

    // for-in inclusive range
    for n in range.closed(4, 6) {
        total += n
    }

    // infinite loop with explicit break
    loop {
        total += 1
        if total > 40 {
            break
        }
    }

    return total
}
FZY

fz run /tmp/code_loops_full.fzy --backend llvm --json
```

## 7) Branching + `match` semantics

```bash
cat > /tmp/code_match.fzy <<'FZY'
enum Msg {
    Msg::Ping,
    Msg::Pong,
    Msg::Data(i32),
    Msg::Err(i32),
}

fn code(v: i32) -> i32 {
    if v < 0 {
        return -1
    } else if v == 0 {
        return 10
    }
    return 20
}

fn classify(msg: Msg) -> i32 {
    return match msg {
        Msg::Ping => 1,
        Msg::Pong => 2,
        Msg::Data(v) => v,
        Msg::Err(code) => 0 - code,
        _ => 0,
    }
}

fn main() -> i32 {
    let a = code(0)
    let b = classify(Msg::Ping)
    return a + b
}
FZY

fz check /tmp/code_match.fzy --json
```

## 8) Function declarations, visibility, ext, async, function types

```bash
cat > /tmp/code_functions.fzy <<'FZY'
ext unsafe c fn c_add(left: i32, right: i32) -> i32;

pub fn sum(x: i32, y: i32) -> i32 { return x + y }

fn apply(cb: fn(i32) -> i32, v: i32) -> i32 {
    return cb(v)
}

async fn worker(v: i32) -> i32 {
    checkpoint()
    return v + 100
}

async fn run_worker(v: i32) -> i32 {
    return await worker(v)
}

fn id(v: i32) -> i32 { return v }

fn main() -> i32 {
    let a = sum(4, 5)
    let b = apply(id, a)
    discard c_add
    discard run_worker
    return b
}
FZY

fz check /tmp/code_functions.fzy --json
```

## 9) Lambda syntax + closures (capturing outer variables)

```bash
cat > /tmp/code_lambda_closure.fzy <<'FZY'
fn apply(cb: fn(i32) -> i32, v: i32) -> i32 {
    return cb(v)
}

fn main() -> i32 {
    let base = 12
    let values = [1, 2, 3]
    let idx = 1

    // lambda syntax: |param: type| expr
    let plus = |x: i32| x + base + values[idx]
    return apply(plus, 5)
}
FZY

fz run /tmp/code_lambda_closure.fzy --backend llvm --json
```

## 10) Globals: `const`, `static`, `static mut`

```bash
cat > /tmp/code_globals_full.fzy <<'FZY'
const MAGIC: i32 = 9;
static SCALE: i32 = 4;
static mut COUNTER: i32 = 0;

fn bump() -> i32 {
    COUNTER += 1
    return COUNTER
}

fn main() -> i32 {
    let mut out = MAGIC * SCALE
    out += bump()
    out += bump()
    return out
}
FZY

fz run /tmp/code_globals_full.fzy --backend cranelift --json
```

## 11) Structs, enums, traits, impl, field access, struct init

```bash
cat > /tmp/code_types_full.fzy <<'FZY'
trait Render {
    fn render(v: i32) -> i32;
}

struct Point {
    x: i32,
    y: i32,
}

enum Flag {
    Flag::On,
    Flag::Off,
}

impl Render for Point {
    fn render(v: i32) -> i32 {
        return v + 1
    }
}

fn main() -> i32 {
    let p = Point { x: 3, y: 8 }
    let f = Flag::On
    discard f
    return Point.render(p.x + p.y)
}
FZY

fz check /tmp/code_types_full.fzy --json
```

## 12) Import ergonomics: path import, alias, re-export, grouped, wildcard

```bash
tmpd="$(mktemp -d /tmp/code_import_surface.XXXXXX)"
mkdir -p "$tmpd/services"

cat > "$tmpd/main.fzy" <<'FZY'
mod services;
use services::auth::init as auth_init;
pub use services::store::init;
use services::{metrics::tick, telemetry::*};

fn main() -> i32 {
    tick()
    services.telemetry.pulse()
    return auth_init() + init()
}
FZY

cat > "$tmpd/services/mod.fzy" <<'FZY'
mod auth;
mod store;
mod metrics;
mod telemetry;
FZY
cat > "$tmpd/services/auth.fzy" <<'FZY'
pub fn init() -> i32 { return 10 }
FZY
cat > "$tmpd/services/store.fzy" <<'FZY'
pub fn init() -> i32 { return 20 }
FZY
cat > "$tmpd/services/metrics.fzy" <<'FZY'
pub fn tick() -> i32 { return 0 }
FZY
cat > "$tmpd/services/telemetry.fzy" <<'FZY'
pub fn pulse() -> i32 { return 0 }
FZY

fz check "$tmpd/main.fzy" --json
```

## 13) Contracts, `defer`, and explicit unsafe islands

```bash
cat > /tmp/code_contracts_safety.fzy <<'FZY'
unsafe fn checked_add(x: i32, y: i32) -> i32 {
    requires x >= 0
    defer pulse()
    let p = alloc(8)
    // Compiler-generated unsafe docs include reason/invariant/owner/scope/risk_class/proof_ref.
    unsafe {
        free(p)
    }
    let out = x + y
    ensures out >= x
    return out
}

fn main() -> i32 {
    return checked_add(3, 7)
}
FZY

fz check /tmp/code_contracts_safety.fzy --json
```

## 14) Runtime/task semantics: timeout, cancel, checkpoint, yield, spawn/join

```bash
cat > /tmp/code_runtime_tasks.fzy <<'FZY'
use core.thread;

async fn worker(v: i32) -> i32 {
    timeout(50)
    checkpoint()
    yield()
    pulse()
    if recv() != 0 then return -1
    return v + 100
}

fn main() -> i32 {
    let h = spawn(worker)
    let out = join(h)
    discard out
    cancel()
    return 0
}
FZY

fz check /tmp/code_runtime_tasks.fzy --json
```

## 15) Task-group API surface

```bash
cat > /tmp/code_task_groups.fzy <<'FZY'
fn job_a() -> i32 { return 0 }
fn job_b() -> i32 { return 0 }

fn main() -> i32 {
    let g = task.group_begin()
    discard task.group_spawn(g, job_a)
    discard task.group_spawn(g, job_b)
    discard task.group_join(g)
    discard task.group_cancel(g)
    return 0
}
FZY

fz check /tmp/code_task_groups.fzy --json
```

## 16) FFI exports/imports + panic policy attribute

```bash
cat > /tmp/code_ffi_full.fzy <<'FZY'
ext unsafe c fn c_add(left: i32, right: i32) -> i32;

#[ffi_panic(abort)]
pubext c fn add_safe(left: i32, right: i32) -> i32 {
    return left + right
}

fn main() -> i32 {
    let local = add_safe(5, 6)
    unsafe {
        discard c_add
    }
    return local
}
FZY

fz check /tmp/code_ffi_full.fzy --json
```

## 17) `#[repr(C)]` layout contracts on structs/enums

```bash
cat > /tmp/code_repr_c.fzy <<'FZY'
#[repr(C)]
struct Header {
    version: u32,
    flags: u32,
    payload_len: usize,
}

#[repr(C)]
enum Kind {
    Kind::A,
    Kind::B,
}

fn main() -> i32 {
    let h = Header { version: 1, flags: 0, payload_len: 8 }
    discard h
    let k = Kind::A
    discard k
    return 0
}
FZY

fz check /tmp/code_repr_c.fzy --json
```

## 18) RPC declarations

```bash
cat > /tmp/code_rpc.fzy <<'FZY'
rpc Ping(req: i32) -> i32;
rpc Put(key: i32, value: i32) -> i32;

fn main() -> i32 {
    discard Ping(1)
    discard Put(2, 3)
    return 0
}
FZY

fz check /tmp/code_rpc.fzy --json
```

## 19) Test blocks: deterministic and nondeterministic forms

```bash
cat > /tmp/code_tests_surface.fzy <<'FZY'
fn add(x: i32, y: i32) -> i32 { return x + y }

test "det-add" {
    let v = add(2, 3)
    assert.eq_i32(v, 5)
}

test "nondet-smoke" nondet {
    pulse()
}

fn main() -> i32 {
    return add(1, 1)
}
FZY

fz test /tmp/code_tests_surface.fzy --det --json
```

## 20) Native parity probe for language completeness

```bash
fz parity tests/fixtures/native_completeness/main.fzy --seed 4242 --json
fz equivalence tests/fixtures/native_completeness/main.fzy --seed 4242 --json
```

## 21) Formatting convention gate on source trees

```bash
fz fmt examples/fullstack/src --json
fz fmt examples/robust_cli/src --json
fz fmt examples/fullstack/src examples/robust_cli/src --check
```

## 22) End-to-end synthesis snippet (feature blend)

```bash
cat > /tmp/code_synthesis.fzy <<'FZY'
use core.time;

const C: i32 = 2;
static S: i32 = 3;
static mut M: i32 = 0;

fn bump() -> i32 {
    M += 1
    return M
}

fn apply(cb: fn(i32) -> i32, x: i32) -> i32 {
    return cb(x)
}

fn main() -> i32 {
    requires true

    let values = [5, 8, 13]
    let mut idx = 1
    idx += 1

    let lam = |x: i32| x + values[idx] + C + S
    let out = apply(lam, time.now() % 7) + bump()

    match out % 3 {
        0 => return out,
        1 => return out + 1,
        _ => {
            ensures out >= 0
            return out + 2
        }
    }
}
FZY

fz check /tmp/code_synthesis.fzy --json
fz build /tmp/code_synthesis.fzy --backend llvm --json
fz build /tmp/code_synthesis.fzy --backend cranelift --json
```

## 23) Core HTTP namespace surface (HTTP-only)

```bash
cat > /tmp/code_http_namespace.fzy <<'FZY'
use core.http;

fn main() -> i32 {
    let listener = http.bind()
    if http.listen(listener) != 0 {
        return 1
    }
    let conn = http.accept()
    discard http.read(conn)
    discard http.write(conn, 200, "ok")
    return 0
}
FZY

fz check /tmp/code_http_namespace.fzy --json
fz build /tmp/code_http_namespace.fzy --backend llvm --json
fz build /tmp/code_http_namespace.fzy --backend cranelift --json
```

## 24) New stdlib ergonomics modules: full crate tests

```bash
cargo test -p core
cargo test -p stdlib abi::
cargo test -p stdlib text::
cargo test -p stdlib resultx::
cargo test -p stdlib task::
cargo test -p stdlib collections::
```

## 25) Deterministic + trace lifecycle + host-backed HTTP checks

```bash
fozzy doctor --deep --scenario tests/example.fozzy.json --runs 5 --seed 4242 --json
fozzy test --det --strict tests/example.fozzy.json --seed 4242 --json
fozzy run tests/example.fozzy.json --det --record artifacts/core-http.trace.fozzy --json
fozzy trace verify artifacts/core-http.trace.fozzy --strict --json
fozzy replay artifacts/core-http.trace.fozzy --json
fozzy ci artifacts/core-http.trace.fozzy --json
fozzy run tests/example.fozzy.json --proc-backend host --fs-backend host --http-backend host --json

fozzy test --det --strict tests/pedantic.crates_stdlib.http.host_backends_run.pass.fozzy.json --json
fozzy test --det --strict tests/pedantic.crates_stdlib.http.explore_schedule_faults.pass.fozzy.json --json
fozzy test --det --strict tests/pedantic.crates_stdlib.http.shrink_exercised.pass.fozzy.json --json
fozzy test --det --strict tests/pedantic.crates_stdlib.http.fuzz_inputs.pass.fozzy.json --json
fozzy test --det --strict tests/pedantic.crates_stdlib.http.memory_graph_diff_top.pass.fozzy.json --json
```

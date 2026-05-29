# Native Embedding Contract v1

This document defines the production host lifecycle for embedding Fozzy in a native process.

## Required Host Symbols

- `fz_host_init`
- `fz_host_shutdown`
- `fz_host_cleanup`
- `fz_host_last_error_code`
- `fz_host_last_error_class`
- `fz_host_last_error_message`
- `fz_host_register_callback_i32`
- `fz_host_invoke_callback_i32`

## Lifecycle

1. Call `fz_host_init()` before registering callbacks or invoking exported Fozzy functions from an in-process host.
2. Call exported functions.
3. On operational failure, read `fz_host_last_error_code()`, `fz_host_last_error_class()`, and `fz_host_last_error_message()` immediately.
4. Call `fz_host_shutdown()` when the host is done issuing calls.
5. Call `fz_host_cleanup()` during teardown to clear callback registrations and transient host state.

## Concurrency

- Host lifecycle state is process-global.
- Callback registration is guarded by a mutex.
- The current production shim exposes 64 typed `i32` callback slots.

## Canonical Rust Sketch

```rust
unsafe {
    assert_eq!(fz_host_init(), 0);

    let rc = my_exported_entry(arg0, arg1);
    if rc != 0 {
        let code = fz_host_last_error_code();
        let class = fz_host_last_error_class();
        let msg = std::ffi::CStr::from_ptr(fz_host_last_error_message())
            .to_string_lossy()
            .into_owned();
        eprintln!("fozzy call failed: rc={rc} code={code} class={class} msg={msg}");
    }

    assert_eq!(fz_host_shutdown(), 0);
    assert_eq!(fz_host_cleanup(), 0);
}
```

## Tooling

Use:

```bash
fz inspect embedding <target> --json
```

This emits the exact lifecycle contract, header path, ABI manifest path, and exported symbol list for the selected target.

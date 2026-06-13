#[test]
fn native_runtime_shim_bootstraps_dotenv_for_env_and_http() {
    let shim = render_native_runtime_shim(&[], &[], &[], &[]);
    assert!(shim.contains("FZ_DOTENV_PATH"));
    assert!(shim.contains("fz_http_header_upsert"));
    assert!(shim.contains("content-type"));
    assert!(shim.contains("--connect-timeout"));
    assert!(shim.contains("--max-time"));
    assert!(shim.contains("unable to exec curl"));
}

#[test]
fn native_runtime_shim_declares_shared_helpers_before_first_use() {
    let shim = render_native_runtime_shim(&[], &[], &[], &[]);

    let bytes_init_decl = shim
        .find("static void fz_bytes_buf_init(fz_bytes_buf* buf);")
        .expect("bytes init prototype should be emitted");
    let bytes_free_decl = shim
        .find("static void fz_bytes_buf_free(fz_bytes_buf* buf);")
        .expect("bytes free prototype should be emitted");
    let bytes_append_decl = shim
        .find("static int fz_bytes_buf_append(fz_bytes_buf* buf, const char* data, size_t len);")
        .expect("bytes append prototype should be emitted");
    let wait_decl = shim
        .find("static int fz_wait_for_fd_event(int fd, short events, int timeout_ms);")
        .expect("wait helper prototype should be emitted");
    let bytes_init_def = shim
        .find("static void fz_bytes_buf_init(fz_bytes_buf* buf) {")
        .expect("bytes init definition should be emitted");
    let bytes_free_def = shim
        .find("static void fz_bytes_buf_free(fz_bytes_buf* buf) {")
        .expect("bytes free definition should be emitted");
    let bytes_append_def = shim
        .find("static int fz_bytes_buf_append(fz_bytes_buf* buf, const char* data, size_t len) {")
        .expect("bytes append definition should be emitted");
    let wait_def = shim
        .find("static int fz_wait_for_fd_event(int fd, short events, int timeout_ms) {")
        .expect("wait helper definition should be emitted");

    assert!(bytes_init_decl < bytes_init_def);
    assert!(bytes_free_decl < bytes_free_def);
    assert!(bytes_append_decl < bytes_append_def);
    assert!(wait_decl < wait_def);
}

#[test]
fn backend_defaults_dev_cranelift_release_llvm() {
    let project_name = format!(
        "fozzylang-backend-defaults-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let root = std::env::temp_dir().join(project_name);
    std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
    std::fs::write(
        root.join("fozzy.toml"),
        "[package]\nname=\"demo\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"demo\"\npath=\"src/main.fzy\"\n",
    )
    .expect("manifest should be written");
    std::fs::write(
        root.join("src/main.fzy"),
        "fn main() -> i32 {\n    return 0\n}\n",
    )
    .expect("source should be written");

    let dev = compile_file_with_backend(&root, BuildProfile::Dev, None)
        .expect("dev build should succeed");
    assert_eq!(dev.status, "ok");
    assert!(root.join(".fz/build/demo.o").exists());
    assert_eq!(
        dev.output
            .as_deref()
            .and_then(|path| path.file_name())
            .and_then(|name| name.to_str()),
        Some("demo")
    );

    let release = compile_file_with_backend(&root, BuildProfile::Release, None)
        .expect("release build should succeed");
    assert_eq!(release.status, "ok");
    assert!(root.join(".fz/build/demo.ll").exists());

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn verify_accepts_runtime_and_dotted_native_calls() {
    let file_name = format!(
        "fozzylang-native-supported-runtime-{}.fzy",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let path = std::env::temp_dir().join(file_name);
    std::fs::write(
        &path,
        "use core.http;\nfn main() -> i32 {\n    let listener = http.bind()\n    http.listen(listener)\n    http.poll_register(listener)\n    discard http.poll_next()\n    return 0\n}\n",
    )
    .expect("temp source should be written");

    let output = verify_file(&path).expect("verify should run");
    assert!(!output.diagnostic_details.iter().any(|diag| diag
        .message
        .contains("native backend cannot execute unresolved call")));

    let _ = std::fs::remove_file(path);
}

#[test]
fn verify_gpu_surface_stays_backend_neutral_before_live_adapter_lands() {
    let file_name = format!(
        "fozzylang-gpu-verify-neutral-{}.fzy",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let path = std::env::temp_dir().join(file_name);
    std::fs::write(
        &path,
        "use core.gpu;\nkernel fn copy(input: GpuSlice<f32>, output: GpuSlice<f32>, n: i32) -> void {\n    let i = gpu.global_id_x()\n    if i < n {\n        output[i] = input[i]\n    }\n}\nhost fn main() -> i32 {\n    let dev = gpu.default_device()\n    let input = gpu.alloc_f32(dev, 4)\n    defer gpu.free(input)\n    let output = gpu.alloc_f32(dev, 4)\n    defer gpu.free(output)\n    let event = gpu.launch3(copy, 1, 64, gpu.slice(input, 0, 4), gpu.slice(output, 0, 4), 4)\n    gpu.wait(event)\n    return 0\n}\n",
    )
    .expect("temp source should be written");

    let output = verify_file(&path).expect("verify should run");
    assert!(
        !output
            .diagnostic_details
            .iter()
            .any(|diag| diag.message.contains(
                "gpu backend `metal` is declared in the architecture but not yet executable"
            )),
        "verify should stay backend-neutral, got {:?}",
        output
            .diagnostic_details
            .iter()
            .map(|diag| diag.message.clone())
            .collect::<Vec<_>>()
    );
    assert!(
        !output.diagnostic_details.iter().any(|diag| diag
            .message
            .contains("native backend cannot execute unresolved call `gpu.")),
        "verify should not regress to unresolved GPU call diagnostics, got {:?}",
        output
            .diagnostic_details
            .iter()
            .map(|diag| diag.message.clone())
            .collect::<Vec<_>>()
    );

    let _ = std::fs::remove_file(path);
}

#[test]
fn native_build_routes_gpu_launch_through_truthful_backend_path() {
    let project_name = format!(
        "fozzylang-gpu-build-declared-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let root = std::env::temp_dir().join(project_name);
    std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
    std::fs::write(
        root.join("fozzy.toml"),
        "[package]\nname=\"gpu_build_declared\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"gpu_build_declared\"\npath=\"src/main.fzy\"\n",
    )
    .expect("manifest should be written");
    std::fs::write(
        root.join("src/main.fzy"),
        "use core.gpu;\nkernel fn copy(input: GpuSlice<f32>, output: GpuSlice<f32>, n: i32) -> void {\n    let i = gpu.global_id_x()\n    if i < n {\n        output[i] = input[i]\n    }\n}\nhost fn main() -> i32 {\n    let dev = gpu.default_device()\n    let input = gpu.alloc_f32(dev, 4)\n    defer gpu.free(input)\n    let output = gpu.alloc_f32(dev, 4)\n    defer gpu.free(output)\n    let event = gpu.launch3(copy, 1, 64, gpu.slice(input, 0, 4), gpu.slice(output, 0, 4), 4)\n    gpu.wait(event)\n    return 0\n}\n",
    )
    .expect("source should be written");

    let artifact = compile_file_with_backend(&root, BuildProfile::Dev, None)
        .expect("gpu build should return artifact diagnostics");
    if cfg!(target_vendor = "apple") {
        assert_eq!(artifact.status, "ok");
        let output = artifact
            .output
            .as_deref()
            .expect("gpu build output should exist on Apple");
        assert_eq!(run_native_exit(output), 0);
    } else {
        assert_eq!(artifact.status, "error");
        assert!(
            artifact
                .diagnostic_details
                .iter()
                .any(|diag| diag.message.contains(
                    "gpu backend `metal` is declared in the architecture but not yet executable"
                )),
            "expected declared-but-not-executable diagnostic, got {:?}",
            artifact
                .diagnostic_details
                .iter()
                .map(|diag| diag.message.clone())
                .collect::<Vec<_>>()
        );
    }
    assert!(
        !artifact.diagnostic_details.iter().any(|diag| diag
            .message
            .contains("native backend cannot execute unresolved call `gpu.")),
        "GPU build should not regress to unresolved GPU call diagnostics, got {:?}",
        artifact
            .diagnostic_details
            .iter()
            .map(|diag| diag.message.clone())
            .collect::<Vec<_>>()
    );

    let _ = std::fs::remove_dir_all(root);
}

#[cfg(target_vendor = "apple")]
#[test]
fn native_build_and_run_metal_host_gpu_lifecycle_program() {
    let project_name = format!(
        "fozzylang-gpu-metal-host-lifecycle-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let root = std::env::temp_dir().join(project_name);
    std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
    std::fs::write(
        root.join("fozzy.toml"),
        "[package]\nname=\"gpu_metal_host_lifecycle\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"gpu_metal_host_lifecycle\"\npath=\"src/main.fzy\"\n",
    )
    .expect("manifest should be written");
    std::fs::write(
        root.join("src/main.fzy"),
        "use core.gpu;\nhost fn main() -> i32 {\n    let count = gpu.device_count()\n    if count < 1 {\n        return 11\n    }\n    let dev = gpu.default_device()\n    let name = gpu.device_name(dev)\n    let bytes = gpu.device_memory_bytes(dev)\n    let zero: i64 = 0\n    if str.len(name) <= 0 {\n        return 12\n    }\n    if bytes <= zero {\n        return 13\n    }\n    let buf = gpu.alloc_f32(dev, 16)\n    let window = gpu.slice(buf, 4, 8)\n    discard window\n    gpu.free(buf)\n    return 0\n}\n",
    )
    .expect("source should be written");

    let artifact = compile_file_with_backend(&root, BuildProfile::Dev, None)
        .expect("metal host lifecycle build should succeed");
    assert_eq!(artifact.status, "ok");
    let exit = run_native_exit(
        artifact
            .output
            .as_deref()
            .expect("metal host lifecycle output should exist"),
    );
    assert_eq!(exit, 0);

    let _ = std::fs::remove_dir_all(root);
}

#[cfg(target_vendor = "apple")]
#[test]
fn native_build_and_run_metal_host_gpu_upload_program() {
    let project_name = format!(
        "fozzylang-gpu-metal-host-upload-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let root = std::env::temp_dir().join(project_name);
    std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
    std::fs::write(
        root.join("fozzy.toml"),
        "[package]\nname=\"gpu_metal_host_upload\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"gpu_metal_host_upload\"\npath=\"src/main.fzy\"\n",
    )
    .expect("manifest should be written");
    std::fs::write(
        root.join("src/main.fzy"),
        "use core.gpu;\nuse core.simd;\nhost fn main() -> i32 {\n    let dev = gpu.default_device()\n    let values: [f32; 4] = simd.f32x4_store(simd.f32x4_new(1.0, 2.0, 3.0, 4.0))\n    let buf: GpuBuffer<f32> = gpu.upload_f32(dev, values)\n    let window: GpuSlice<f32> = gpu.slice(buf, 1, 2)\n    discard window\n    gpu.free(buf)\n    return 0\n}\n",
    )
    .expect("source should be written");

    let artifact = compile_file_with_backend(&root, BuildProfile::Dev, None)
        .expect("metal host upload build should succeed");
    assert_eq!(artifact.status, "ok");
    let exit = run_native_exit(
        artifact
            .output
            .as_deref()
            .expect("metal host upload output should exist"),
    );
    assert_eq!(exit, 0);

    let _ = std::fs::remove_dir_all(root);
}

#[cfg(target_vendor = "apple")]
#[test]
fn native_build_and_run_metal_host_gpu_download_roundtrip_program() {
    let project_name = format!(
        "fozzylang-gpu-metal-host-download-roundtrip-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let root = std::env::temp_dir().join(project_name);
    std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
    std::fs::write(
        root.join("fozzy.toml"),
        "[package]\nname=\"gpu_metal_host_download_roundtrip\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"gpu_metal_host_download_roundtrip\"\npath=\"src/main.fzy\"\n",
    )
    .expect("manifest should be written");
    std::fs::write(
        root.join("src/main.fzy"),
        "use core.gpu;\nuse core.simd;\nhost fn main() -> i32 {\n    let dev = gpu.default_device()\n    let values: [f32; 4] = simd.f32x4_store(simd.f32x4_new(1.0, 2.0, 3.0, 4.0))\n    let buf: GpuBuffer<f32> = gpu.upload_f32(dev, values)\n    let downloaded: Vec<f32> = gpu.download_f32(buf)\n    gpu.free(buf)\n    if downloaded[0] != values[0] {\n        return 11\n    }\n    if downloaded[1] != values[1] {\n        return 12\n    }\n    if downloaded[2] != values[2] {\n        return 13\n    }\n    if downloaded[3] != values[3] {\n        return 14\n    }\n    return 0\n}\n",
    )
    .expect("source should be written");

    let artifact = compile_file_with_backend(&root, BuildProfile::Dev, None)
        .expect("metal host download roundtrip build should succeed");
    assert_eq!(artifact.status, "ok");
    let exit = run_native_exit(
        artifact
            .output
            .as_deref()
            .expect("metal host download roundtrip output should exist"),
    );
    assert_eq!(exit, 0);

    let _ = std::fs::remove_dir_all(root);
}

#[cfg(target_vendor = "apple")]
#[test]
fn native_build_and_run_metal_gpu_kernel_suite_program() {
    let project_name = format!(
        "fozzylang-gpu-metal-kernel-suite-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let root = std::env::temp_dir().join(project_name);
    std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
    std::fs::write(
        root.join("fozzy.toml"),
        "[package]\nname=\"gpu_metal_kernel_suite\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"gpu_metal_kernel_suite\"\npath=\"src/main.fzy\"\n",
    )
    .expect("manifest should be written");
    std::fs::write(
        root.join("src/main.fzy"),
        "use core.gpu;\nuse core.simd;\nkernel fn vector_add(left: GpuSlice<f32>, right: GpuSlice<f32>, output: GpuSlice<f32>, n: i32) -> void {\n    let i = gpu.global_id_x()\n    if i < n {\n        output[i] = left[i] + right[i]\n    }\n}\nkernel fn saxpy(x: GpuSlice<f32>, y: GpuSlice<f32>, output: GpuSlice<f32>, n: i32) -> void {\n    let i = gpu.global_id_x()\n    if i < n {\n        output[i] = x[i] * 2.0f32 + y[i]\n    }\n}\nkernel fn relu(input: GpuSlice<f32>, output: GpuSlice<f32>, n: i32) -> void {\n    let i = gpu.global_id_x()\n    if i < n {\n        let value = input[i]\n        if value > 0.0f32 {\n            output[i] = value\n        } else {\n            output[i] = 0.0f32\n        }\n    }\n}\nhost fn main() -> i32 {\n    let dev = gpu.default_device()\n\n    let left: [f32; 4] = simd.f32x4_store(simd.f32x4_new(1.0, 2.0, 3.0, 4.0))\n    let right: [f32; 4] = simd.f32x4_store(simd.f32x4_new(10.0, 20.0, 30.0, 40.0))\n    let left_buf: GpuBuffer<f32> = gpu.upload_f32(dev, left)\n    let right_buf: GpuBuffer<f32> = gpu.upload_f32(dev, right)\n    let add_buf: GpuBuffer<f32> = gpu.alloc_f32(dev, 4)\n    let add_event = gpu.launch4(vector_add, 1, 64, gpu.slice(left_buf, 0, 4), gpu.slice(right_buf, 0, 4), gpu.slice(add_buf, 0, 4), 4)\n    gpu.wait(add_event)\n    let add_out: Vec<f32> = gpu.download_f32(add_buf)\n    gpu.free(left_buf)\n    gpu.free(right_buf)\n    gpu.free(add_buf)\n    if add_out[0] != 11.0f32 || add_out[1] != 22.0f32 || add_out[2] != 33.0f32 || add_out[3] != 44.0f32 {\n        return 11\n    }\n\n    let saxpy_x: [f32; 4] = simd.f32x4_store(simd.f32x4_new(1.0, 2.0, 3.0, 4.0))\n    let saxpy_y: [f32; 4] = simd.f32x4_store(simd.f32x4_new(5.0, 6.0, 7.0, 8.0))\n    let saxpy_x_buf: GpuBuffer<f32> = gpu.upload_f32(dev, saxpy_x)\n    let saxpy_y_buf: GpuBuffer<f32> = gpu.upload_f32(dev, saxpy_y)\n    let saxpy_out_buf: GpuBuffer<f32> = gpu.alloc_f32(dev, 4)\n    let saxpy_event = gpu.launch4(saxpy, 1, 64, gpu.slice(saxpy_x_buf, 0, 4), gpu.slice(saxpy_y_buf, 0, 4), gpu.slice(saxpy_out_buf, 0, 4), 4)\n    gpu.wait(saxpy_event)\n    let saxpy_out: Vec<f32> = gpu.download_f32(saxpy_out_buf)\n    gpu.free(saxpy_x_buf)\n    gpu.free(saxpy_y_buf)\n    gpu.free(saxpy_out_buf)\n    if saxpy_out[0] != 7.0f32 || saxpy_out[1] != 10.0f32 || saxpy_out[2] != 13.0f32 || saxpy_out[3] != 16.0f32 {\n        return 12\n    }\n\n    let relu_values: [f32; 4] = simd.f32x4_store(simd.f32x4_new(-1.0, -2.0, 3.0, 4.0))\n    let relu_in_buf: GpuBuffer<f32> = gpu.upload_f32(dev, relu_values)\n    let relu_out_buf: GpuBuffer<f32> = gpu.alloc_f32(dev, 4)\n    let relu_event = gpu.launch3(relu, 1, 64, gpu.slice(relu_in_buf, 0, 4), gpu.slice(relu_out_buf, 0, 4), 4)\n    gpu.wait(relu_event)\n    let relu_out: Vec<f32> = gpu.download_f32(relu_out_buf)\n    gpu.free(relu_in_buf)\n    gpu.free(relu_out_buf)\n    if relu_out[0] != 0.0f32 || relu_out[1] != 0.0f32 || relu_out[2] != 3.0f32 || relu_out[3] != 4.0f32 {\n        return 13\n    }\n    return 0\n}\n",
    )
    .expect("source should be written");

    let artifact = compile_file_with_backend(&root, BuildProfile::Dev, None)
        .expect("metal kernel suite build should succeed");
    assert_eq!(artifact.status, "ok");
    let exit = run_native_exit(
        artifact
            .output
            .as_deref()
            .expect("metal kernel suite output should exist"),
    );
    assert_eq!(exit, 0);

    let _ = std::fs::remove_dir_all(root);
}

#[cfg(target_vendor = "apple")]
#[test]
fn native_build_and_run_metal_gpu_image_brightness_program() {
    let project_name = format!(
        "fozzylang-gpu-metal-image-brightness-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let root = std::env::temp_dir().join(project_name);
    std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
    std::fs::write(
        root.join("fozzy.toml"),
        "[package]\nname=\"gpu_metal_image_brightness\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"gpu_metal_image_brightness\"\npath=\"src/main.fzy\"\n",
    )
    .expect("manifest should be written");
    std::fs::write(
        root.join("src/main.fzy"),
        "use core.gpu;\nuse core.simd;\nkernel fn brighten(input: GpuSlice<f32>, delta: f32, output: GpuSlice<f32>, n: i32) -> void {\n    let i = gpu.global_id_x()\n    if i < n {\n        let value = input[i] + delta\n        if value > 1.0f32 {\n            output[i] = 1.0f32\n        } else {\n            output[i] = value\n        }\n    }\n}\nhost fn main() -> i32 {\n    let dev = gpu.default_device()\n    let pixels: [f32; 4] = simd.f32x4_store(simd.f32x4_new(0.0, 0.25, 0.75, 0.5))\n    let input_buf: GpuBuffer<f32> = gpu.upload_f32(dev, pixels)\n    let output_buf: GpuBuffer<f32> = gpu.alloc_f32(dev, 4)\n    let event = gpu.launch4(brighten, 1, 64, gpu.slice(input_buf, 0, 4), 0.25f32, gpu.slice(output_buf, 0, 4), 4)\n    gpu.wait(event)\n    let output: Vec<f32> = gpu.download_f32(output_buf)\n    gpu.free(input_buf)\n    gpu.free(output_buf)\n    if output[0] != 0.25f32 || output[1] != 0.5f32 || output[2] != 1.0f32 || output[3] != 0.75f32 {\n        return 41\n    }\n    return 0\n}\n",
    )
    .expect("source should be written");

    let artifact = compile_file_with_backend(&root, BuildProfile::Dev, None)
        .expect("metal image brightness build should succeed");
    assert_eq!(artifact.status, "ok");
    let exit = run_native_exit(
        artifact
            .output
            .as_deref()
            .expect("metal image brightness output should exist"),
    );
    assert_eq!(exit, 0);

    let _ = std::fs::remove_dir_all(root);
}

#[cfg(target_vendor = "apple")]
#[test]
fn native_build_and_run_metal_gpu_runtime_failure_reports_stable_diagnostics() {
    let project_name = format!(
        "fozzylang-gpu-runtime-failure-diagnostics-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let root = std::env::temp_dir().join(project_name);
    std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
    std::fs::write(
        root.join("fozzy.toml"),
        "[package]\nname=\"gpu_runtime_failure_diagnostics\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"gpu_runtime_failure_diagnostics\"\npath=\"src/main.fzy\"\n",
    )
    .expect("manifest should be written");
    std::fs::write(
        root.join("src/main.fzy"),
        "use core.gpu;\nkernel fn copy(input: GpuSlice<f32>, output: GpuSlice<f32>, n: i32) -> void {\n    let i = gpu.global_id_x()\n    if i < n {\n        output[i] = input[i]\n    }\n}\nhost fn main() -> i32 {\n    let dev = gpu.default_device()\n    let input = gpu.alloc_f32(dev, 4)\n    let output = gpu.alloc_f32(dev, 4)\n    let event = gpu.launch3(copy, 1, 1000000, gpu.slice(input, 0, 4), gpu.slice(output, 0, 4), 4)\n    gpu.wait(event)\n    gpu.free(input)\n    gpu.free(output)\n    return 0\n}\n",
    )
    .expect("source should be written");

    let artifact = compile_file_with_backend(&root, BuildProfile::Dev, None)
        .expect("metal runtime failure diagnostics build should succeed");
    assert_eq!(artifact.status, "ok");
    let output = Command::new(
        artifact
            .output
            .as_deref()
            .expect("metal runtime failure diagnostics output should exist"),
    )
    .env("FZ_NATIVE_DEBUG_ERRORS", "1")
    .output()
    .expect("native artifact should execute");
    assert_eq!(output.status.code(), Some(0));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr
        .contains("gpu.launch failed: block 1000000 exceeds Metal max threads-per-threadgroup"));
    assert!(stderr.contains("gpu.wait failed: invalid GPU event handle"));

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn cross_backend_non_i32_and_aggregate_signatures_execute_consistently() {
    let project_name = format!(
        "fozzylang-non-i32-cross-backend-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let root = std::env::temp_dir().join(project_name);
    std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
    std::fs::write(
        root.join("fozzy.toml"),
        "[package]\nname=\"demo\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"demo\"\npath=\"src/main.fzy\"\n",
    )
    .expect("manifest should be written");
    std::fs::write(
        root.join("src/main.fzy"),
        "#[repr(C)]\nstruct Pair { lo: i32, hi: i32 }\nfn id64(v: i64) -> i64 {\n    return v\n}\nfn gate(flag: bool) -> bool {\n    return flag\n}\nfn make_pair() -> Pair {\n    let p: Pair = Pair { lo: 1, hi: 2 }\n    return p\n}\nfn main() -> i64 {\n    let p: Pair = make_pair()\n    discard p\n    if gate(true) then return id64(3000000000)\n    return id64(3000000000)\n}\n",
    )
    .expect("source should be written");

    let cranelift = compile_file_with_backend(&root, BuildProfile::Dev, Some("cranelift"))
        .expect("cranelift build should succeed");
    assert_eq!(cranelift.status, "ok");
    let llvm = compile_file_with_backend(&root, BuildProfile::Dev, Some("llvm"))
        .expect("llvm build should succeed");
    assert_eq!(llvm.status, "ok");
    let cranelift_exit = run_native_exit(
        cranelift
            .output
            .as_deref()
            .expect("cranelift artifact output should exist"),
    );
    let llvm_exit = run_native_exit(
        llvm.output
            .as_deref()
            .expect("llvm artifact output should exist"),
    );
    assert_eq!(cranelift_exit, llvm_exit);

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn cross_backend_primitive_control_flow_and_operator_fixture_execute_consistently() {
    let project_name = format!(
        "fozzylang-primitive-cross-backend-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let root = std::env::temp_dir().join(project_name);
    std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
    std::fs::write(
        root.join("fozzy.toml"),
        "[package]\nname=\"demo\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"demo\"\npath=\"src/main.fzy\"\n",
    )
    .expect("manifest should be written");
    let fixture = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/primitive_parity/main.fzy"),
    )
    .expect("primitive parity fixture should be readable");
    std::fs::write(root.join("src/main.fzy"), fixture).expect("source should be written");

    let cranelift = compile_file_with_backend(&root, BuildProfile::Dev, Some("cranelift"))
        .expect("cranelift build should succeed");
    assert_eq!(cranelift.status, "ok");
    let llvm = compile_file_with_backend(&root, BuildProfile::Dev, Some("llvm"))
        .expect("llvm build should succeed");
    assert_eq!(llvm.status, "ok");
    let cranelift_exit = run_native_exit(
        cranelift
            .output
            .as_deref()
            .expect("cranelift artifact output should exist"),
    );
    let llvm_exit = run_native_exit(
        llvm.output
            .as_deref()
            .expect("llvm artifact output should exist"),
    );
    assert_eq!(cranelift_exit, llvm_exit);

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn cross_backend_native_completeness_fixture_execute_consistently() {
    let project_name = format!(
        "fozzylang-native-completeness-cross-backend-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let root = std::env::temp_dir().join(project_name);
    std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
    std::fs::write(
        root.join("fozzy.toml"),
        "[package]\nname=\"demo\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"demo\"\npath=\"src/main.fzy\"\n",
    )
    .expect("manifest should be written");
    let fixture = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/native_completeness/main.fzy"),
    )
    .expect("native completeness fixture should be readable");
    std::fs::write(root.join("src/main.fzy"), fixture).expect("source should be written");

    let cranelift = compile_file_with_backend(&root, BuildProfile::Dev, Some("cranelift"))
        .expect("cranelift build should succeed");
    assert_eq!(cranelift.status, "ok");
    let llvm = compile_file_with_backend(&root, BuildProfile::Dev, Some("llvm"))
        .expect("llvm build should succeed");
    assert_eq!(llvm.status, "ok");
    let cranelift_exit = run_native_exit(
        cranelift
            .output
            .as_deref()
            .expect("cranelift artifact output should exist"),
    );
    let llvm_exit = run_native_exit(
        llvm.output
            .as_deref()
            .expect("llvm artifact output should exist"),
    );
    assert_eq!(cranelift_exit, llvm_exit);
    assert_eq!(cranelift_exit, 25);

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn cross_backend_const_static_globals_execute_consistently() {
    let project_name = format!(
        "fozzylang-const-static-cross-backend-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let root = std::env::temp_dir().join(project_name);
    std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
    std::fs::write(
        root.join("fozzy.toml"),
        "[package]\nname=\"demo\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"demo\"\npath=\"src/main.fzy\"\n",
    )
    .expect("manifest should be written");
    std::fs::write(
        root.join("src/main.fzy"),
        "const MAGIC: i32 = 7;\nstatic LIMIT: i32 = MAGIC + 3;\nfn main() -> i32 {\n    return MAGIC + LIMIT\n}\n",
    )
    .expect("source should be written");

    let cranelift = compile_file_with_backend(&root, BuildProfile::Dev, Some("cranelift"))
        .expect("cranelift build should succeed");
    assert_eq!(cranelift.status, "ok");
    let llvm = compile_file_with_backend(&root, BuildProfile::Dev, Some("llvm"))
        .expect("llvm build should succeed");
    assert_eq!(llvm.status, "ok");
    let cranelift_exit = run_native_exit(
        cranelift
            .output
            .as_deref()
            .expect("cranelift artifact output should exist"),
    );
    let llvm_exit = run_native_exit(
        llvm.output
            .as_deref()
            .expect("llvm artifact output should exist"),
    );
    assert_eq!(cranelift_exit, llvm_exit);
    assert_eq!(cranelift_exit, 17);

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn cross_backend_static_mut_globals_execute_consistently() {
    let project_name = format!(
        "fozzylang-static-mut-cross-backend-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let root = std::env::temp_dir().join(project_name);
    std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
    std::fs::write(
        root.join("fozzy.toml"),
        "[package]\nname=\"demo\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"demo\"\npath=\"src/main.fzy\"\n",
    )
    .expect("manifest should be written");
    std::fs::write(
        root.join("src/main.fzy"),
        "static mut COUNTER: i32 = 2;\nfn bump() -> i32 {\n    COUNTER += 3;\n    return COUNTER\n}\nfn main() -> i32 {\n    let first = bump()\n    let second = bump()\n    return first + second\n}\n",
    )
    .expect("source should be written");

    let cranelift = compile_file_with_backend(&root, BuildProfile::Dev, Some("cranelift"))
        .expect("cranelift build should succeed");
    assert_eq!(cranelift.status, "ok");
    let llvm = compile_file_with_backend(&root, BuildProfile::Dev, Some("llvm"))
        .expect("llvm build should succeed");
    assert_eq!(llvm.status, "ok");
    let cranelift_exit = run_native_exit(
        cranelift
            .output
            .as_deref()
            .expect("cranelift artifact output should exist"),
    );
    let llvm_exit = run_native_exit(
        llvm.output
            .as_deref()
            .expect("llvm artifact output should exist"),
    );
    assert_eq!(cranelift_exit, llvm_exit);
    assert_eq!(cranelift_exit, 13);

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn cross_backend_float_execution_is_consistent() {
    let project_name = format!(
        "fozzylang-float-cross-backend-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let root = std::env::temp_dir().join(project_name);
    std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
    std::fs::write(
        root.join("fozzy.toml"),
        "[package]\nname=\"demo\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"demo\"\npath=\"src/main.fzy\"\n",
    )
    .expect("manifest should be written");
    std::fs::write(
        root.join("src/main.fzy"),
        "fn score(base: f64, bonus: f64) -> f64 {\n    return (base + bonus) / 2.0\n}\nfn main() -> i32 {\n    let blended: f64 = score(5.0, 1.0)\n    if blended >= 3.0 && blended < 4.0 {\n        return 17\n    }\n    return 9\n}\n",
    )
    .expect("source should be written");

    let cranelift = compile_file_with_backend(&root, BuildProfile::Dev, Some("cranelift"))
        .expect("cranelift build should succeed");
    assert_eq!(cranelift.status, "ok");
    let llvm = compile_file_with_backend(&root, BuildProfile::Dev, Some("llvm"))
        .expect("llvm build should succeed");
    assert_eq!(llvm.status, "ok");
    let cranelift_exit = run_native_exit(
        cranelift
            .output
            .as_deref()
            .expect("cranelift artifact output should exist"),
    );
    let llvm_exit = run_native_exit(
        llvm.output
            .as_deref()
            .expect("llvm artifact output should exist"),
    );
    assert_eq!(cranelift_exit, llvm_exit);
    assert_eq!(cranelift_exit, 17);

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn cross_backend_non_finite_float_results_trap() {
    let project_name = format!(
        "fozzylang-float-nonfinite-cross-backend-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let root = std::env::temp_dir().join(project_name);
    std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
    std::fs::write(
        root.join("fozzy.toml"),
        "[package]\nname=\"demo\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"demo\"\npath=\"src/main.fzy\"\n",
    )
    .expect("manifest should be written");
    std::fs::write(
        root.join("src/main.fzy"),
        "fn main() -> i32 {\n    let boom: f64 = 1.0 / 0.0\n    return if boom > 0.0 { 1 } else { 0 }\n}\n",
    )
    .expect("source should be written");

    let cranelift = compile_file_with_backend(&root, BuildProfile::Dev, Some("cranelift"))
        .expect("cranelift build should succeed");
    assert_eq!(cranelift.status, "ok");
    let llvm = compile_file_with_backend(&root, BuildProfile::Dev, Some("llvm"))
        .expect("llvm build should succeed");
    assert_eq!(llvm.status, "ok");

    let cranelift_status = run_native_status(
        cranelift
            .output
            .as_deref()
            .expect("cranelift artifact output should exist"),
    );
    let llvm_status = run_native_status(
        llvm.output
            .as_deref()
            .expect("llvm artifact output should exist"),
    );

    assert!(!cranelift_status.success());
    assert!(!llvm_status.success());

    let _ = std::fs::remove_dir_all(root);
}


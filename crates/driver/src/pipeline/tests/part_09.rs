use super::*;
use super::super::llvm::lower_llvm_ir;

#[test]
fn llvm_array_literal_return_values_round_trip_through_named_locals() {
    let project_name = format!(
        "fozzylang-array-return-{}",
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
        "fn make() -> [i32; 4] {\n    return [1, 2, 3, 4]\n}\n\nfn main() -> i32 {\n    let out = make()\n    return out[2] - 3\n}\n",
    )
    .expect("source should be written");

    let llvm = compile_file_with_backend(&root, BuildProfile::Dev, Some("llvm"))
        .expect("llvm build should succeed");
    assert_eq!(llvm.status, "ok");
    let llvm_exit = run_native_exit(llvm.output.as_ref().expect("llvm output should exist"));
    assert_eq!(llvm_exit, 0);

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn cross_backend_array_return_values_survive_following_calls() {
    let project_name = format!(
        "fozzylang-array-return-ownership-{}",
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
        "fn seed() -> [i32; 4] {\n    return [9, 8, 7, 6]\n}\n\nfn id(v: i32) -> i32 {\n    return v\n}\n\nfn main() -> i32 {\n    let values = seed()\n    discard id(41)\n    if values[0] != 9 || values[1] != 8 || values[2] != 7 || values[3] != 6 {\n        return 77\n    }\n    return 0\n}\n",
    )
    .expect("source should be written");

    let cranelift = compile_file_with_backend(&root, BuildProfile::Dev, Some("cranelift"))
        .expect("cranelift build should succeed");
    let llvm = compile_file_with_backend(&root, BuildProfile::Dev, Some("llvm"))
        .expect("llvm build should succeed");
    assert_eq!(cranelift.status, "ok");
    assert_eq!(llvm.status, "ok");

    let cranelift_exit = run_native_exit(
        cranelift
            .output
            .as_ref()
            .expect("cranelift output should exist"),
    );
    let llvm_exit = run_native_exit(llvm.output.as_ref().expect("llvm output should exist"));
    assert_eq!(cranelift_exit, 0);
    assert_eq!(llvm_exit, 0);

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn portable_simd_surface_executes_on_cranelift_backend() {
    let project_name = format!(
        "fozzylang-simd-cranelift-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let root = std::env::temp_dir().join(project_name);
    std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
    std::fs::write(
        root.join("fozzy.toml"),
        "[package]\nname=\"demo\"\nversion=\"0.1.0\"\n\n[[target.bin]]\nname=\"demo\"\npath=\"src/main.fzy\"\n[build]\nbackend=\"cranelift\"\n",
    )
    .expect("manifest should be written");
    std::fs::write(
        root.join("src/main.fzy"),
        "use core.simd;\nfn main() -> i32 {\n    let ints = simd.i32x4_add(simd.i32x4_new(1, 2, 3, 4), simd.i32x4_splat(1))\n    return simd.i32x4_lane0(ints)\n}\n",
    )
    .expect("source should be written");

    let artifact = compile_file_with_backend(&root, BuildProfile::Dev, Some("cranelift"))
        .expect("cranelift SIMD build should succeed");
    assert_eq!(artifact.status, "ok");
    let exit = run_native_exit(
        artifact
            .output
            .as_deref()
            .expect("cranelift SIMD artifact output should exist"),
    );
    assert_eq!(exit, 2);

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn portable_simd_raw_pointer_memory_executes_on_native_backends() {
    let project_name = format!(
        "fozzylang-simd-ptr-{}",
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
        "use core.simd;\n\nfn plus1(ptr: *mut u8) -> *mut u8 {\n    unsafe {\n        return ptr + 1\n    }\n}\n\nfn aligned_lane0(ptr: *mut u8) -> i32 {\n    unsafe {\n        let value = simd.i32x4_load_ptr_aligned(ptr)\n        return simd.i32x4_lane0(value)\n    }\n}\n\nfn aligned_lane3(ptr: *mut u8) -> i32 {\n    unsafe {\n        let value = simd.i32x4_load_ptr_aligned(ptr)\n        return simd.i32x4_lane3(value)\n    }\n}\n\nfn unaligned_lane0(ptr: *mut u8) -> i32 {\n    unsafe {\n        let value = simd.i32x4_load_ptr_unaligned(ptr)\n        return simd.i32x4_lane0(value)\n    }\n}\n\nfn unaligned_lane3(ptr: *mut u8) -> i32 {\n    unsafe {\n        let value = simd.i32x4_load_ptr_unaligned(ptr)\n        return simd.i32x4_lane3(value)\n    }\n}\n\nfn aligned_mask_bits(ptr: *mut u8) -> i32 {\n    unsafe {\n        return simd.mask32x4_bitmask(simd.mask32x4_load_ptr_aligned(ptr))\n    }\n}\n\nfn unaligned_mask_bits(ptr: *mut u8) -> i32 {\n    unsafe {\n        return simd.mask32x4_bitmask(simd.mask32x4_load_ptr_unaligned(ptr))\n    }\n}\n\nfn main() -> i32 {\n    let p = alloc(32)\n    defer free(p)\n    let r = alloc(32)\n    defer free(r)\n    let m = alloc(16)\n    defer free(m)\n    let n = alloc(16)\n    defer free(n)\n    unsafe {\n        simd.i32x4_store_ptr_aligned(p, simd.i32x4_new(10, 20, 30, 40))\n        simd.i32x4_store_ptr_unaligned(plus1(r), simd.i32x4_new(90, 80, 70, 60))\n        simd.mask32x4_store_ptr_aligned(m, simd.mask32x4_load([true, false, true, false]))\n        simd.mask32x4_store_ptr_unaligned(plus1(n), simd.mask32x4_load([false, true, true, false]))\n    }\n    if aligned_lane0(p) != 10 || aligned_lane3(p) != 40 { return 11 }\n    if unaligned_lane0(plus1(r)) != 90 || unaligned_lane3(plus1(r)) != 60 { return 13 }\n    if aligned_mask_bits(m) != 5 { return 15 }\n    if unaligned_mask_bits(plus1(n)) != 6 { return 17 }\n    return 0\n}\n",
    )
    .expect("source should be written");

    let llvm = compile_file_with_backend(&root, BuildProfile::Dev, Some("llvm"))
        .expect("llvm build should succeed");
    let cranelift = compile_file_with_backend(&root, BuildProfile::Dev, Some("cranelift"))
        .expect("cranelift build should succeed");
    assert_eq!(llvm.status, "ok");
    assert_eq!(cranelift.status, "ok");
    assert_eq!(
        run_native_exit(llvm.output.as_ref().expect("llvm output should exist")),
        0
    );
    assert_eq!(
        run_native_exit(
            cranelift
                .output
                .as_ref()
                .expect("cranelift output should exist")
        ),
        0
    );

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn portable_simd_types_are_rejected_across_abi_boundaries() {
    let file_name = format!(
        "fozzylang-simd-abi-{}.fzy",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let path = std::env::temp_dir().join(file_name);
    std::fs::write(
        &path,
        "pubext c fn expose(v: i32x4) -> i32x4 { return v }\nfn main() -> i32 { return 0 }\n",
    )
    .expect("temp source should be written");

    let output = verify_file(&path).expect("verify should run");
    assert!(output.diagnostic_details.iter().any(|diagnostic| diagnostic
        .message
        .contains("SIMD type appears across ABI boundary")));

    let _ = std::fs::remove_file(path);
}

#[test]
fn portable_simd_shuffle_traps_on_out_of_range_lane() {
    let project_name = format!(
        "fozzylang-simd-shuffle-trap-{}",
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
        "use core.simd;\nfn main() -> i32 {\n    let bad = 9\n    let value = simd.i32x4_shuffle(simd.i32x4_new(1, 2, 3, 4), simd.i32x4_splat(0), 0, bad, 2, 3)\n    return simd.i32x4_lane0(value)\n}\n",
    )
    .expect("source should be written");

    let llvm = compile_file_with_backend(&root, BuildProfile::Dev, Some("llvm"))
        .expect("llvm build should succeed");
    let llvm_status = run_native_status(
        llvm.output
            .as_deref()
            .expect("llvm artifact output should exist"),
    );
    assert!(!llvm_status.success());

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn compile_project_directory_uses_manifest_target() {
    let project_name = format!(
        "fozzylang-project-{}",
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
        "use core.time;\nfn main() -> i32 {\n    return 0\n}\n",
    )
    .expect("source should be written");

    let artifact = compile_file(&root, BuildProfile::Dev).expect("project should compile");
    assert_eq!(artifact.module, "main");
    assert_eq!(
        artifact
            .output
            .as_deref()
            .and_then(|path| path.file_name())
            .and_then(|name| name.to_str()),
        Some("demo")
    );
    assert!(artifact.output.as_ref().is_some_and(|path| path.exists()));

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn compile_library_uses_lib_target_when_present() {
    let project_name = format!(
        "fozzylang-project-lib-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let root = std::env::temp_dir().join(project_name);
    std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
    std::fs::write(
        root.join("fozzy.toml"),
        "[package]\nname=\"demo_lib\"\nversion=\"0.1.0\"\n\n[target.lib]\nname=\"demo_lib\"\npath=\"src/lib.fzy\"\n",
    )
    .expect("manifest should be written");
    std::fs::write(
        root.join("src/lib.fzy"),
        "#[ffi_panic(abort)]\npubext c fn add(left: i32, right: i32) -> i32 {\n    return left + right\n}\n",
    )
    .expect("source should be written");

    let artifact = compile_library_with_backend(&root, BuildProfile::Dev, None)
        .expect("library project should compile");
    assert_eq!(artifact.module, "lib");
    assert!(artifact
        .static_lib
        .as_ref()
        .is_some_and(|path| path.exists()));
    assert!(artifact
        .shared_lib
        .as_ref()
        .is_some_and(|path| path.exists()));

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn compile_library_allows_explicit_llvm_backend_override() {
    let project_name = format!(
        "fozzylang-project-lib-llvm-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let root = std::env::temp_dir().join(project_name);
    std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
    std::fs::write(
        root.join("fozzy.toml"),
        "[package]\nname=\"demo_lib\"\nversion=\"0.1.0\"\n\n[target.lib]\nname=\"demo_lib\"\npath=\"src/lib.fzy\"\n",
    )
    .expect("manifest should be written");
    std::fs::write(
        root.join("src/lib.fzy"),
        "#[ffi_panic(abort)]\npubext c fn add(left: i32, right: i32) -> i32 {\n    return left + right\n}\n",
    )
    .expect("source should be written");

    let artifact = compile_library_with_backend(&root, BuildProfile::Release, Some("llvm"))
        .expect("llvm backend override should compile for --lib");
    assert_eq!(artifact.status, "ok");
    assert!(artifact
        .static_lib
        .as_ref()
        .is_some_and(|path| path.exists()));
    assert!(artifact
        .shared_lib
        .as_ref()
        .is_some_and(|path| path.exists()));

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn compile_library_supports_raw_pointer_indexing_and_usize_consts() {
    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock should be after epoch")
        .as_nanos();
    let llvm_root = std::env::temp_dir().join(format!("fozzylang-lib-ptr-llvm-{suffix}"));
    let clif_root = std::env::temp_dir().join(format!("fozzylang-lib-ptr-clif-{suffix}"));
    let manifest =
        "[package]\nname=\"demo_lib\"\nversion=\"0.1.0\"\n\n[target.lib]\nname=\"demo_lib\"\npath=\"src/lib.fzy\"\n";
    let source = "const WEIGHT_COUNT_LEN: usize = 4\n#[ffi_panic(abort)]\npubext c fn head_pair_sum(weights_borrowed: *f32, weights_len: usize) -> f32 {\n    discard weights_len\n    discard WEIGHT_COUNT_LEN\n    return weights_borrowed[0] + weights_borrowed[1]\n}\n";

    for root in [&llvm_root, &clif_root] {
        std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
        std::fs::write(root.join("fozzy.toml"), manifest).expect("manifest should be written");
        std::fs::write(root.join("src/lib.fzy"), source).expect("source should be written");
    }

    let llvm = compile_library_with_backend(&llvm_root, BuildProfile::Release, Some("llvm"))
        .expect("llvm raw pointer indexing library build should succeed");
    assert_eq!(llvm.status, "ok");
    let cranelift = compile_library_with_backend(&clif_root, BuildProfile::Dev, Some("cranelift"))
        .expect("cranelift raw pointer indexing library build should succeed");
    assert_eq!(cranelift.status, "ok");

    let _ = std::fs::remove_dir_all(llvm_root);
    let _ = std::fs::remove_dir_all(clif_root);
}

#[test]
fn compile_library_supports_raw_pointer_indexed_writes() {
    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock should be after epoch")
        .as_nanos();
    let root = std::env::temp_dir().join(format!("fozzylang-lib-ptr-write-{suffix}"));
    std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
    std::fs::write(
        root.join("fozzy.toml"),
        "[package]\nname=\"demo_lib\"\nversion=\"0.1.0\"\n\n[target.lib]\nname=\"demo_lib\"\npath=\"src/lib.fzy\"\n",
    )
    .expect("manifest should be written");
    std::fs::write(
        root.join("src/lib.fzy"),
        "#[ffi_panic(abort)]\npubext c fn poke(out_values_out: *f32, out_values_len: usize) -> i32 {\n    discard out_values_len\n    out_values_out[0] = 1.0f32\n    return 0\n}\n",
    )
    .expect("source should be written");

    let parsed = parse_program(&root.join("src/lib.fzy")).expect("parse should succeed");
    let ((_typed, fir), _) = super::lower_fir_cached_with_metadata(&parsed);
    assert_eq!(fir.type_errors, 0, "{:?}", fir.type_error_details);

    let artifact = compile_library_with_backend(&root, BuildProfile::Dev, Some("cranelift"))
        .expect("raw pointer indexed write library build should succeed");
    assert_eq!(
        artifact.status,
        "ok",
        "{:?}",
        artifact
            .diagnostic_details
            .iter()
            .map(|diagnostic| diagnostic.message.clone())
            .collect::<Vec<_>>()
    );

    let _ = std::fs::remove_dir_all(root);
}

#[cfg(target_vendor = "apple")]
#[test]
fn compile_library_supports_gpu_pointer_upload_helpers_and_kernel_simd_arrays() {
    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock should be after epoch")
        .as_nanos();
    let llvm_root = std::env::temp_dir().join(format!("fozzylang-lib-gpu-neural-llvm-{suffix}"));
    let clif_root = std::env::temp_dir().join(format!("fozzylang-lib-gpu-neural-clif-{suffix}"));
    let manifest =
        "[package]\nname=\"gpu_demo_lib\"\nversion=\"0.1.0\"\n\n[target.lib]\nname=\"gpu_demo_lib\"\npath=\"src/lib.fzy\"\n";
    let source = r#"use core.gpu;
use core.simd;

fn bias(value: f32) -> f32 {
    return value + 1.0f32
}

kernel fn forward(input: GpuSlice<f32>, output: GpuSlice<f32>, n: i32) -> void {
    let i = gpu.global_id_x()
    if i < n {
        let lanes = simd.f32x4_store(simd.f32x4_add(
            simd.f32x4_splat(bias(input[i])),
            simd.f32x4_load([1.0f32, 2.0f32, 3.0f32, 4.0f32]),
        ))
        let mut scratch = [0.0f32, 0.0f32, 0.0f32, 0.0f32]
        scratch[0] = lanes[0]
        output[i] = scratch[0]
    }
}

#[ffi_panic(abort)]
pubext c fn render(weights_borrowed: *f32, weights_len: usize, out_values_out: *f32, out_values_len: usize) -> i32 {
    discard weights_len
    if out_values_len < 4 { return 11 }
    let dev = gpu.default_device()
    let input: GpuBuffer<f32> = gpu.upload_f32(dev, weights_borrowed)
    defer gpu.free(input)
    let output: GpuBuffer<f32> = gpu.alloc_f32(dev, 4)
    defer gpu.free(output)
    let event = gpu.launch3(forward, 4, 64, gpu.slice(input, 0, 4), gpu.slice(output, 0, 4), 4)
    gpu.wait(event)
    let values: Vec<f32> = gpu.download_f32(output)
    let mut idx = 0
    while idx < 4 {
        out_values_out[idx] = values[idx]
        idx = idx + 1
    }
    return 0
}
"#;

    for root in [&llvm_root, &clif_root] {
        std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
        std::fs::write(root.join("fozzy.toml"), manifest).expect("manifest should be written");
        std::fs::write(root.join("src/lib.fzy"), source).expect("source should be written");
    }

    let llvm = compile_library_with_backend(&llvm_root, BuildProfile::Release, Some("llvm"))
        .expect("llvm gpu helper library build should succeed");
    assert_eq!(llvm.status, "ok");
    let cranelift = compile_library_with_backend(&clif_root, BuildProfile::Dev, Some("cranelift"))
        .expect("cranelift gpu helper library build should succeed");
    assert_eq!(cranelift.status, "ok");

    let _ = std::fs::remove_dir_all(llvm_root);
    let _ = std::fs::remove_dir_all(clif_root);
}

#[cfg(target_vendor = "apple")]
#[test]
fn borrowed_gpu_upload_from_ffi_raw_pointer_uses_element_counts_at_runtime() {
    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock should be after epoch")
        .as_nanos();
    let llvm_root =
        std::env::temp_dir().join(format!("fozzylang-lib-gpu-upload-runtime-llvm-{suffix}"));
    let clif_root =
        std::env::temp_dir().join(format!("fozzylang-lib-gpu-upload-runtime-clif-{suffix}"));
    let manifest = "[package]\nname=\"gpu_upload_runtime\"\nversion=\"0.1.0\"\n\n[target.lib]\nname=\"gpu_upload_runtime\"\npath=\"src/lib.fzy\"\n";
    let source = r#"use core.gpu;

#[ffi_panic(abort)]
pubext c fn echo_gpu_upload(weights_borrowed: *f32, weights_len: usize, out_values_out: *f32, out_values_len: usize) -> i32 {
    discard weights_len
    discard out_values_len
    let dev = gpu.default_device()
    let input: GpuBuffer<f32> = gpu.upload_f32(dev, weights_borrowed)
    defer gpu.free(input)
    let values: Vec<f32> = gpu.download_f32(input)
    out_values_out[0] = values[0]
    out_values_out[1] = values[1]
    out_values_out[2] = values[2]
    out_values_out[3] = values[3]
    return 0
}
"#;

    for root in [&llvm_root, &clif_root] {
        std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
        std::fs::write(root.join("fozzy.toml"), manifest).expect("manifest should be written");
        std::fs::write(root.join("src/lib.fzy"), source).expect("source should be written");
    }

    let llvm = compile_library_with_backend(&llvm_root, BuildProfile::Release, Some("llvm"))
        .expect("llvm gpu upload runtime library build should succeed");
    assert_eq!(llvm.status, "ok");
    let cranelift = compile_library_with_backend(&clif_root, BuildProfile::Dev, Some("cranelift"))
        .expect("cranelift gpu upload runtime library build should succeed");
    assert_eq!(cranelift.status, "ok");

    let host_source = r#"
#include <stdint.h>

int32_t echo_gpu_upload(float* weights_borrowed, uintptr_t weights_len, float* out_values_out, uintptr_t out_values_len);

int main(void) {
  float values[4] = {1.0f, 2.0f, 3.0f, 4.0f};
  float out[4] = {0.0f, 0.0f, 0.0f, 0.0f};
  int32_t status = echo_gpu_upload(values, sizeof(values), out, sizeof(out));
  if (status != 0) return 11;
  if (out[0] != 1.0f) return 12;
  if (out[1] != 2.0f) return 13;
  if (out[2] != 3.0f) return 14;
  if (out[3] != 4.0f) return 15;
  return 0;
}
"#;

    compile_and_run_c_host_with_metal(
        host_source,
        llvm.static_lib
            .as_deref()
            .expect("llvm static lib should exist"),
        &llvm_root,
    );
    compile_and_run_c_host_with_metal(
        host_source,
        cranelift
            .static_lib
            .as_deref()
            .expect("cranelift static lib should exist"),
        &clif_root,
    );

    let _ = std::fs::remove_dir_all(llvm_root);
    let _ = std::fs::remove_dir_all(clif_root);
}

#[cfg(target_vendor = "apple")]
#[test]
fn metal_kernel_stmt_discard_of_gpu_slice_lowers_to_noop_without_breaking_launch() {
    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock should be after epoch")
        .as_nanos();
    let clif_root =
        std::env::temp_dir().join(format!("fozzylang-lib-gpu-discard-slice-runtime-{suffix}"));
    let manifest = "[package]\nname=\"gpu_discard_slice_runtime\"\nversion=\"0.1.0\"\n\n[ffi]\npanic_boundary=\"abort\"\n\n[target.lib]\nname=\"gpu_discard_slice_runtime\"\npath=\"src/lib.fzy\"\n";
    let source = r#"use core.gpu;

kernel fn paint(input: GpuSlice<f32>, output: GpuSlice<i32>) -> void {
    let i = gpu.global_id_x()
    let total = gpu.slice_len(output)
    if i < total {
        discard input
        output[i] = 7
    }
}

#[ffi_panic(abort)]
pubext c fn render(values_borrowed: *f32, values_len: usize, out_words_out: *i32, out_words_len: usize) -> i32 {
    discard values_len
    discard out_words_len
    let dev = gpu.default_device()
    let input: GpuBuffer<f32> = gpu.upload_f32(dev, values_borrowed)
    defer gpu.free(input)
    let output: GpuBuffer<i32> = gpu.alloc_i32(dev, 8)
    defer gpu.free(output)
    let event = gpu.launch2(paint, 1, 64, gpu.slice(input, 0, 8), gpu.slice(output, 0, 8))
    gpu.wait(event)
    let words: Vec<i32> = gpu.download_i32(output)
    out_words_out[0] = words[0]
    out_words_out[1] = words[1]
    out_words_out[2] = words[2]
    out_words_out[3] = words[3]
    return 0
}
"#;

    std::fs::create_dir_all(clif_root.join("src")).expect("project dir should be created");
    std::fs::write(clif_root.join("fozzy.toml"), manifest).expect("manifest should be written");
    std::fs::write(clif_root.join("src/lib.fzy"), source).expect("source should be written");

    let cranelift = compile_library_with_backend(&clif_root, BuildProfile::Dev, Some("cranelift"))
        .expect("cranelift discard-slice runtime library build should succeed");
    assert_eq!(cranelift.status, "ok");

    let host_source = r#"
#include <stdint.h>

int32_t render(float* values_borrowed, uintptr_t values_len, int32_t* out_words_out, uintptr_t out_words_len);

int main(void) {
  float values[8] = {0.0f, 1.0f, 2.0f, 3.0f, 4.0f, 5.0f, 6.0f, 7.0f};
  int32_t out[4] = {0, 0, 0, 0};
  int32_t status = render(values, sizeof(values), out, sizeof(out));
  if (status != 0) return 11;
  if (out[0] != 7) return 12;
  if (out[1] != 7) return 13;
  if (out[2] != 7) return 14;
  if (out[3] != 7) return 15;
  return 0;
}
"#;

    compile_and_run_c_host_with_metal(
        host_source,
        cranelift
            .static_lib
            .as_deref()
            .expect("cranelift static lib should exist"),
        &clif_root,
    );

    let _ = std::fs::remove_dir_all(clif_root);
}

#[cfg(target_vendor = "apple")]
#[test]
fn gpu_download_u32_large_readback_survives_multi_threadgroup_launch() {
    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock should be after epoch")
        .as_nanos();
    let clif_root =
        std::env::temp_dir().join(format!("fozzylang-lib-gpu-large-u32-readback-{suffix}"));
    let manifest = "[package]\nname=\"gpu_large_u32_readback\"\nversion=\"0.1.0\"\n\n[ffi]\npanic_boundary=\"abort\"\n\n[target.lib]\nname=\"gpu_large_u32_readback\"\npath=\"src/lib.fzy\"\n";
    let source = r#"use core.gpu;

kernel fn paint(output: GpuSlice<u32>, n: i32) -> void {
    let i = gpu.global_id_x()
    if i < n {
        output[i] = 255 + ((i + 1) << 8)
    }
}

#[ffi_panic(abort)]
pubext c fn run(out_rgba_out: *u32, out_rgba_len: usize, out_count: i32) -> i32 {
    discard out_rgba_len
    let dev = gpu.default_device()
    let output: GpuBuffer<u32> = gpu.alloc_u32(dev, out_count)
    defer gpu.free(output)
    let event = gpu.launch2(paint, ((out_count + 63) / 64), 64, gpu.slice(output, 0, out_count), out_count)
    gpu.wait(event)
    let words: Vec<u32> = gpu.download_u32(output)
    let mut idx = 0
    while idx < out_count {
        out_rgba_out[idx] = words[idx]
        idx = idx + 1
    }
    return 0
}
"#;

    std::fs::create_dir_all(clif_root.join("src")).expect("project dir should be created");
    std::fs::write(clif_root.join("fozzy.toml"), manifest).expect("manifest should be written");
    std::fs::write(clif_root.join("src/lib.fzy"), source).expect("source should be written");

    let cranelift = compile_library_with_backend(&clif_root, BuildProfile::Dev, Some("cranelift"))
        .expect("cranelift large u32 readback library build should succeed");
    assert_eq!(cranelift.status, "ok");

    let host_source = r#"
#include <stdint.h>

int32_t run(uint32_t* out_rgba_out, uintptr_t out_rgba_len, int32_t out_count);

int main(void) {
  static uint32_t out[12544];
  int32_t status = run(out, sizeof(out), 12544);
  if (status != 0) return 11;
  if (out[0] != 511u) return 12;
  if (out[1] != 767u) return 13;
  if (out[4095] != (uint32_t)(255 + ((4095 + 1) << 8))) return 14;
  if (out[12543] != (uint32_t)(255 + ((12543 + 1) << 8))) return 15;
  return 0;
}
"#;

    compile_and_run_c_host_with_metal(
        host_source,
        cranelift
            .static_lib
            .as_deref()
            .expect("cranelift static lib should exist"),
        &clif_root,
    );

    let _ = std::fs::remove_dir_all(clif_root);
}

#[test]
fn compile_library_allows_async_c_exports_with_default_release_backend() {
    let project_name = format!(
        "fozzylang-project-lib-async-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );
    let root = std::env::temp_dir().join(project_name);
    std::fs::create_dir_all(root.join("src")).expect("project dir should be created");
    std::fs::write(
        root.join("fozzy.toml"),
        "[package]\nname=\"demo_lib\"\nversion=\"0.1.0\"\n\n[target.lib]\nname=\"demo_lib\"\npath=\"src/lib.fzy\"\n",
    )
    .expect("manifest should be written");
    std::fs::write(
        root.join("src/lib.fzy"),
        "use core.thread;\n#[ffi_panic(abort)]\npubext async c fn flush(code: i32) -> i32 {\n    checkpoint();\n    return code\n}\n",
    )
    .expect("source should be written");

    let artifact = compile_library_with_backend(&root, BuildProfile::Release, None)
        .expect("library project should compile");
    assert_eq!(artifact.status, "ok");
    assert!(artifact
        .static_lib
        .as_ref()
        .is_some_and(|path| path.exists()));
    assert!(artifact
        .shared_lib
        .as_ref()
        .is_some_and(|path| path.exists()));

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn llvm_lowering_declares_extern_c_import_without_defining_stub() {
    let source = "ext c fn c_add(left: i32, right: i32) -> i32;\nfn main() -> i32 {\n    return c_add(1, 2)\n}\n";
    let module = parser::parse(source, "ffi_import").expect("source should parse");
    let typed = hir::lower(&module);
    let fir = fir::build_owned(typed);
    let ir = lower_llvm_ir(&fir, true).expect("llvm lowering should succeed");
    assert!(ir.contains("declare i32 @c_add(i32, i32)"));
    assert!(!ir.contains("define i32 @c_add("));
}

#[test]
fn llvm_lowering_uses_native_aggregate_handles_for_aggregate_literals() {
    let source = "struct Pair { left: i32, right: i32 }\nenum Maybe { Some(i32), None }\nfn main() -> i32 {\n    let pair = Pair { left: 3, right: 4 }\n    let tagged = Maybe::Some(9)\n    let tupled = (1, 2)\n    discard pair\n    discard tagged\n    discard tupled\n    return 0\n}\n";
    let module = parser::parse(source, "agg_handles").expect("source should parse");
    let typed = hir::lower(&module);
    let fir = fir::build_owned(typed);
    let ir = lower_llvm_ir(&fir, true).expect("llvm lowering should succeed");
    assert!(ir.contains("declare i64 @fz_native_agg_new(i32, i32)"));
    assert!(ir.contains("call i64 @fz_native_agg_new("));
    assert!(ir.contains("call i32 @fz_native_agg_set_i64("));
}

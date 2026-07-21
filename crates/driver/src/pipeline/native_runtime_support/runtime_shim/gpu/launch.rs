pub(super) fn section() -> &'static str {
    r#"
static int fz_gpu_slice_unpack(uintptr_t slice_handle, int32_t* out_buffer, int32_t* out_offset, int32_t* out_len) {
  if (slice_handle == 0 || fz_native_agg_tag((uint64_t)slice_handle) != FZ_GPU_SLICE_TAG) {
    return -1;
  }
  *out_buffer = (int32_t)fz_native_agg_get_i64((uint64_t)slice_handle, 0);
  *out_offset = (int32_t)fz_native_agg_get_i64((uint64_t)slice_handle, 1);
  *out_len = (int32_t)fz_native_agg_get_i64((uint64_t)slice_handle, 2);
  return 0;
}

#if defined(__APPLE__) && defined(__OBJC__)
static id<MTLComputePipelineState> fz_gpu_pipeline_for_kernel(
    int32_t device_handle,
    int32_t source_id,
    int32_t kernel_name_id
) {
  for (int i = 0; i < FZ_MAX_GPU_PIPELINES; i++) {
    fz_gpu_pipeline_state* state = &fz_gpu_pipelines[i];
    if (state->in_use
        && state->device_handle == device_handle
        && state->source_id == source_id
        && state->kernel_name_id == kernel_name_id
        && state->pipeline != NULL) {
      state->last_used_epoch = ++fz_gpu_pipeline_epoch;
      return (id<MTLComputePipelineState>)state->pipeline;
    }
  }
  id<MTLDevice> device = fz_gpu_device_for_handle(device_handle);
  if (device == nil) {
    fz_set_last_error(EINVAL, 3, "gpu.launch failed: invalid device handle");
    return nil;
  }
  const char* source_c = (const char*)fz_native_str_ptr(source_id);
  const char* kernel_c = (const char*)fz_native_str_ptr(kernel_name_id);
  if (source_c == NULL || kernel_c == NULL || source_c[0] == '\0' || kernel_c[0] == '\0') {
    fz_set_last_error(EINVAL, 3, "gpu.launch failed: missing kernel source or name");
    return nil;
  }
  NSString* source = [NSString stringWithUTF8String:source_c];
  NSString* kernel = [NSString stringWithUTF8String:kernel_c];
  if (source == nil || kernel == nil) {
    fz_set_last_error(EINVAL, 3, "gpu.launch failed: could not decode kernel source or name");
    return nil;
  }
  NSError* error = nil;
  id<MTLLibrary> library = [device newLibraryWithSource:source options:nil error:&error];
  if (library == nil) {
    const char* detail = error == nil ? "unknown Metal library compile error" : [[error localizedDescription] UTF8String];
    fz_set_last_error(EINVAL, 3, detail == NULL ? "gpu.launch failed: Metal library compile failed" : detail);
    return nil;
  }
  id<MTLFunction> function = [library newFunctionWithName:kernel];
  if (function == nil) {
    [library release];
    fz_set_last_error(EINVAL, 3, "gpu.launch failed: Metal kernel entry was not found");
    return nil;
  }
  id<MTLComputePipelineState> pipeline = [device newComputePipelineStateWithFunction:function error:&error];
  [function release];
  [library release];
  if (pipeline == nil) {
    const char* detail = error == nil ? "unknown Metal pipeline compile error" : [[error localizedDescription] UTF8String];
    fz_set_last_error(EINVAL, 3, detail == NULL ? "gpu.launch failed: Metal pipeline creation failed" : detail);
    return nil;
  }
  int32_t slot = fz_gpu_pipeline_alloc_slot();
  if (slot <= 0) {
    slot = fz_gpu_pipeline_evict_lru_slot();
    if (slot <= 0) {
      [pipeline release];
      fz_set_last_error(ENOSPC, 3, "gpu.launch failed: GPU pipeline registry full and no reusable slot was available");
      return nil;
    }
  }
  fz_gpu_pipeline_state* state = &fz_gpu_pipelines[slot - 1];
  state->device_handle = device_handle;
  state->source_id = source_id;
  state->kernel_name_id = kernel_name_id;
  state->last_used_epoch = ++fz_gpu_pipeline_epoch;
  state->pipeline = (void*)pipeline;
  return pipeline;
}

static int32_t fz_gpu_launch_impl(
    int32_t kernel_name_id,
    int32_t source_id,
    int32_t layout_id,
    int32_t grid,
    int32_t block,
    int argc,
    uintptr_t a0,
    uintptr_t a1,
    uintptr_t a2,
    uintptr_t a3
) {
  pthread_once(&fz_gpu_init_once, fz_gpu_runtime_init);
  if (grid <= 0 || block <= 0) {
    fz_set_last_error(EINVAL, 3, "gpu.launch failed: grid and block must be > 0");
    return 0;
  }
  const char* layout = (const char*)fz_native_str_ptr(layout_id);
  if (layout == NULL || layout[0] == '\0') {
    fz_set_last_error(EINVAL, 3, "gpu.launch failed: missing launch layout");
    return 0;
  }
  uintptr_t raw_args[4] = {a0, a1, a2, a3};
  const char* token = layout;
  int32_t device_handle = 0;
  int32_t slice_buffers[4] = {0, 0, 0, 0};
  int32_t slice_offsets[4] = {0, 0, 0, 0};
  int32_t slice_lens[4] = {0, 0, 0, 0};
  int32_t slice_element_sizes[4] = {0, 0, 0, 0};
  int slice_count = 0;
  for (int arg = 0; arg < argc; arg++) {
    const char* next = strchr(token, ',');
    size_t token_len = next == NULL ? strlen(token) : (size_t)(next - token);
    if (token_len == 0) {
      fz_set_last_error(EINVAL, 3, "gpu.launch failed: malformed launch layout");
      return 0;
    }
    if (token_len >= 6 && strncmp(token, "slice_", 6) == 0) {
      if (slice_count >= 4) {
        fz_set_last_error(EINVAL, 3, "gpu.launch failed: more than 4 slice args are unsupported");
        return 0;
      }
      if (fz_gpu_slice_unpack(raw_args[arg], &slice_buffers[slice_count], &slice_offsets[slice_count], &slice_lens[slice_count]) != 0) {
        fz_set_last_error(EINVAL, 3, "gpu.launch failed: expected a GpuSlice launch argument");
        return 0;
      }
      if (slice_buffers[slice_count] <= 0 || slice_buffers[slice_count] > FZ_MAX_GPU_BUFFERS) {
        fz_set_last_error(EINVAL, 3, "gpu.launch failed: invalid slice buffer handle");
        return 0;
      }
      fz_gpu_buffer_state* buffer_state = &fz_gpu_buffers[slice_buffers[slice_count] - 1];
      if (!buffer_state->in_use || buffer_state->buffer == NULL) {
        fz_set_last_error(EINVAL, 3, "gpu.launch failed: invalid slice buffer handle");
        return 0;
      }
      slice_element_sizes[arg] = buffer_state->element_size;
      if (device_handle == 0) {
        device_handle = buffer_state->device_handle;
      } else if (device_handle != buffer_state->device_handle) {
        fz_set_last_error(EINVAL, 3, "gpu.launch failed: all GPU slices must target the same device");
        return 0;
      }
      slice_count++;
    }
    token = next == NULL ? token + token_len : next + 1;
  }
  if (device_handle == 0) {
    device_handle = fz_native_gpu_default_device();
    if (device_handle == 0) {
      return 0;
    }
  }
  @autoreleasepool {
    id<MTLCommandQueue> queue = fz_gpu_queue_for_device(device_handle);
    if (queue == nil) {
      fz_set_last_error(EIO, 3, "gpu.launch failed: could not allocate Metal command queue");
      return 0;
    }
    id<MTLComputePipelineState> pipeline = fz_gpu_pipeline_for_kernel(device_handle, source_id, kernel_name_id);
    if (pipeline == nil) {
      return 0;
    }
    if ((NSUInteger)block > [pipeline maxTotalThreadsPerThreadgroup]) {
      char detail[160];
      snprintf(
          detail,
          sizeof(detail),
          "gpu.launch failed: block %d exceeds Metal max threads-per-threadgroup %lu",
          block,
          (unsigned long)[pipeline maxTotalThreadsPerThreadgroup]);
      fz_set_last_error(EINVAL, 3, detail);
      return 0;
    }
    id<MTLCommandBuffer> command_buffer = [queue commandBuffer];
    if (command_buffer == nil) {
      fz_set_last_error(EIO, 3, "gpu.launch failed: could not create Metal command buffer");
      return 0;
    }
    id<MTLComputeCommandEncoder> encoder = [command_buffer computeCommandEncoder];
    if (encoder == nil) {
      fz_set_last_error(EIO, 3, "gpu.launch failed: could not create Metal compute encoder");
      return 0;
    }
    [encoder setComputePipelineState:pipeline];
    token = layout;
    NSUInteger buffer_index = 0;
    for (int arg = 0; arg < argc; arg++) {
      const char* next = strchr(token, ',');
      size_t token_len = next == NULL ? strlen(token) : (size_t)(next - token);
      if (token_len >= 6 && strncmp(token, "slice_", 6) == 0) {
        int32_t buffer_handle = 0;
        int32_t offset = 0;
        int32_t len = 0;
        if (fz_gpu_slice_unpack(raw_args[arg], &buffer_handle, &offset, &len) != 0) {
          [encoder endEncoding];
          fz_set_last_error(EINVAL, 3, "gpu.launch failed: expected a GpuSlice launch argument");
          return 0;
        }
        id<MTLBuffer> buffer = fz_gpu_buffer_for_handle(buffer_handle);
        if (buffer == nil) {
          [encoder endEncoding];
          fz_set_last_error(EINVAL, 3, "gpu.launch failed: invalid slice buffer handle");
          return 0;
        }
        NSUInteger byte_offset = (NSUInteger)((uint64_t)(uint32_t)offset * (uint64_t)(uint32_t)slice_element_sizes[arg]);
        uint32_t len_u = (uint32_t)len;
        [encoder setBuffer:buffer offset:byte_offset atIndex:buffer_index++];
        [encoder setBytes:&len_u length:sizeof(uint32_t) atIndex:buffer_index++];
      } else if (token_len == 3 && strncmp(token, "i32", 3) == 0) {
        int32_t value = (int32_t)raw_args[arg];
        [encoder setBytes:&value length:sizeof(int32_t) atIndex:buffer_index++];
      } else if (token_len == 3 && strncmp(token, "u32", 3) == 0) {
        uint32_t value = (uint32_t)raw_args[arg];
        [encoder setBytes:&value length:sizeof(uint32_t) atIndex:buffer_index++];
      } else if (token_len == 3 && strncmp(token, "f32", 3) == 0) {
        union { uint32_t bits; float value; } cast;
        cast.bits = (uint32_t)raw_args[arg];
        [encoder setBytes:&cast.value length:sizeof(float) atIndex:buffer_index++];
      } else {
        [encoder endEncoding];
        fz_set_last_error(EINVAL, 3, "gpu.launch failed: unsupported Metal launch param layout");
        return 0;
      }
      token = next == NULL ? token + token_len : next + 1;
    }
    MTLSize threads_per_threadgroup = MTLSizeMake((NSUInteger)block, 1, 1);
    MTLSize threadgroups_per_grid = MTLSizeMake((NSUInteger)grid, 1, 1);
    [encoder dispatchThreadgroups:threadgroups_per_grid threadsPerThreadgroup:threads_per_threadgroup];
    [encoder endEncoding];
    [command_buffer retain];
    [command_buffer commit];
    pthread_mutex_lock(&fz_gpu_lock);
    int32_t event_handle = fz_gpu_event_alloc_slot();
    if (event_handle > 0) {
      fz_gpu_event_state* event = &fz_gpu_events[event_handle - 1];
      event->device_handle = device_handle;
      event->command_buffer = (void*)command_buffer;
    }
    pthread_mutex_unlock(&fz_gpu_lock);
    if (event_handle <= 0) {
      [command_buffer release];
      fz_set_last_error(ENOSPC, 3, "gpu.launch failed: GPU event registry full");
      return 0;
    }
    fz_set_last_error(0, 0, "");
    return event_handle;
  }
}
#elif defined(__linux__) && defined(FZ_GPU_BACKEND_ROCM)
static fz_gpu_pipeline_state* fz_gpu_pipeline_for_kernel(
    int32_t device_handle,
    int32_t source_id,
    int32_t kernel_name_id
) {
  for (int i = 0; i < FZ_MAX_GPU_PIPELINES; i++) {
    fz_gpu_pipeline_state* state = &fz_gpu_pipelines[i];
    if (state->in_use
        && state->device_handle == device_handle
        && state->source_id == source_id
        && state->kernel_name_id == kernel_name_id
        && state->pipeline != NULL
        && state->module != NULL) {
      state->last_used_epoch = ++fz_gpu_pipeline_epoch;
      return state;
    }
  }
  int device = 0;
  if (fz_gpu_hip_device_index_for_handle(device_handle, &device) != 0) {
    fz_set_last_error(EINVAL, 3, "gpu.launch failed: invalid device handle");
    return NULL;
  }
  const char* source_c = (const char*)fz_native_str_ptr(source_id);
  const char* kernel_c = (const char*)fz_native_str_ptr(kernel_name_id);
  if (source_c == NULL || kernel_c == NULL || source_c[0] == '\0' || kernel_c[0] == '\0') {
    fz_set_last_error(EINVAL, 3, "gpu.launch failed: missing kernel source or name");
    return NULL;
  }
  fz_hip_error_t hip_status = fz_hip.hipSetDevice(device);
  if (hip_status != FZ_HIP_SUCCESS) {
    fz_set_last_error(EIO, 3, fz_gpu_hip_error_string(hip_status));
    return NULL;
  }
  fz_hiprtc_program_t program = NULL;
  fz_hiprtc_result_t rtc_status = fz_hip.hiprtcCreateProgram(&program, source_c, "fz_kernel.hip", 0, NULL, NULL);
  if (rtc_status != FZ_HIPRTC_SUCCESS || program == NULL) {
    fz_set_last_error(EINVAL, 3, "gpu.launch failed: hiprtc program creation failed");
    return NULL;
  }
  const char* arch = getenv("FZ_GPU_ROCM_ARCH");
  const char* options[3];
  int option_count = 0;
  char arch_option[96];
  options[option_count++] = "--std=c++17";
  if (arch != NULL && arch[0] != '\0') {
    snprintf(arch_option, sizeof(arch_option), "--gpu-architecture=%s", arch);
    options[option_count++] = arch_option;
  }
  rtc_status = fz_hip.hiprtcCompileProgram(program, option_count, options);
  if (rtc_status != FZ_HIPRTC_SUCCESS) {
    size_t log_size = 0;
    fz_hip.hiprtcGetProgramLogSize(program, &log_size);
    char* log = NULL;
    if (log_size > 0) {
      log = (char*)malloc(log_size + 1);
      if (log != NULL) {
        memset(log, 0, log_size + 1);
        fz_hip.hiprtcGetProgramLog(program, log);
      }
    }
    fz_set_last_error(EINVAL, 3, log == NULL ? "gpu.launch failed: hiprtc compile failed" : log);
    free(log);
    fz_hip.hiprtcDestroyProgram(&program);
    return NULL;
  }
  size_t code_size = 0;
  rtc_status = fz_hip.hiprtcGetCodeSize(program, &code_size);
  if (rtc_status != FZ_HIPRTC_SUCCESS || code_size == 0) {
    fz_set_last_error(EINVAL, 3, "gpu.launch failed: hiprtc returned no code");
    fz_hip.hiprtcDestroyProgram(&program);
    return NULL;
  }
  char* code = (char*)malloc(code_size);
  if (code == NULL) {
    fz_set_last_error(ENOMEM, 3, "gpu.launch failed: HIP code allocation failed");
    fz_hip.hiprtcDestroyProgram(&program);
    return NULL;
  }
  rtc_status = fz_hip.hiprtcGetCode(program, code);
  fz_hip.hiprtcDestroyProgram(&program);
  if (rtc_status != FZ_HIPRTC_SUCCESS) {
    free(code);
    fz_set_last_error(EINVAL, 3, "gpu.launch failed: hiprtc code extraction failed");
    return NULL;
  }
  fz_hip_module_t module = NULL;
  fz_hip_function_t function = NULL;
  hip_status = fz_hip.hipModuleLoadData(&module, code);
  free(code);
  if (hip_status != FZ_HIP_SUCCESS || module == NULL) {
    fz_set_last_error(EINVAL, 3, fz_gpu_hip_error_string(hip_status));
    return NULL;
  }
  hip_status = fz_hip.hipModuleGetFunction(&function, module, kernel_c);
  if (hip_status != FZ_HIP_SUCCESS || function == NULL) {
    fz_hip.hipModuleUnload(module);
    fz_set_last_error(EINVAL, 3, fz_gpu_hip_error_string(hip_status));
    return NULL;
  }
  int32_t slot = fz_gpu_pipeline_alloc_slot();
  if (slot <= 0) {
    slot = fz_gpu_pipeline_evict_lru_slot();
    if (slot <= 0) {
      fz_hip.hipModuleUnload(module);
      fz_set_last_error(ENOSPC, 3, "gpu.launch failed: GPU pipeline registry full and no reusable slot was available");
      return NULL;
    }
  }
  fz_gpu_pipeline_state* state = &fz_gpu_pipelines[slot - 1];
  state->device_handle = device_handle;
  state->source_id = source_id;
  state->kernel_name_id = kernel_name_id;
  state->last_used_epoch = ++fz_gpu_pipeline_epoch;
  state->pipeline = function;
  state->module = module;
  return state;
}

static int32_t fz_gpu_launch_impl(
    int32_t kernel_name_id,
    int32_t source_id,
    int32_t layout_id,
    int32_t grid,
    int32_t block,
    int argc,
    uintptr_t a0,
    uintptr_t a1,
    uintptr_t a2,
    uintptr_t a3
) {
  pthread_once(&fz_gpu_init_once, fz_gpu_runtime_init);
  if (grid <= 0 || block <= 0) {
    fz_set_last_error(EINVAL, 3, "gpu.launch failed: grid and block must be > 0");
    return 0;
  }
  const char* layout = (const char*)fz_native_str_ptr(layout_id);
  if (layout == NULL || layout[0] == '\0') {
    fz_set_last_error(EINVAL, 3, "gpu.launch failed: missing launch layout");
    return 0;
  }
  uintptr_t raw_args[4] = {a0, a1, a2, a3};
  const char* token = layout;
  int32_t device_handle = 0;
  int32_t slice_buffers[4] = {0, 0, 0, 0};
  int32_t slice_offsets[4] = {0, 0, 0, 0};
  int32_t slice_lens[4] = {0, 0, 0, 0};
  int32_t slice_element_sizes[4] = {0, 0, 0, 0};
  int slice_count = 0;
  for (int arg = 0; arg < argc; arg++) {
    const char* next = strchr(token, ',');
    size_t token_len = next == NULL ? strlen(token) : (size_t)(next - token);
    if (token_len == 0) {
      fz_set_last_error(EINVAL, 3, "gpu.launch failed: malformed launch layout");
      return 0;
    }
    if (token_len >= 6 && strncmp(token, "slice_", 6) == 0) {
      if (slice_count >= 4) {
        fz_set_last_error(EINVAL, 3, "gpu.launch failed: more than 4 slice args are unsupported");
        return 0;
      }
      if (fz_gpu_slice_unpack(raw_args[arg], &slice_buffers[slice_count], &slice_offsets[slice_count], &slice_lens[slice_count]) != 0) {
        fz_set_last_error(EINVAL, 3, "gpu.launch failed: expected a GpuSlice launch argument");
        return 0;
      }
      if (slice_buffers[slice_count] <= 0 || slice_buffers[slice_count] > FZ_MAX_GPU_BUFFERS) {
        fz_set_last_error(EINVAL, 3, "gpu.launch failed: invalid slice buffer handle");
        return 0;
      }
      fz_gpu_buffer_state* buffer_state = &fz_gpu_buffers[slice_buffers[slice_count] - 1];
      if (!buffer_state->in_use || buffer_state->buffer == NULL) {
        fz_set_last_error(EINVAL, 3, "gpu.launch failed: invalid slice buffer handle");
        return 0;
      }
      slice_element_sizes[arg] = buffer_state->element_size;
      if (device_handle == 0) {
        device_handle = buffer_state->device_handle;
      } else if (device_handle != buffer_state->device_handle) {
        fz_set_last_error(EINVAL, 3, "gpu.launch failed: all GPU slices must target the same device");
        return 0;
      }
      slice_count++;
    }
    token = next == NULL ? token + token_len : next + 1;
  }
  if (device_handle == 0) {
    device_handle = fz_native_gpu_default_device();
    if (device_handle == 0) {
      return 0;
    }
  }
  int device = 0;
  if (fz_gpu_hip_device_index_for_handle(device_handle, &device) != 0) {
    fz_set_last_error(EINVAL, 3, "gpu.launch failed: invalid device handle");
    return 0;
  }
  fz_hip_error_t status = fz_hip.hipSetDevice(device);
  if (status != FZ_HIP_SUCCESS) {
    fz_set_last_error(EIO, 3, fz_gpu_hip_error_string(status));
    return 0;
  }
  fz_gpu_pipeline_state* pipeline = fz_gpu_pipeline_for_kernel(device_handle, source_id, kernel_name_id);
  if (pipeline == NULL) {
    return 0;
  }

  void* kernel_params[8];
  int kernel_param_count = 0;
  void* data_ptrs[4];
  uint32_t len_values[4];
  int32_t i32_values[4];
  uint32_t u32_values[4];
  float f32_values[4];
  int slice_arg = 0;
  int i32_arg = 0;
  int u32_arg = 0;
  int f32_arg = 0;
  token = layout;
  for (int arg = 0; arg < argc; arg++) {
    const char* next = strchr(token, ',');
    size_t token_len = next == NULL ? strlen(token) : (size_t)(next - token);
    if (token_len >= 6 && strncmp(token, "slice_", 6) == 0) {
      int32_t buffer_handle = 0;
      int32_t offset = 0;
      int32_t len = 0;
      if (fz_gpu_slice_unpack(raw_args[arg], &buffer_handle, &offset, &len) != 0) {
        fz_set_last_error(EINVAL, 3, "gpu.launch failed: expected a GpuSlice launch argument");
        return 0;
      }
      fz_gpu_buffer_state* buffer_state = &fz_gpu_buffers[buffer_handle - 1];
      uintptr_t base = (uintptr_t)buffer_state->buffer;
      uintptr_t byte_offset = (uintptr_t)((uint64_t)(uint32_t)offset * (uint64_t)(uint32_t)slice_element_sizes[arg]);
      data_ptrs[slice_arg] = (void*)(base + byte_offset);
      len_values[slice_arg] = (uint32_t)len;
      kernel_params[kernel_param_count++] = &data_ptrs[slice_arg];
      kernel_params[kernel_param_count++] = &len_values[slice_arg];
      slice_arg++;
    } else if (token_len == 3 && strncmp(token, "i32", 3) == 0) {
      i32_values[i32_arg] = (int32_t)raw_args[arg];
      kernel_params[kernel_param_count++] = &i32_values[i32_arg++];
    } else if (token_len == 3 && strncmp(token, "u32", 3) == 0) {
      u32_values[u32_arg] = (uint32_t)raw_args[arg];
      kernel_params[kernel_param_count++] = &u32_values[u32_arg++];
    } else if (token_len == 3 && strncmp(token, "f32", 3) == 0) {
      union { uint32_t bits; float value; } cast;
      cast.bits = (uint32_t)raw_args[arg];
      f32_values[f32_arg] = cast.value;
      kernel_params[kernel_param_count++] = &f32_values[f32_arg++];
    } else {
      fz_set_last_error(EINVAL, 3, "gpu.launch failed: unsupported ROCm launch param layout");
      return 0;
    }
    token = next == NULL ? token + token_len : next + 1;
  }

  fz_hip_stream_t stream = NULL;
  status = fz_hip.hipStreamCreate(&stream);
  if (status != FZ_HIP_SUCCESS || stream == NULL) {
    fz_set_last_error(EIO, 3, fz_gpu_hip_error_string(status));
    return 0;
  }
  status = fz_hip.hipModuleLaunchKernel(
      (fz_hip_function_t)pipeline->pipeline,
      (unsigned int)grid, 1, 1,
      (unsigned int)block, 1, 1,
      0,
      stream,
      kernel_params,
      NULL);
  if (status != FZ_HIP_SUCCESS) {
    fz_hip.hipStreamDestroy(stream);
    fz_set_last_error(EIO, 3, fz_gpu_hip_error_string(status));
    return 0;
  }
  pthread_mutex_lock(&fz_gpu_lock);
  int32_t event_handle = fz_gpu_event_alloc_slot();
  if (event_handle > 0) {
    fz_gpu_event_state* event = &fz_gpu_events[event_handle - 1];
    event->device_handle = device_handle;
    event->command_buffer = stream;
  }
  pthread_mutex_unlock(&fz_gpu_lock);
  if (event_handle <= 0) {
    fz_hip.hipStreamDestroy(stream);
    fz_set_last_error(ENOSPC, 3, "gpu.launch failed: GPU event registry full");
    return 0;
  }
  fz_set_last_error(0, 0, "");
  return event_handle;
}
#elif defined(__linux__) && defined(FZ_GPU_BACKEND_CUDA)
static fz_gpu_pipeline_state* fz_gpu_pipeline_for_kernel(
    int32_t device_handle,
    int32_t source_id,
    int32_t kernel_name_id
) {
  for (int i = 0; i < FZ_MAX_GPU_PIPELINES; i++) {
    fz_gpu_pipeline_state* state = &fz_gpu_pipelines[i];
    if (state->in_use
        && state->device_handle == device_handle
        && state->source_id == source_id
        && state->kernel_name_id == kernel_name_id
        && state->pipeline != NULL
        && state->module != NULL) {
      state->last_used_epoch = ++fz_gpu_pipeline_epoch;
      return state;
    }
  }
  fz_cuda_device_t device = 0;
  fz_cuda_context_t context = NULL;
  if (fz_gpu_cuda_device_for_handle(device_handle, &device, &context) != 0) {
    fz_set_last_error(EINVAL, 3, "gpu.launch failed: invalid device handle");
    return NULL;
  }
  const char* source_c = (const char*)fz_native_str_ptr(source_id);
  const char* kernel_c = (const char*)fz_native_str_ptr(kernel_name_id);
  if (source_c == NULL || kernel_c == NULL || source_c[0] == '\0' || kernel_c[0] == '\0') {
    fz_set_last_error(EINVAL, 3, "gpu.launch failed: missing kernel source or name");
    return NULL;
  }
  fz_cuda_result_t cuda_status = fz_cuda.cuCtxSetCurrent(context);
  if (cuda_status != FZ_CUDA_SUCCESS) {
    fz_set_last_error(EIO, 3, fz_gpu_cuda_error_string(cuda_status));
    return NULL;
  }
  fz_cuda_module_t module = NULL;
  fz_cuda_function_t function = NULL;
#if defined(FZ_GPU_BACKEND_NVPTX)
  cuda_status = fz_cuda.cuModuleLoadData(&module, source_c);
  if (cuda_status != FZ_CUDA_SUCCESS || module == NULL) {
    fz_set_last_error(EINVAL, 3, fz_gpu_cuda_error_string(cuda_status));
    return NULL;
  }
#else
  fz_nvrtc_program_t program = NULL;
  fz_nvrtc_result_t rtc_status = fz_cuda.nvrtcCreateProgram(&program, source_c, "fz_kernel.cu", 0, NULL, NULL);
  if (rtc_status != FZ_NVRTC_SUCCESS || program == NULL) {
    fz_set_last_error(EINVAL, 3, "gpu.launch failed: nvrtc program creation failed");
    return NULL;
  }
  const char* arch = getenv("FZ_GPU_CUDA_ARCH");
  const char* options[3];
  int option_count = 0;
  char arch_option[96];
  options[option_count++] = "--std=c++17";
  if (arch != NULL && arch[0] != '\0') {
    if (strncmp(arch, "compute_", 8) == 0 || strncmp(arch, "sm_", 3) == 0) {
      snprintf(arch_option, sizeof(arch_option), "--gpu-architecture=%s", arch);
    } else {
      snprintf(arch_option, sizeof(arch_option), "--gpu-architecture=compute_%s", arch);
    }
    options[option_count++] = arch_option;
  } else {
    int major = 0;
    int minor = 0;
    if (fz_cuda.cuDeviceGetAttribute(&major, FZ_CUDA_DEVICE_ATTRIBUTE_COMPUTE_CAPABILITY_MAJOR, device) == FZ_CUDA_SUCCESS
        && fz_cuda.cuDeviceGetAttribute(&minor, FZ_CUDA_DEVICE_ATTRIBUTE_COMPUTE_CAPABILITY_MINOR, device) == FZ_CUDA_SUCCESS
        && major > 0) {
      snprintf(arch_option, sizeof(arch_option), "--gpu-architecture=compute_%d%d", major, minor);
      options[option_count++] = arch_option;
    }
  }
  rtc_status = fz_cuda.nvrtcCompileProgram(program, option_count, options);
  if (rtc_status != FZ_NVRTC_SUCCESS) {
    size_t log_size = 0;
    fz_cuda.nvrtcGetProgramLogSize(program, &log_size);
    char* log = NULL;
    if (log_size > 0) {
      log = (char*)malloc(log_size + 1);
      if (log != NULL) {
        memset(log, 0, log_size + 1);
        fz_cuda.nvrtcGetProgramLog(program, log);
      }
    }
    fz_set_last_error(EINVAL, 3, log == NULL ? "gpu.launch failed: nvrtc compile failed" : log);
    free(log);
    fz_cuda.nvrtcDestroyProgram(&program);
    return NULL;
  }
  size_t ptx_size = 0;
  rtc_status = fz_cuda.nvrtcGetPTXSize(program, &ptx_size);
  if (rtc_status != FZ_NVRTC_SUCCESS || ptx_size == 0) {
    fz_set_last_error(EINVAL, 3, "gpu.launch failed: nvrtc returned no PTX");
    fz_cuda.nvrtcDestroyProgram(&program);
    return NULL;
  }
  char* ptx = (char*)malloc(ptx_size);
  if (ptx == NULL) {
    fz_set_last_error(ENOMEM, 3, "gpu.launch failed: CUDA PTX allocation failed");
    fz_cuda.nvrtcDestroyProgram(&program);
    return NULL;
  }
  rtc_status = fz_cuda.nvrtcGetPTX(program, ptx);
  fz_cuda.nvrtcDestroyProgram(&program);
  if (rtc_status != FZ_NVRTC_SUCCESS) {
    free(ptx);
    fz_set_last_error(EINVAL, 3, "gpu.launch failed: nvrtc PTX extraction failed");
    return NULL;
  }
  cuda_status = fz_cuda.cuModuleLoadData(&module, ptx);
  free(ptx);
  if (cuda_status != FZ_CUDA_SUCCESS || module == NULL) {
    fz_set_last_error(EINVAL, 3, fz_gpu_cuda_error_string(cuda_status));
    return NULL;
  }
#endif
  cuda_status = fz_cuda.cuModuleGetFunction(&function, module, kernel_c);
  if (cuda_status != FZ_CUDA_SUCCESS || function == NULL) {
    fz_cuda.cuModuleUnload(module);
    fz_set_last_error(EINVAL, 3, fz_gpu_cuda_error_string(cuda_status));
    return NULL;
  }
  int32_t slot = fz_gpu_pipeline_alloc_slot();
  if (slot <= 0) {
    slot = fz_gpu_pipeline_evict_lru_slot();
    if (slot <= 0) {
      fz_cuda.cuModuleUnload(module);
      fz_set_last_error(ENOSPC, 3, "gpu.launch failed: GPU pipeline registry full and no reusable slot was available");
      return NULL;
    }
  }
  fz_gpu_pipeline_state* state = &fz_gpu_pipelines[slot - 1];
  state->device_handle = device_handle;
  state->source_id = source_id;
  state->kernel_name_id = kernel_name_id;
  state->last_used_epoch = ++fz_gpu_pipeline_epoch;
  state->pipeline = function;
  state->module = module;
  return state;
}

static int32_t fz_gpu_launch_impl(
    int32_t kernel_name_id,
    int32_t source_id,
    int32_t layout_id,
    int32_t grid,
    int32_t block,
    int argc,
    uintptr_t a0,
    uintptr_t a1,
    uintptr_t a2,
    uintptr_t a3
) {
  pthread_once(&fz_gpu_init_once, fz_gpu_runtime_init);
  if (grid <= 0 || block <= 0) {
    fz_set_last_error(EINVAL, 3, "gpu.launch failed: grid and block must be > 0");
    return 0;
  }
  const char* layout = (const char*)fz_native_str_ptr(layout_id);
  if (layout == NULL || layout[0] == '\0') {
    fz_set_last_error(EINVAL, 3, "gpu.launch failed: missing launch layout");
    return 0;
  }
  uintptr_t raw_args[4] = {a0, a1, a2, a3};
  const char* token = layout;
  int32_t device_handle = 0;
  int32_t slice_buffers[4] = {0, 0, 0, 0};
  int32_t slice_offsets[4] = {0, 0, 0, 0};
  int32_t slice_lens[4] = {0, 0, 0, 0};
  int32_t slice_element_sizes[4] = {0, 0, 0, 0};
  int slice_count = 0;
  for (int arg = 0; arg < argc; arg++) {
    const char* next = strchr(token, ',');
    size_t token_len = next == NULL ? strlen(token) : (size_t)(next - token);
    if (token_len == 0) {
      fz_set_last_error(EINVAL, 3, "gpu.launch failed: malformed launch layout");
      return 0;
    }
    if (token_len >= 6 && strncmp(token, "slice_", 6) == 0) {
      if (slice_count >= 4) {
        fz_set_last_error(EINVAL, 3, "gpu.launch failed: more than 4 slice args are unsupported");
        return 0;
      }
      if (fz_gpu_slice_unpack(raw_args[arg], &slice_buffers[slice_count], &slice_offsets[slice_count], &slice_lens[slice_count]) != 0) {
        fz_set_last_error(EINVAL, 3, "gpu.launch failed: expected a GpuSlice launch argument");
        return 0;
      }
      if (slice_buffers[slice_count] <= 0 || slice_buffers[slice_count] > FZ_MAX_GPU_BUFFERS) {
        fz_set_last_error(EINVAL, 3, "gpu.launch failed: invalid slice buffer handle");
        return 0;
      }
      fz_gpu_buffer_state* buffer_state = &fz_gpu_buffers[slice_buffers[slice_count] - 1];
      if (!buffer_state->in_use || buffer_state->buffer == NULL) {
        fz_set_last_error(EINVAL, 3, "gpu.launch failed: invalid slice buffer handle");
        return 0;
      }
      slice_element_sizes[arg] = buffer_state->element_size;
      if (device_handle == 0) {
        device_handle = buffer_state->device_handle;
      } else if (device_handle != buffer_state->device_handle) {
        fz_set_last_error(EINVAL, 3, "gpu.launch failed: all GPU slices must target the same device");
        return 0;
      }
      slice_count++;
    }
    token = next == NULL ? token + token_len : next + 1;
  }
  if (device_handle == 0) {
    device_handle = fz_native_gpu_default_device();
    if (device_handle == 0) {
      return 0;
    }
  }
  fz_cuda_device_t device = 0;
  fz_cuda_context_t context = NULL;
  if (fz_gpu_cuda_device_for_handle(device_handle, &device, &context) != 0) {
    fz_set_last_error(EINVAL, 3, "gpu.launch failed: invalid device handle");
    return 0;
  }
  (void)device;
  fz_cuda_result_t status = fz_cuda.cuCtxSetCurrent(context);
  if (status != FZ_CUDA_SUCCESS) {
    fz_set_last_error(EIO, 3, fz_gpu_cuda_error_string(status));
    return 0;
  }
  fz_gpu_pipeline_state* pipeline = fz_gpu_pipeline_for_kernel(device_handle, source_id, kernel_name_id);
  if (pipeline == NULL) {
    return 0;
  }

  void* kernel_params[8];
  int kernel_param_count = 0;
  fz_cuda_deviceptr_t data_ptrs[4];
  uint32_t len_values[4];
  int32_t i32_values[4];
  uint32_t u32_values[4];
  float f32_values[4];
  int slice_arg = 0;
  int i32_arg = 0;
  int u32_arg = 0;
  int f32_arg = 0;
  token = layout;
  for (int arg = 0; arg < argc; arg++) {
    const char* next = strchr(token, ',');
    size_t token_len = next == NULL ? strlen(token) : (size_t)(next - token);
    if (token_len >= 6 && strncmp(token, "slice_", 6) == 0) {
      int32_t buffer_handle = 0;
      int32_t offset = 0;
      int32_t len = 0;
      if (fz_gpu_slice_unpack(raw_args[arg], &buffer_handle, &offset, &len) != 0) {
        fz_set_last_error(EINVAL, 3, "gpu.launch failed: expected a GpuSlice launch argument");
        return 0;
      }
      fz_gpu_buffer_state* buffer_state = &fz_gpu_buffers[buffer_handle - 1];
      fz_cuda_deviceptr_t base = (fz_cuda_deviceptr_t)(uintptr_t)buffer_state->buffer;
      fz_cuda_deviceptr_t byte_offset = (fz_cuda_deviceptr_t)((uint64_t)(uint32_t)offset * (uint64_t)(uint32_t)slice_element_sizes[arg]);
      data_ptrs[slice_arg] = base + byte_offset;
      len_values[slice_arg] = (uint32_t)len;
      kernel_params[kernel_param_count++] = &data_ptrs[slice_arg];
      kernel_params[kernel_param_count++] = &len_values[slice_arg];
      slice_arg++;
    } else if (token_len == 3 && strncmp(token, "i32", 3) == 0) {
      i32_values[i32_arg] = (int32_t)raw_args[arg];
      kernel_params[kernel_param_count++] = &i32_values[i32_arg++];
    } else if (token_len == 3 && strncmp(token, "u32", 3) == 0) {
      u32_values[u32_arg] = (uint32_t)raw_args[arg];
      kernel_params[kernel_param_count++] = &u32_values[u32_arg++];
    } else if (token_len == 3 && strncmp(token, "f32", 3) == 0) {
      union { uint32_t bits; float value; } cast;
      cast.bits = (uint32_t)raw_args[arg];
      f32_values[f32_arg] = cast.value;
      kernel_params[kernel_param_count++] = &f32_values[f32_arg++];
    } else {
      fz_set_last_error(EINVAL, 3, "gpu.launch failed: unsupported CUDA launch param layout");
      return 0;
    }
    token = next == NULL ? token + token_len : next + 1;
  }

  fz_cuda_stream_t stream = NULL;
  status = fz_cuda.cuStreamCreate(&stream, 0);
  if (status != FZ_CUDA_SUCCESS || stream == NULL) {
    fz_set_last_error(EIO, 3, fz_gpu_cuda_error_string(status));
    return 0;
  }
  status = fz_cuda.cuLaunchKernel(
      (fz_cuda_function_t)pipeline->pipeline,
      (unsigned int)grid, 1, 1,
      (unsigned int)block, 1, 1,
      0,
      stream,
      kernel_params,
      NULL);
  if (status != FZ_CUDA_SUCCESS) {
    fz_cuda.cuStreamDestroy(stream);
    fz_set_last_error(EIO, 3, fz_gpu_cuda_error_string(status));
    return 0;
  }
  pthread_mutex_lock(&fz_gpu_lock);
  int32_t event_handle = fz_gpu_event_alloc_slot();
  if (event_handle > 0) {
    fz_gpu_event_state* event = &fz_gpu_events[event_handle - 1];
    event->device_handle = device_handle;
    event->command_buffer = stream;
  }
  pthread_mutex_unlock(&fz_gpu_lock);
  if (event_handle <= 0) {
    fz_cuda.cuStreamDestroy(stream);
    fz_set_last_error(ENOSPC, 3, "gpu.launch failed: GPU event registry full");
    return 0;
  }
  fz_set_last_error(0, 0, "");
  return event_handle;
}
#endif

int32_t fz_native_gpu_launch0(int32_t kernel_name_id, int32_t source_id, int32_t layout_id, int32_t grid, int32_t block) {
#if (defined(__APPLE__) && defined(__OBJC__)) || defined(__linux__)
  return fz_gpu_launch_impl(kernel_name_id, source_id, layout_id, grid, block, 0, 0, 0, 0, 0);
#else
  (void)kernel_name_id; (void)source_id; (void)layout_id; (void)grid; (void)block;
  fz_set_last_error(ENOTSUP, 3, "gpu.launch failed: Metal runtime unavailable on this host");
  return 0;
#endif
}

int32_t fz_native_gpu_launch1(int32_t kernel_name_id, int32_t source_id, int32_t layout_id, int32_t grid, int32_t block, uintptr_t a0) {
#if (defined(__APPLE__) && defined(__OBJC__)) || defined(__linux__)
  return fz_gpu_launch_impl(kernel_name_id, source_id, layout_id, grid, block, 1, a0, 0, 0, 0);
#else
  (void)kernel_name_id; (void)source_id; (void)layout_id; (void)grid; (void)block; (void)a0;
  fz_set_last_error(ENOTSUP, 3, "gpu.launch failed: Metal runtime unavailable on this host");
  return 0;
#endif
}

int32_t fz_native_gpu_launch2(int32_t kernel_name_id, int32_t source_id, int32_t layout_id, int32_t grid, int32_t block, uintptr_t a0, uintptr_t a1) {
#if (defined(__APPLE__) && defined(__OBJC__)) || defined(__linux__)
  return fz_gpu_launch_impl(kernel_name_id, source_id, layout_id, grid, block, 2, a0, a1, 0, 0);
#else
  (void)kernel_name_id; (void)source_id; (void)layout_id; (void)grid; (void)block; (void)a0; (void)a1;
  fz_set_last_error(ENOTSUP, 3, "gpu.launch failed: Metal runtime unavailable on this host");
  return 0;
#endif
}

int32_t fz_native_gpu_launch3(int32_t kernel_name_id, int32_t source_id, int32_t layout_id, int32_t grid, int32_t block, uintptr_t a0, uintptr_t a1, uintptr_t a2) {
#if (defined(__APPLE__) && defined(__OBJC__)) || defined(__linux__)
  return fz_gpu_launch_impl(kernel_name_id, source_id, layout_id, grid, block, 3, a0, a1, a2, 0);
#else
  (void)kernel_name_id; (void)source_id; (void)layout_id; (void)grid; (void)block; (void)a0; (void)a1; (void)a2;
  fz_set_last_error(ENOTSUP, 3, "gpu.launch failed: Metal runtime unavailable on this host");
  return 0;
#endif
}

int32_t fz_native_gpu_launch4(int32_t kernel_name_id, int32_t source_id, int32_t layout_id, int32_t grid, int32_t block, uintptr_t a0, uintptr_t a1, uintptr_t a2, uintptr_t a3) {
#if (defined(__APPLE__) && defined(__OBJC__)) || defined(__linux__)
  return fz_gpu_launch_impl(kernel_name_id, source_id, layout_id, grid, block, 4, a0, a1, a2, a3);
#else
  (void)kernel_name_id; (void)source_id; (void)layout_id; (void)grid; (void)block; (void)a0; (void)a1; (void)a2; (void)a3;
  fz_set_last_error(ENOTSUP, 3, "gpu.launch failed: Metal runtime unavailable on this host");
  return 0;
#endif
}

int32_t fz_native_gpu_wait(int32_t event_handle) {
  pthread_once(&fz_gpu_init_once, fz_gpu_runtime_init);
  if (event_handle <= 0 || event_handle > FZ_MAX_GPU_EVENTS) {
    fz_set_last_error(EINVAL, 3, "gpu.wait failed: invalid GPU event handle");
    return -1;
  }
  pthread_mutex_lock(&fz_gpu_lock);
  fz_gpu_event_state* state = &fz_gpu_events[event_handle - 1];
  if (!state->in_use || state->command_buffer == NULL) {
    pthread_mutex_unlock(&fz_gpu_lock);
    fz_set_last_error(EINVAL, 3, "gpu.wait failed: invalid GPU event handle");
    return -1;
  }
#if defined(__APPLE__) && defined(__OBJC__)
  id<MTLCommandBuffer> command_buffer = (id<MTLCommandBuffer>)state->command_buffer;
  [command_buffer retain];
  memset(state, 0, sizeof(*state));
  pthread_mutex_unlock(&fz_gpu_lock);
  [command_buffer waitUntilCompleted];
  MTLCommandBufferStatus status = [command_buffer status];
  NSError* error = [command_buffer error];
  [command_buffer release];
  if (status == MTLCommandBufferStatusError) {
    const char* detail = error == nil ? "gpu.wait failed: Metal command buffer completed with error" : [[error localizedDescription] UTF8String];
    fz_set_last_error(EIO, 3, detail == NULL ? "gpu.wait failed: Metal command buffer completed with error" : detail);
    return -1;
  }
  fz_set_last_error(0, 0, "");
  return 0;
#elif defined(__linux__) && defined(FZ_GPU_BACKEND_ROCM)
  fz_hip_stream_t stream = (fz_hip_stream_t)state->command_buffer;
  memset(state, 0, sizeof(*state));
  pthread_mutex_unlock(&fz_gpu_lock);
  fz_hip_error_t status = fz_hip.hipStreamSynchronize(stream);
  fz_hip.hipStreamDestroy(stream);
  if (status != FZ_HIP_SUCCESS) {
    fz_set_last_error(EIO, 3, fz_gpu_hip_error_string(status));
    return -1;
  }
  fz_set_last_error(0, 0, "");
  return 0;
#elif defined(__linux__) && defined(FZ_GPU_BACKEND_CUDA)
  int32_t device_handle = state->device_handle;
  fz_cuda_stream_t stream = (fz_cuda_stream_t)state->command_buffer;
  memset(state, 0, sizeof(*state));
  pthread_mutex_unlock(&fz_gpu_lock);
  fz_cuda_device_t device = 0;
  fz_cuda_context_t context = NULL;
  if (fz_gpu_cuda_device_for_handle(device_handle, &device, &context) != 0) {
    fz_cuda.cuStreamDestroy(stream);
    fz_set_last_error(EINVAL, 3, "gpu.wait failed: invalid device handle");
    return -1;
  }
  (void)device;
  fz_cuda_result_t status = fz_cuda.cuCtxSetCurrent(context);
  if (status == FZ_CUDA_SUCCESS) {
    status = fz_cuda.cuStreamSynchronize(stream);
  }
  fz_cuda.cuStreamDestroy(stream);
  if (status != FZ_CUDA_SUCCESS) {
    fz_set_last_error(EIO, 3, fz_gpu_cuda_error_string(status));
    return -1;
  }
  fz_set_last_error(0, 0, "");
  return 0;
#else
  pthread_mutex_unlock(&fz_gpu_lock);
  fz_set_last_error(ENOTSUP, 3, "gpu.wait failed: Metal runtime unavailable on this host");
  return -1;
#endif
}

int32_t fz_native_gpu_wait_async(int32_t event_handle) {
  return fz_native_gpu_wait(event_handle);
}

"#
}

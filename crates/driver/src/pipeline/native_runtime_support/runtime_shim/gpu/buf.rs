pub(super) fn section() -> &'static str {
    r#"
int32_t fz_native_gpu_device_count(void) {
  pthread_once(&fz_gpu_init_once, fz_gpu_runtime_init);
  if (fz_gpu_device_count_cached < 0) {
    return 0;
  }
  return fz_gpu_device_count_cached;
}

int32_t fz_native_gpu_default_device(void) {
  pthread_once(&fz_gpu_init_once, fz_gpu_runtime_init);
  if (fz_gpu_device_count_cached <= 0) {
    const char* backend_error =
#if defined(__linux__) && defined(FZ_GPU_BACKEND_CUDA)
        fz_gpu_runtime_error[0] == '\0' ? "gpu.default_device failed: no CUDA device available" : fz_gpu_runtime_error;
#elif defined(__linux__) && defined(FZ_GPU_BACKEND_ROCM)
        fz_gpu_runtime_error[0] == '\0' ? "gpu.default_device failed: no ROCm device available" : fz_gpu_runtime_error;
#elif defined(__APPLE__) && defined(__OBJC__)
        "gpu.default_device failed: no Metal device available";
#else
        "gpu.default_device failed: no GPU backend selected for this native runtime";
#endif
    fz_set_last_error(ENODEV, 3, backend_error);
    return 0;
  }
  fz_set_last_error(0, 0, "");
  return 1;
}

int32_t fz_native_gpu_device_name(int32_t device_handle) {
  pthread_once(&fz_gpu_init_once, fz_gpu_runtime_init);
#if defined(__APPLE__) && defined(__OBJC__)
  @autoreleasepool {
    id<MTLDevice> device = fz_gpu_device_for_handle(device_handle);
    if (device == nil) {
      fz_set_last_error(EINVAL, 3, "gpu.device_name failed: invalid device handle");
      return 0;
    }
    NSString* name = [device name];
    const char* utf8 = name == nil ? "" : [name UTF8String];
    fz_set_last_error(0, 0, "");
    return fz_intern_slice(utf8 == NULL ? "" : utf8, utf8 == NULL ? 0 : strlen(utf8));
  }
#elif defined(__linux__) && defined(FZ_GPU_BACKEND_ROCM)
  int device = 0;
  if (fz_gpu_hip_device_index_for_handle(device_handle, &device) != 0) {
    fz_set_last_error(EINVAL, 3, "gpu.device_name failed: invalid device handle");
    return 0;
  }
  char name[256];
  memset(name, 0, sizeof(name));
  fz_hip_error_t status = fz_hip.hipDeviceGetName(name, (int)sizeof(name), device);
  if (status != FZ_HIP_SUCCESS) {
    fz_set_last_error(EIO, 3, fz_gpu_hip_error_string(status));
    return 0;
  }
  fz_set_last_error(0, 0, "");
  return fz_intern_slice(name, strlen(name));
#elif defined(__linux__) && defined(FZ_GPU_BACKEND_CUDA)
  fz_cuda_device_t device = 0;
  fz_cuda_context_t cuda_context = NULL;
  if (fz_gpu_cuda_device_for_handle(device_handle, &device, &cuda_context) != 0) {
    fz_set_last_error(EINVAL, 3, "gpu.device_name failed: invalid device handle");
    return 0;
  }
  char name[256];
  memset(name, 0, sizeof(name));
  fz_cuda_result_t status = fz_cuda.cuDeviceGetName(name, (int)sizeof(name), device);
  if (status != FZ_CUDA_SUCCESS) {
    fz_set_last_error(EIO, 3, fz_gpu_cuda_error_string(status));
    return 0;
  }
  fz_set_last_error(0, 0, "");
  return fz_intern_slice(name, strlen(name));
#else
  (void)device_handle;
  fz_set_last_error(ENOTSUP, 3, "gpu.device_name failed: GPU runtime unavailable on this host");
  return 0;
#endif
}

int64_t fz_native_gpu_device_memory_bytes(int32_t device_handle) {
  pthread_once(&fz_gpu_init_once, fz_gpu_runtime_init);
#if defined(__APPLE__) && defined(__OBJC__)
  @autoreleasepool {
    id<MTLDevice> device = fz_gpu_device_for_handle(device_handle);
    if (device == nil) {
      fz_set_last_error(EINVAL, 3, "gpu.device_memory_bytes failed: invalid device handle");
      return 0;
    }
    uint64_t bytes = 0;
    if ([device respondsToSelector:@selector(recommendedMaxWorkingSetSize)]) {
      bytes = [device recommendedMaxWorkingSetSize];
    }
    fz_set_last_error(0, 0, "");
    return (int64_t)bytes;
  }
#elif defined(__linux__) && defined(FZ_GPU_BACKEND_ROCM)
  int device = 0;
  if (fz_gpu_hip_device_index_for_handle(device_handle, &device) != 0) {
    fz_set_last_error(EINVAL, 3, "gpu.device_memory_bytes failed: invalid device handle");
    return 0;
  }
  fz_hip_error_t status = fz_hip.hipSetDevice(device);
  if (status != FZ_HIP_SUCCESS) {
    fz_set_last_error(EIO, 3, fz_gpu_hip_error_string(status));
    return 0;
  }
  size_t free_bytes = 0;
  size_t total_bytes = 0;
  status = fz_hip.hipMemGetInfo(&free_bytes, &total_bytes);
  if (status != FZ_HIP_SUCCESS) {
    fz_set_last_error(EIO, 3, fz_gpu_hip_error_string(status));
    return 0;
  }
  fz_set_last_error(0, 0, "");
  return (int64_t)total_bytes;
#elif defined(__linux__) && defined(FZ_GPU_BACKEND_CUDA)
  fz_cuda_device_t device = 0;
  fz_cuda_context_t cuda_context = NULL;
  if (fz_gpu_cuda_device_for_handle(device_handle, &device, &cuda_context) != 0) {
    fz_set_last_error(EINVAL, 3, "gpu.device_memory_bytes failed: invalid device handle");
    return 0;
  }
  size_t total_bytes = 0;
  fz_cuda_result_t status = fz_cuda.cuDeviceTotalMem(&total_bytes, device);
  if (status != FZ_CUDA_SUCCESS) {
    fz_set_last_error(EIO, 3, fz_gpu_cuda_error_string(status));
    return 0;
  }
  fz_set_last_error(0, 0, "");
  return (int64_t)total_bytes;
#else
  (void)device_handle;
  fz_set_last_error(ENOTSUP, 3, "gpu.device_memory_bytes failed: GPU runtime unavailable on this host");
  return 0;
#endif
}

static int32_t fz_native_gpu_buffer_new(
    int32_t device_handle,
    int32_t len,
    int32_t element_size,
    const char* context,
    const char* alloc_failure_context,
    const void* host_data
) {
  pthread_once(&fz_gpu_init_once, fz_gpu_runtime_init);
  if (len < 0) {
    fz_set_last_error(EINVAL, 3, context);
    return 0;
  }
#if defined(__APPLE__) && defined(__OBJC__)
  @autoreleasepool {
    id<MTLDevice> device = fz_gpu_device_for_handle(device_handle);
    if (device == nil) {
      fz_set_last_error(EINVAL, 3, "gpu.alloc failed: invalid device handle");
      return 0;
    }
    NSUInteger bytes = (NSUInteger)((uint64_t)(uint32_t)len * (uint64_t)(uint32_t)element_size);
    id<MTLBuffer> buffer = [device newBufferWithLength:bytes options:MTLResourceStorageModeShared];
    if (buffer == nil) {
      fz_set_last_error(ENOMEM, 3, alloc_failure_context);
      return 0;
    }
    if (bytes > 0 && host_data != NULL) {
      void* contents = [buffer contents];
      if (contents == NULL) {
        [buffer release];
        fz_set_last_error(EIO, 3, "gpu.upload failed: Metal buffer has no CPU-visible contents");
        return 0;
      }
      memcpy(contents, host_data, bytes);
    }
    pthread_mutex_lock(&fz_gpu_lock);
    int32_t handle = fz_gpu_buffer_alloc_slot();
    if (handle > 0) {
      fz_gpu_buffer_state* state = &fz_gpu_buffers[handle - 1];
      state->device_handle = device_handle;
      state->element_size = element_size;
      state->len = len;
      state->buffer = (void*)buffer;
    }
    pthread_mutex_unlock(&fz_gpu_lock);
    if (handle <= 0) {
      [buffer release];
      fz_set_last_error(ENOSPC, 3, "gpu.alloc failed: GPU buffer registry full");
      return 0;
    }
    fz_set_last_error(0, 0, "");
    return handle;
  }
#elif defined(__linux__) && defined(FZ_GPU_BACKEND_ROCM)
  int device = 0;
  if (fz_gpu_hip_device_index_for_handle(device_handle, &device) != 0) {
    fz_set_last_error(EINVAL, 3, "gpu.alloc failed: invalid device handle");
    return 0;
  }
  uint64_t byte_count = (uint64_t)(uint32_t)len * (uint64_t)(uint32_t)element_size;
  size_t bytes = (size_t)byte_count;
  if ((uint64_t)bytes != byte_count) {
    fz_set_last_error(EOVERFLOW, 3, "gpu.alloc failed: allocation size overflow");
    return 0;
  }
  fz_hip_error_t status = fz_hip.hipSetDevice(device);
  if (status != FZ_HIP_SUCCESS) {
    fz_set_last_error(EIO, 3, fz_gpu_hip_error_string(status));
    return 0;
  }
  void* buffer = NULL;
  status = fz_hip.hipMalloc(&buffer, bytes == 0 ? 1 : bytes);
  if (status != FZ_HIP_SUCCESS || buffer == NULL) {
    fz_set_last_error(ENOMEM, 3, fz_gpu_hip_error_string(status));
    return 0;
  }
  if (bytes > 0 && host_data != NULL) {
    status = fz_hip.hipMemcpy(buffer, host_data, bytes, FZ_HIP_MEMCPY_HOST_TO_DEVICE);
    if (status != FZ_HIP_SUCCESS) {
      fz_hip.hipFree(buffer);
      fz_set_last_error(EIO, 3, fz_gpu_hip_error_string(status));
      return 0;
    }
  }
  pthread_mutex_lock(&fz_gpu_lock);
  int32_t handle = fz_gpu_buffer_alloc_slot();
  if (handle > 0) {
    fz_gpu_buffer_state* state = &fz_gpu_buffers[handle - 1];
    state->device_handle = device_handle;
    state->element_size = element_size;
    state->len = len;
    state->buffer = buffer;
  }
  pthread_mutex_unlock(&fz_gpu_lock);
  if (handle <= 0) {
    fz_hip.hipFree(buffer);
    fz_set_last_error(ENOSPC, 3, "gpu.alloc failed: GPU buffer registry full");
    return 0;
  }
  fz_set_last_error(0, 0, "");
  return handle;
#elif defined(__linux__) && defined(FZ_GPU_BACKEND_CUDA)
  fz_cuda_device_t device = 0;
  fz_cuda_context_t cuda_context = NULL;
  if (fz_gpu_cuda_device_for_handle(device_handle, &device, &cuda_context) != 0) {
    fz_set_last_error(EINVAL, 3, "gpu.alloc failed: invalid device handle");
    return 0;
  }
  (void)device;
  uint64_t byte_count = (uint64_t)(uint32_t)len * (uint64_t)(uint32_t)element_size;
  size_t bytes = (size_t)byte_count;
  if ((uint64_t)bytes != byte_count) {
    fz_set_last_error(EOVERFLOW, 3, "gpu.alloc failed: allocation size overflow");
    return 0;
  }
  fz_cuda_result_t status = fz_cuda.cuCtxSetCurrent(cuda_context);
  if (status != FZ_CUDA_SUCCESS) {
    fz_set_last_error(EIO, 3, fz_gpu_cuda_error_string(status));
    return 0;
  }
  fz_cuda_deviceptr_t buffer = 0;
  status = fz_cuda.cuMemAlloc(&buffer, bytes == 0 ? 1 : bytes);
  if (status != FZ_CUDA_SUCCESS || buffer == 0) {
    fz_set_last_error(ENOMEM, 3, fz_gpu_cuda_error_string(status));
    return 0;
  }
  if (bytes > 0 && host_data != NULL) {
    status = fz_cuda.cuMemcpyHtoD(buffer, host_data, bytes);
    if (status != FZ_CUDA_SUCCESS) {
      fz_cuda.cuMemFree(buffer);
      fz_set_last_error(EIO, 3, fz_gpu_cuda_error_string(status));
      return 0;
    }
  }
  pthread_mutex_lock(&fz_gpu_lock);
  int32_t handle = fz_gpu_buffer_alloc_slot();
  if (handle > 0) {
    fz_gpu_buffer_state* state = &fz_gpu_buffers[handle - 1];
    state->device_handle = device_handle;
    state->element_size = element_size;
    state->len = len;
    state->buffer = (void*)(uintptr_t)buffer;
  }
  pthread_mutex_unlock(&fz_gpu_lock);
  if (handle <= 0) {
    fz_cuda.cuMemFree(buffer);
    fz_set_last_error(ENOSPC, 3, "gpu.alloc failed: GPU buffer registry full");
    return 0;
  }
  fz_set_last_error(0, 0, "");
  return handle;
#else
  (void)device_handle;
  (void)element_size;
  (void)host_data;
  fz_set_last_error(ENOTSUP, 3, alloc_failure_context);
  return 0;
#endif
}

int32_t fz_native_gpu_alloc_f32(int32_t device_handle, int32_t len) {
  return fz_native_gpu_buffer_new(
      device_handle,
      len,
      4,
      "gpu.alloc_f32 failed: len must be >= 0",
      "gpu.alloc failed: Metal buffer allocation returned nil",
      NULL);
}

int32_t fz_native_gpu_alloc_i32(int32_t device_handle, int32_t len) {
  return fz_native_gpu_buffer_new(
      device_handle,
      len,
      4,
      "gpu.alloc_i32 failed: len must be >= 0",
      "gpu.alloc failed: Metal buffer allocation returned nil",
      NULL);
}

int32_t fz_native_gpu_alloc_u32(int32_t device_handle, int32_t len) {
  return fz_native_gpu_buffer_new(
      device_handle,
      len,
      4,
      "gpu.alloc_u32 failed: len must be >= 0",
      "gpu.alloc failed: Metal buffer allocation returned nil",
      NULL);
}

static int32_t fz_native_gpu_upload_bytes(
    int32_t device_handle,
    const void* host_data,
    int32_t len,
    int32_t element_size,
    const char* len_context
) {
  if (len < 0) {
    fz_set_last_error(EINVAL, 3, len_context);
    return 0;
  }
  if (len > 0 && host_data == NULL) {
    fz_set_last_error(EINVAL, 3, "gpu.upload failed: host data pointer was null");
    return 0;
  }
  return fz_native_gpu_buffer_new(
      device_handle,
      len,
      element_size,
      len_context,
      "gpu.upload failed: Metal buffer allocation returned nil",
      host_data);
}

int32_t fz_native_gpu_upload_f32(int32_t device_handle, uintptr_t host_data, int32_t len) {
  return fz_native_gpu_upload_bytes(
      device_handle,
      (const void*)host_data,
      len,
      4,
      "gpu.upload_f32 failed: len must be >= 0");
}

int32_t fz_native_gpu_upload_i32(int32_t device_handle, uintptr_t host_data, int32_t len) {
  return fz_native_gpu_upload_bytes(
      device_handle,
      (const void*)host_data,
      len,
      4,
      "gpu.upload_i32 failed: len must be >= 0");
}

int32_t fz_native_gpu_upload_u32(int32_t device_handle, uintptr_t host_data, int32_t len) {
  return fz_native_gpu_upload_bytes(
      device_handle,
      (const void*)host_data,
      len,
      4,
      "gpu.upload_u32 failed: len must be >= 0");
}

static uintptr_t fz_native_gpu_download_bytes(
    int32_t buffer_handle,
    int32_t expected_element_size,
    int32_t element_kind,
    const char* invalid_buffer_context,
    const char* element_mismatch_context
) {
  pthread_once(&fz_gpu_init_once, fz_gpu_runtime_init);
  pthread_mutex_lock(&fz_gpu_lock);
  if (buffer_handle <= 0 || buffer_handle > FZ_MAX_GPU_BUFFERS) {
    pthread_mutex_unlock(&fz_gpu_lock);
    fz_set_last_error(EINVAL, 3, invalid_buffer_context);
    return 0;
  }
  fz_gpu_buffer_state* state = &fz_gpu_buffers[buffer_handle - 1];
  if (!state->in_use || state->buffer == NULL) {
    pthread_mutex_unlock(&fz_gpu_lock);
    fz_set_last_error(EINVAL, 3, invalid_buffer_context);
    return 0;
  }
  if (state->element_size != expected_element_size) {
    pthread_mutex_unlock(&fz_gpu_lock);
    fz_set_last_error(EINVAL, 3, element_mismatch_context);
    return 0;
  }
  int32_t len = state->len;
#if defined(__APPLE__) && defined(__OBJC__)
  id<MTLBuffer> buffer = (id<MTLBuffer>)state->buffer;
  [buffer retain];
  pthread_mutex_unlock(&fz_gpu_lock);
  void* contents = [buffer contents];
  if (len > 0 && contents == NULL) {
    [buffer release];
    fz_set_last_error(EIO, 3, "gpu.download failed: Metal buffer has no CPU-visible contents");
    return 0;
  }
  pthread_mutex_lock(&fz_collections_lock);
  int32_t handle = fz_numeric_vec_alloc();
  if (handle > 0) {
    fz_numeric_vec_state* vec = fz_numeric_vec_get((uintptr_t)handle);
    if (vec != NULL) {
      vec->element_kind = element_kind;
      if (fz_numeric_vec_reserve(vec, len) != 0) {
        handle = -1;
        fz_numeric_vec_reset(vec);
      }
      uint32_t* words = (uint32_t*)contents;
      if (handle > 0) {
        for (int32_t index = 0; index < len; index++) {
          if (fz_numeric_vec_push_bits32(vec, words[index]) != 0) {
            handle = -1;
            fz_numeric_vec_reset(vec);
            break;
          }
        }
      }
    } else {
      handle = -1;
    }
  }
  pthread_mutex_unlock(&fz_collections_lock);
  [buffer release];
  if (handle <= 0) {
    fz_set_last_error(ENOSPC, 3, "gpu.download failed: numeric vector registry full");
    return 0;
  }
  fz_set_last_error(0, 0, "");
  return (uintptr_t)handle;
#else
  #if defined(__linux__) && defined(FZ_GPU_BACKEND_ROCM)
  int32_t device_handle = state->device_handle;
  void* device_buffer = state->buffer;
  int device = 0;
  if (fz_gpu_hip_device_index_for_handle(device_handle, &device) != 0) {
    pthread_mutex_unlock(&fz_gpu_lock);
    fz_set_last_error(EINVAL, 3, invalid_buffer_context);
    return 0;
  }
  pthread_mutex_unlock(&fz_gpu_lock);
  uint64_t byte_count = (uint64_t)(uint32_t)len * (uint64_t)(uint32_t)expected_element_size;
  size_t bytes = (size_t)byte_count;
  if ((uint64_t)bytes != byte_count) {
    fz_set_last_error(EOVERFLOW, 3, "gpu.download failed: download size overflow");
    return 0;
  }
  uint32_t* words = NULL;
  if (bytes > 0) {
    words = (uint32_t*)malloc(bytes);
    if (words == NULL) {
      fz_set_last_error(ENOMEM, 3, "gpu.download failed: host staging allocation failed");
      return 0;
    }
    fz_hip_error_t status = fz_hip.hipSetDevice(device);
    if (status == FZ_HIP_SUCCESS) {
      status = fz_hip.hipMemcpy(words, device_buffer, bytes, FZ_HIP_MEMCPY_DEVICE_TO_HOST);
    }
    if (status != FZ_HIP_SUCCESS) {
      free(words);
      fz_set_last_error(EIO, 3, fz_gpu_hip_error_string(status));
      return 0;
    }
  }
  pthread_mutex_lock(&fz_collections_lock);
  int32_t handle = fz_numeric_vec_alloc();
  if (handle > 0) {
    fz_numeric_vec_state* vec = fz_numeric_vec_get((uintptr_t)handle);
    if (vec != NULL) {
      vec->element_kind = element_kind;
      if (fz_numeric_vec_reserve(vec, len) != 0) {
        handle = -1;
        fz_numeric_vec_reset(vec);
      }
      if (handle > 0) {
        for (int32_t index = 0; index < len; index++) {
          if (fz_numeric_vec_push_bits32(vec, words == NULL ? 0 : words[index]) != 0) {
            handle = -1;
            fz_numeric_vec_reset(vec);
            break;
          }
        }
      }
    } else {
      handle = -1;
    }
  }
  pthread_mutex_unlock(&fz_collections_lock);
  free(words);
  if (handle <= 0) {
    fz_set_last_error(ENOSPC, 3, "gpu.download failed: numeric vector registry full");
    return 0;
  }
  fz_set_last_error(0, 0, "");
  return (uintptr_t)handle;
  #elif defined(__linux__) && defined(FZ_GPU_BACKEND_CUDA)
  int32_t device_handle = state->device_handle;
  fz_cuda_deviceptr_t device_buffer = (fz_cuda_deviceptr_t)(uintptr_t)state->buffer;
  fz_cuda_device_t device = 0;
  fz_cuda_context_t context = NULL;
  if (fz_gpu_cuda_device_for_handle(device_handle, &device, &context) != 0) {
    pthread_mutex_unlock(&fz_gpu_lock);
    fz_set_last_error(EINVAL, 3, invalid_buffer_context);
    return 0;
  }
  pthread_mutex_unlock(&fz_gpu_lock);
  (void)device;
  uint64_t byte_count = (uint64_t)(uint32_t)len * (uint64_t)(uint32_t)expected_element_size;
  size_t bytes = (size_t)byte_count;
  if ((uint64_t)bytes != byte_count) {
    fz_set_last_error(EOVERFLOW, 3, "gpu.download failed: download size overflow");
    return 0;
  }
  uint32_t* words = NULL;
  if (bytes > 0) {
    words = (uint32_t*)malloc(bytes);
    if (words == NULL) {
      fz_set_last_error(ENOMEM, 3, "gpu.download failed: host staging allocation failed");
      return 0;
    }
    fz_cuda_result_t status = fz_cuda.cuCtxSetCurrent(context);
    if (status == FZ_CUDA_SUCCESS) {
      status = fz_cuda.cuMemcpyDtoH(words, device_buffer, bytes);
    }
    if (status != FZ_CUDA_SUCCESS) {
      free(words);
      fz_set_last_error(EIO, 3, fz_gpu_cuda_error_string(status));
      return 0;
    }
  }
  pthread_mutex_lock(&fz_collections_lock);
  int32_t handle = fz_numeric_vec_alloc();
  if (handle > 0) {
    fz_numeric_vec_state* vec = fz_numeric_vec_get((uintptr_t)handle);
    if (vec != NULL) {
      vec->element_kind = element_kind;
      if (fz_numeric_vec_reserve(vec, len) != 0) {
        handle = -1;
        fz_numeric_vec_reset(vec);
      }
      if (handle > 0) {
        for (int32_t index = 0; index < len; index++) {
          if (fz_numeric_vec_push_bits32(vec, words == NULL ? 0 : words[index]) != 0) {
            handle = -1;
            fz_numeric_vec_reset(vec);
            break;
          }
        }
      }
    } else {
      handle = -1;
    }
  }
  pthread_mutex_unlock(&fz_collections_lock);
  free(words);
  if (handle <= 0) {
    fz_set_last_error(ENOSPC, 3, "gpu.download failed: numeric vector registry full");
    return 0;
  }
  fz_set_last_error(0, 0, "");
  return (uintptr_t)handle;
  #else
    pthread_mutex_unlock(&fz_gpu_lock);
    fz_set_last_error(ENOTSUP, 3, "gpu.download failed: GPU runtime unavailable on this host");
    return 0;
  #endif
#endif
}

uintptr_t fz_native_gpu_download_f32(int32_t buffer_handle) {
  return fz_native_gpu_download_bytes(
      buffer_handle,
      4,
      1,
      "gpu.download_f32 failed: invalid GPU buffer handle",
      "gpu.download_f32 failed: buffer element type did not match f32");
}

uintptr_t fz_native_gpu_download_i32(int32_t buffer_handle) {
  return fz_native_gpu_download_bytes(
      buffer_handle,
      4,
      2,
      "gpu.download_i32 failed: invalid GPU buffer handle",
      "gpu.download_i32 failed: buffer element type did not match i32");
}

uintptr_t fz_native_gpu_download_u32(int32_t buffer_handle) {
  return fz_native_gpu_download_bytes(
      buffer_handle,
      4,
      3,
      "gpu.download_u32 failed: invalid GPU buffer handle",
      "gpu.download_u32 failed: buffer element type did not match u32");
}

int32_t fz_native_gpu_buffer_free(int32_t buffer_handle) {
  pthread_once(&fz_gpu_init_once, fz_gpu_runtime_init);
  if (buffer_handle <= 0 || buffer_handle > FZ_MAX_GPU_BUFFERS) {
    fz_set_last_error(EINVAL, 3, "gpu.free failed: invalid GPU buffer handle");
    return -1;
  }
  pthread_mutex_lock(&fz_gpu_lock);
  fz_gpu_buffer_state* state = &fz_gpu_buffers[buffer_handle - 1];
  if (!state->in_use || state->buffer == NULL) {
    pthread_mutex_unlock(&fz_gpu_lock);
    fz_set_last_error(EINVAL, 3, "gpu.free failed: invalid GPU buffer handle");
    return -1;
  }
#if defined(__APPLE__) && defined(__OBJC__)
  id<MTLBuffer> buffer = (id<MTLBuffer>)state->buffer;
  [buffer release];
#elif defined(__linux__)
  void* buffer = state->buffer;
  int32_t device_handle = state->device_handle;
  if (buffer != NULL) {
#if defined(FZ_GPU_BACKEND_ROCM)
    fz_hip.hipFree(buffer);
#elif defined(FZ_GPU_BACKEND_CUDA)
    fz_cuda_device_t device = 0;
    fz_cuda_context_t context = NULL;
    if (fz_gpu_cuda_device_for_handle(device_handle, &device, &context) == 0) {
      (void)device;
      fz_cuda.cuCtxSetCurrent(context);
    }
    fz_cuda.cuMemFree((fz_cuda_deviceptr_t)(uintptr_t)buffer);
#endif
  }
#endif
  memset(state, 0, sizeof(*state));
  pthread_mutex_unlock(&fz_gpu_lock);
  fz_set_last_error(0, 0, "");
  return 0;
}

uint64_t fz_native_gpu_slice(int32_t buffer_handle, int32_t offset, int32_t len) {
  pthread_once(&fz_gpu_init_once, fz_gpu_runtime_init);
  if (offset < 0 || len < 0) {
    fz_set_last_error(EINVAL, 3, "gpu.slice failed: offset/len must be >= 0");
    return 0;
  }
  pthread_mutex_lock(&fz_gpu_lock);
  if (buffer_handle <= 0 || buffer_handle > FZ_MAX_GPU_BUFFERS) {
    pthread_mutex_unlock(&fz_gpu_lock);
    fz_set_last_error(EINVAL, 3, "gpu.slice failed: invalid GPU buffer handle");
    return 0;
  }
  fz_gpu_buffer_state* state = &fz_gpu_buffers[buffer_handle - 1];
  if (!state->in_use || state->buffer == NULL) {
    pthread_mutex_unlock(&fz_gpu_lock);
    fz_set_last_error(EINVAL, 3, "gpu.slice failed: invalid GPU buffer handle");
    return 0;
  }
  if (offset > state->len || len > state->len - offset) {
    pthread_mutex_unlock(&fz_gpu_lock);
    fz_set_last_error(EINVAL, 3, "gpu.slice failed: slice range exceeds GPU buffer length");
    return 0;
  }
  pthread_mutex_unlock(&fz_gpu_lock);

  uint64_t handle = fz_native_agg_new(FZ_GPU_SLICE_TAG, 3);
  if (handle == 0) {
    fz_set_last_error(ENOSPC, 3, "gpu.slice failed: GPU slice registry full");
    return 0;
  }
  if (fz_native_agg_set_i64(handle, 0, (uint64_t)(uint32_t)buffer_handle) != 0
      || fz_native_agg_set_i64(handle, 1, (uint64_t)(uint32_t)offset) != 0
      || fz_native_agg_set_i64(handle, 2, (uint64_t)(uint32_t)len) != 0) {
    fz_set_last_error(EINVAL, 3, "gpu.slice failed: could not materialize slice handle");
    return 0;
  }
  fz_set_last_error(0, 0, "");
  return handle;
}

"#
}

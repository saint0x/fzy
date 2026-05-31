pub(super) fn runtime_shim_section_gpu() -> &'static str {
    r#"
#define FZ_MAX_GPU_DEVICES 16
#define FZ_MAX_GPU_BUFFERS 4096
#define FZ_GPU_SLICE_TAG 4101

typedef struct {
  int in_use;
  void* device;
} fz_gpu_device_state;

typedef struct {
  int in_use;
  int32_t device_handle;
  int32_t element_size;
  int32_t len;
  void* buffer;
} fz_gpu_buffer_state;

static fz_gpu_device_state fz_gpu_devices[FZ_MAX_GPU_DEVICES];
static fz_gpu_buffer_state fz_gpu_buffers[FZ_MAX_GPU_BUFFERS];
static int32_t fz_gpu_device_count_cached = -1;
static pthread_mutex_t fz_gpu_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_once_t fz_gpu_init_once = PTHREAD_ONCE_INIT;

static void fz_gpu_runtime_init(void);
static int32_t fz_gpu_buffer_alloc_slot(void);

#if defined(__APPLE__) && defined(__OBJC__)
#import <Foundation/Foundation.h>
#import <Metal/Metal.h>

static void fz_gpu_runtime_init(void) {
  @autoreleasepool {
    int count = 0;
    NSArray<id<MTLDevice>>* devices = MTLCopyAllDevices();
    if (devices != nil && [devices count] > 0) {
      NSUInteger limit = [devices count] < FZ_MAX_GPU_DEVICES ? [devices count] : FZ_MAX_GPU_DEVICES;
      for (NSUInteger index = 0; index < limit; index++) {
        id<MTLDevice> device = [devices objectAtIndex:index];
        if (device == nil) {
          continue;
        }
        [device retain];
        fz_gpu_devices[count].in_use = 1;
        fz_gpu_devices[count].device = (void*)device;
        count++;
      }
      [devices release];
    }
    if (count == 0) {
      id<MTLDevice> device = MTLCreateSystemDefaultDevice();
      if (device != nil) {
        [device retain];
        fz_gpu_devices[count].in_use = 1;
        fz_gpu_devices[count].device = (void*)device;
        count++;
        [device release];
      }
    }
    fz_gpu_device_count_cached = count;
  }
}

static id<MTLDevice> fz_gpu_device_for_handle(int32_t handle) {
  if (handle <= 0 || handle > FZ_MAX_GPU_DEVICES) {
    return nil;
  }
  fz_gpu_device_state* state = &fz_gpu_devices[handle - 1];
  if (!state->in_use || state->device == NULL) {
    return nil;
  }
  return (id<MTLDevice>)state->device;
}

static id<MTLBuffer> fz_gpu_buffer_for_handle(int32_t handle) {
  if (handle <= 0 || handle > FZ_MAX_GPU_BUFFERS) {
    return nil;
  }
  fz_gpu_buffer_state* state = &fz_gpu_buffers[handle - 1];
  if (!state->in_use || state->buffer == NULL) {
    return nil;
  }
  return (id<MTLBuffer>)state->buffer;
}
#else
static void fz_gpu_runtime_init(void) {
  fz_gpu_device_count_cached = 0;
}
#endif

static int32_t fz_gpu_buffer_alloc_slot(void) {
  for (int i = 0; i < FZ_MAX_GPU_BUFFERS; i++) {
    if (!fz_gpu_buffers[i].in_use) {
      memset(&fz_gpu_buffers[i], 0, sizeof(fz_gpu_buffers[i]));
      fz_gpu_buffers[i].in_use = 1;
      return i + 1;
    }
  }
  return 0;
}

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
    fz_set_last_error(ENODEV, 3, "gpu.default_device failed: no Metal device available");
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
#else
  (void)device_handle;
  fz_set_last_error(ENOTSUP, 3, "gpu.device_name failed: Metal runtime unavailable on this host");
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
#else
  (void)device_handle;
  fz_set_last_error(ENOTSUP, 3, "gpu.device_memory_bytes failed: Metal runtime unavailable on this host");
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
      uint32_t* words = (uint32_t*)contents;
      for (int32_t index = 0; index < len; index++) {
        if (fz_numeric_vec_push_bits32(vec, words[index]) != 0) {
          handle = -1;
          vec->in_use = 0;
          break;
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
  pthread_mutex_unlock(&fz_gpu_lock);
  fz_set_last_error(ENOTSUP, 3, "gpu.download failed: Metal runtime unavailable on this host");
  return 0;
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

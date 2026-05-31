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

static int32_t fz_native_gpu_alloc_bytes(int32_t device_handle, int32_t len, int32_t element_size, const char* context) {
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
      fz_set_last_error(ENOMEM, 3, "gpu.alloc failed: Metal buffer allocation returned nil");
      return 0;
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
  fz_set_last_error(ENOTSUP, 3, "gpu.alloc failed: Metal runtime unavailable on this host");
  return 0;
#endif
}

int32_t fz_native_gpu_alloc_f32(int32_t device_handle, int32_t len) {
  return fz_native_gpu_alloc_bytes(device_handle, len, 4, "gpu.alloc_f32 failed: len must be >= 0");
}

int32_t fz_native_gpu_alloc_i32(int32_t device_handle, int32_t len) {
  return fz_native_gpu_alloc_bytes(device_handle, len, 4, "gpu.alloc_i32 failed: len must be >= 0");
}

int32_t fz_native_gpu_alloc_u32(int32_t device_handle, int32_t len) {
  return fz_native_gpu_alloc_bytes(device_handle, len, 4, "gpu.alloc_u32 failed: len must be >= 0");
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

pub(super) fn runtime_shim_section_gpu() -> &'static str {
    r#"
#define FZ_MAX_GPU_DEVICES 16
#define FZ_MAX_GPU_BUFFERS 4096
#define FZ_MAX_GPU_PIPELINES 256
#define FZ_MAX_GPU_EVENTS 4096
#define FZ_GPU_SLICE_TAG 4101

typedef struct {
  int in_use;
  void* device;
  void* command_queue;
} fz_gpu_device_state;

typedef struct {
  int in_use;
  int32_t device_handle;
  int32_t element_size;
  int32_t len;
  void* buffer;
} fz_gpu_buffer_state;

typedef struct {
  int in_use;
  int32_t device_handle;
  int32_t source_id;
  int32_t kernel_name_id;
  void* pipeline;
} fz_gpu_pipeline_state;

typedef struct {
  int in_use;
  int32_t device_handle;
  void* command_buffer;
} fz_gpu_event_state;

static fz_gpu_device_state fz_gpu_devices[FZ_MAX_GPU_DEVICES];
static fz_gpu_buffer_state fz_gpu_buffers[FZ_MAX_GPU_BUFFERS];
static fz_gpu_pipeline_state fz_gpu_pipelines[FZ_MAX_GPU_PIPELINES];
static fz_gpu_event_state fz_gpu_events[FZ_MAX_GPU_EVENTS];
static int32_t fz_gpu_device_count_cached = -1;
static pthread_mutex_t fz_gpu_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_once_t fz_gpu_init_once = PTHREAD_ONCE_INIT;

static void fz_gpu_runtime_init(void);
static int32_t fz_gpu_buffer_alloc_slot(void);
static int32_t fz_gpu_pipeline_alloc_slot(void);
static int32_t fz_gpu_event_alloc_slot(void);

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

static id<MTLCommandQueue> fz_gpu_queue_for_device(int32_t handle) {
  if (handle <= 0 || handle > FZ_MAX_GPU_DEVICES) {
    return nil;
  }
  fz_gpu_device_state* state = &fz_gpu_devices[handle - 1];
  if (!state->in_use || state->device == NULL) {
    return nil;
  }
  if (state->command_queue == NULL) {
    id<MTLDevice> device = (id<MTLDevice>)state->device;
    id<MTLCommandQueue> queue = [device newCommandQueue];
    if (queue == nil) {
      return nil;
    }
    state->command_queue = (void*)queue;
  }
  return (id<MTLCommandQueue>)state->command_queue;
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

static int32_t fz_gpu_pipeline_alloc_slot(void) {
  for (int i = 0; i < FZ_MAX_GPU_PIPELINES; i++) {
    if (!fz_gpu_pipelines[i].in_use) {
      memset(&fz_gpu_pipelines[i], 0, sizeof(fz_gpu_pipelines[i]));
      fz_gpu_pipelines[i].in_use = 1;
      return i + 1;
    }
  }
  return 0;
}

static int32_t fz_gpu_event_alloc_slot(void) {
  for (int i = 0; i < FZ_MAX_GPU_EVENTS; i++) {
    if (!fz_gpu_events[i].in_use) {
      memset(&fz_gpu_events[i], 0, sizeof(fz_gpu_events[i]));
      fz_gpu_events[i].in_use = 1;
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
    [pipeline release];
    fz_set_last_error(ENOSPC, 3, "gpu.launch failed: GPU pipeline registry full");
    return nil;
  }
  fz_gpu_pipeline_state* state = &fz_gpu_pipelines[slot - 1];
  state->device_handle = device_handle;
  state->source_id = source_id;
  state->kernel_name_id = kernel_name_id;
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
        uint32_t offset_u = (uint32_t)offset;
        uint32_t len_u = (uint32_t)len;
        [encoder setBuffer:buffer offset:0 atIndex:buffer_index++];
        [encoder setBytes:&offset_u length:sizeof(uint32_t) atIndex:buffer_index++];
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
    MTLSize threads_per_grid = MTLSizeMake((NSUInteger)((uint64_t)(uint32_t)grid * (uint64_t)(uint32_t)block), 1, 1);
    [encoder dispatchThreads:threads_per_grid threadsPerThreadgroup:threads_per_threadgroup];
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
#endif

int32_t fz_native_gpu_launch0(int32_t kernel_name_id, int32_t source_id, int32_t layout_id, int32_t grid, int32_t block) {
#if defined(__APPLE__) && defined(__OBJC__)
  return fz_gpu_launch_impl(kernel_name_id, source_id, layout_id, grid, block, 0, 0, 0, 0, 0);
#else
  (void)kernel_name_id; (void)source_id; (void)layout_id; (void)grid; (void)block;
  fz_set_last_error(ENOTSUP, 3, "gpu.launch failed: Metal runtime unavailable on this host");
  return 0;
#endif
}

int32_t fz_native_gpu_launch1(int32_t kernel_name_id, int32_t source_id, int32_t layout_id, int32_t grid, int32_t block, uintptr_t a0) {
#if defined(__APPLE__) && defined(__OBJC__)
  return fz_gpu_launch_impl(kernel_name_id, source_id, layout_id, grid, block, 1, a0, 0, 0, 0);
#else
  (void)kernel_name_id; (void)source_id; (void)layout_id; (void)grid; (void)block; (void)a0;
  fz_set_last_error(ENOTSUP, 3, "gpu.launch failed: Metal runtime unavailable on this host");
  return 0;
#endif
}

int32_t fz_native_gpu_launch2(int32_t kernel_name_id, int32_t source_id, int32_t layout_id, int32_t grid, int32_t block, uintptr_t a0, uintptr_t a1) {
#if defined(__APPLE__) && defined(__OBJC__)
  return fz_gpu_launch_impl(kernel_name_id, source_id, layout_id, grid, block, 2, a0, a1, 0, 0);
#else
  (void)kernel_name_id; (void)source_id; (void)layout_id; (void)grid; (void)block; (void)a0; (void)a1;
  fz_set_last_error(ENOTSUP, 3, "gpu.launch failed: Metal runtime unavailable on this host");
  return 0;
#endif
}

int32_t fz_native_gpu_launch3(int32_t kernel_name_id, int32_t source_id, int32_t layout_id, int32_t grid, int32_t block, uintptr_t a0, uintptr_t a1, uintptr_t a2) {
#if defined(__APPLE__) && defined(__OBJC__)
  return fz_gpu_launch_impl(kernel_name_id, source_id, layout_id, grid, block, 3, a0, a1, a2, 0);
#else
  (void)kernel_name_id; (void)source_id; (void)layout_id; (void)grid; (void)block; (void)a0; (void)a1; (void)a2;
  fz_set_last_error(ENOTSUP, 3, "gpu.launch failed: Metal runtime unavailable on this host");
  return 0;
#endif
}

int32_t fz_native_gpu_launch4(int32_t kernel_name_id, int32_t source_id, int32_t layout_id, int32_t grid, int32_t block, uintptr_t a0, uintptr_t a1, uintptr_t a2, uintptr_t a3) {
#if defined(__APPLE__) && defined(__OBJC__)
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

pub(super) fn section() -> &'static str {
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
  uint64_t last_used_epoch;
  void* pipeline;
  void* module;
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
static uint64_t fz_gpu_pipeline_epoch = 0;
static pthread_mutex_t fz_gpu_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_once_t fz_gpu_init_once = PTHREAD_ONCE_INIT;

static void fz_gpu_runtime_init(void);
static int32_t fz_gpu_buffer_alloc_slot(void);
static int32_t fz_gpu_pipeline_alloc_slot(void);
static int32_t fz_gpu_pipeline_evict_lru_slot(void);
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
#elif defined(__linux__)
typedef int fz_hip_error_t;
typedef int fz_hiprtc_result_t;
typedef void* fz_hip_module_t;
typedef void* fz_hip_function_t;
typedef void* fz_hip_stream_t;
typedef void* fz_hiprtc_program_t;

#define FZ_HIP_SUCCESS 0
#define FZ_HIPRTC_SUCCESS 0
#define FZ_HIP_MEMCPY_HOST_TO_DEVICE 1
#define FZ_HIP_MEMCPY_DEVICE_TO_HOST 2

typedef struct {
  void* hip;
  void* hiprtc;
  fz_hip_error_t (*hipGetDeviceCount)(int*);
  fz_hip_error_t (*hipSetDevice)(int);
  fz_hip_error_t (*hipDeviceGetName)(char*, int, int);
  fz_hip_error_t (*hipMemGetInfo)(size_t*, size_t*);
  fz_hip_error_t (*hipMalloc)(void**, size_t);
  fz_hip_error_t (*hipFree)(void*);
  fz_hip_error_t (*hipMemcpy)(void*, const void*, size_t, int);
  fz_hip_error_t (*hipStreamCreate)(fz_hip_stream_t*);
  fz_hip_error_t (*hipStreamSynchronize)(fz_hip_stream_t);
  fz_hip_error_t (*hipStreamDestroy)(fz_hip_stream_t);
  fz_hip_error_t (*hipModuleLoadData)(fz_hip_module_t*, const void*);
  fz_hip_error_t (*hipModuleUnload)(fz_hip_module_t);
  fz_hip_error_t (*hipModuleGetFunction)(fz_hip_function_t*, fz_hip_module_t, const char*);
  fz_hip_error_t (*hipModuleLaunchKernel)(fz_hip_function_t, unsigned int, unsigned int, unsigned int, unsigned int, unsigned int, unsigned int, unsigned int, fz_hip_stream_t, void**, void**);
  const char* (*hipGetErrorString)(fz_hip_error_t);
  fz_hiprtc_result_t (*hiprtcCreateProgram)(fz_hiprtc_program_t*, const char*, const char*, int, const char* const*, const char* const*);
  fz_hiprtc_result_t (*hiprtcCompileProgram)(fz_hiprtc_program_t, int, const char* const*);
  fz_hiprtc_result_t (*hiprtcGetCodeSize)(fz_hiprtc_program_t, size_t*);
  fz_hiprtc_result_t (*hiprtcGetCode)(fz_hiprtc_program_t, char*);
  fz_hiprtc_result_t (*hiprtcGetProgramLogSize)(fz_hiprtc_program_t, size_t*);
  fz_hiprtc_result_t (*hiprtcGetProgramLog)(fz_hiprtc_program_t, char*);
  fz_hiprtc_result_t (*hiprtcDestroyProgram)(fz_hiprtc_program_t*);
  const char* (*hiprtcGetErrorString)(fz_hiprtc_result_t);
} fz_hip_api_state;

static fz_hip_api_state fz_hip;
static char fz_gpu_runtime_error[512];

static void* fz_gpu_dlopen_first(const char* a, const char* b, const char* c) {
  void* handle = dlopen(a, RTLD_LAZY | RTLD_LOCAL);
  if (handle != NULL) {
    return handle;
  }
  handle = dlopen(b, RTLD_LAZY | RTLD_LOCAL);
  if (handle != NULL) {
    return handle;
  }
  return dlopen(c, RTLD_LAZY | RTLD_LOCAL);
}

static int fz_gpu_load_symbol(void* lib, const char* name, void** out) {
  *out = dlsym(lib, name);
  return *out == NULL ? -1 : 0;
}

static const char* fz_gpu_hip_error_string(fz_hip_error_t error) {
  if (fz_hip.hipGetErrorString != NULL) {
    const char* text = fz_hip.hipGetErrorString(error);
    if (text != NULL) {
      return text;
    }
  }
  return "unknown HIP runtime error";
}

static void fz_gpu_runtime_init(void) {
  memset(&fz_hip, 0, sizeof(fz_hip));
  fz_gpu_runtime_error[0] = '\0';
  fz_hip.hip = fz_gpu_dlopen_first("libamdhip64.so", "libamdhip64.so.7", "/opt/rocm/lib/libamdhip64.so");
  fz_hip.hiprtc = fz_gpu_dlopen_first("libhiprtc.so", "libhiprtc.so.7", "/opt/rocm/lib/libhiprtc.so");
  if (fz_hip.hip == NULL || fz_hip.hiprtc == NULL) {
    snprintf(fz_gpu_runtime_error, sizeof(fz_gpu_runtime_error), "ROCm runtime load failed: libamdhip64/libhiprtc unavailable");
    fz_gpu_device_count_cached = 0;
    return;
  }
#define FZ_LOAD_HIP(name) do { if (fz_gpu_load_symbol(fz_hip.hip, #name, (void**)&fz_hip.name) != 0) { snprintf(fz_gpu_runtime_error, sizeof(fz_gpu_runtime_error), "ROCm runtime load failed: missing %s", #name); fz_gpu_device_count_cached = 0; return; } } while (0)
#define FZ_LOAD_HIPRTC(name) do { if (fz_gpu_load_symbol(fz_hip.hiprtc, #name, (void**)&fz_hip.name) != 0) { snprintf(fz_gpu_runtime_error, sizeof(fz_gpu_runtime_error), "ROCm runtime load failed: missing %s", #name); fz_gpu_device_count_cached = 0; return; } } while (0)
  FZ_LOAD_HIP(hipGetDeviceCount);
  FZ_LOAD_HIP(hipSetDevice);
  FZ_LOAD_HIP(hipDeviceGetName);
  FZ_LOAD_HIP(hipMemGetInfo);
  FZ_LOAD_HIP(hipMalloc);
  FZ_LOAD_HIP(hipFree);
  FZ_LOAD_HIP(hipMemcpy);
  FZ_LOAD_HIP(hipStreamCreate);
  FZ_LOAD_HIP(hipStreamSynchronize);
  FZ_LOAD_HIP(hipStreamDestroy);
  FZ_LOAD_HIP(hipModuleLoadData);
  FZ_LOAD_HIP(hipModuleUnload);
  FZ_LOAD_HIP(hipModuleGetFunction);
  FZ_LOAD_HIP(hipModuleLaunchKernel);
  FZ_LOAD_HIP(hipGetErrorString);
  FZ_LOAD_HIPRTC(hiprtcCreateProgram);
  FZ_LOAD_HIPRTC(hiprtcCompileProgram);
  FZ_LOAD_HIPRTC(hiprtcGetCodeSize);
  FZ_LOAD_HIPRTC(hiprtcGetCode);
  FZ_LOAD_HIPRTC(hiprtcGetProgramLogSize);
  FZ_LOAD_HIPRTC(hiprtcGetProgramLog);
  FZ_LOAD_HIPRTC(hiprtcDestroyProgram);
  FZ_LOAD_HIPRTC(hiprtcGetErrorString);
#undef FZ_LOAD_HIP
#undef FZ_LOAD_HIPRTC
  int count = 0;
  fz_hip_error_t status = fz_hip.hipGetDeviceCount(&count);
  if (status != FZ_HIP_SUCCESS || count <= 0) {
    snprintf(fz_gpu_runtime_error, sizeof(fz_gpu_runtime_error), "ROCm device discovery failed: %s", fz_gpu_hip_error_string(status));
    fz_gpu_device_count_cached = 0;
    return;
  }
  if (count > FZ_MAX_GPU_DEVICES) {
    count = FZ_MAX_GPU_DEVICES;
  }
  for (int index = 0; index < count; index++) {
    fz_gpu_devices[index].in_use = 1;
    fz_gpu_devices[index].device = (void*)(intptr_t)index;
  }
  fz_gpu_device_count_cached = count;
}

static int fz_gpu_hip_device_index_for_handle(int32_t handle, int* out_device) {
  if (handle <= 0 || handle > FZ_MAX_GPU_DEVICES) {
    return -1;
  }
  fz_gpu_device_state* state = &fz_gpu_devices[handle - 1];
  if (!state->in_use) {
    return -1;
  }
  *out_device = (int)(intptr_t)state->device;
  return 0;
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

static int32_t fz_gpu_pipeline_evict_lru_slot(void) {
  int32_t slot = 0;
  uint64_t best_epoch = UINT64_MAX;
  for (int i = 0; i < FZ_MAX_GPU_PIPELINES; i++) {
    fz_gpu_pipeline_state* state = &fz_gpu_pipelines[i];
    if (state->in_use && state->pipeline != NULL && state->last_used_epoch < best_epoch) {
      best_epoch = state->last_used_epoch;
      slot = i + 1;
    }
  }
  if (slot <= 0) {
    return 0;
  }
#if defined(__APPLE__) && defined(__OBJC__)
  id<MTLComputePipelineState> pipeline = (id<MTLComputePipelineState>)fz_gpu_pipelines[slot - 1].pipeline;
  if (pipeline != nil) {
    [pipeline release];
  }
#elif defined(__linux__)
  if (fz_gpu_pipelines[slot - 1].module != NULL && fz_hip.hipModuleUnload != NULL) {
    fz_hip.hipModuleUnload((fz_hip_module_t)fz_gpu_pipelines[slot - 1].module);
  }
#endif
  memset(&fz_gpu_pipelines[slot - 1], 0, sizeof(fz_gpu_pipelines[slot - 1]));
  fz_gpu_pipelines[slot - 1].in_use = 1;
  return slot;
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

"#
}

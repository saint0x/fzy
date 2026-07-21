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
#elif defined(__linux__) && defined(FZ_GPU_BACKEND_ROCM)
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
#elif defined(__linux__) && defined(FZ_GPU_BACKEND_CUDA)
typedef int fz_cuda_result_t;
typedef int fz_nvrtc_result_t;
typedef int fz_cuda_device_t;
typedef uint64_t fz_cuda_deviceptr_t;
typedef void* fz_cuda_context_t;
typedef void* fz_cuda_module_t;
typedef void* fz_cuda_function_t;
typedef void* fz_cuda_stream_t;
typedef void* fz_nvrtc_program_t;

#define FZ_CUDA_SUCCESS 0
#define FZ_NVRTC_SUCCESS 0
#define FZ_CUDA_DEVICE_ATTRIBUTE_COMPUTE_CAPABILITY_MAJOR 75
#define FZ_CUDA_DEVICE_ATTRIBUTE_COMPUTE_CAPABILITY_MINOR 76

typedef struct {
  void* cuda;
  void* nvrtc;
  fz_cuda_result_t (*cuInit)(unsigned int);
  fz_cuda_result_t (*cuDeviceGetCount)(int*);
  fz_cuda_result_t (*cuDeviceGet)(fz_cuda_device_t*, int);
  fz_cuda_result_t (*cuDeviceGetName)(char*, int, fz_cuda_device_t);
  fz_cuda_result_t (*cuDeviceTotalMem)(size_t*, fz_cuda_device_t);
  fz_cuda_result_t (*cuDeviceGetAttribute)(int*, int, fz_cuda_device_t);
  fz_cuda_result_t (*cuDevicePrimaryCtxRetain)(fz_cuda_context_t*, fz_cuda_device_t);
  fz_cuda_result_t (*cuCtxSetCurrent)(fz_cuda_context_t);
  fz_cuda_result_t (*cuMemAlloc)(fz_cuda_deviceptr_t*, size_t);
  fz_cuda_result_t (*cuMemFree)(fz_cuda_deviceptr_t);
  fz_cuda_result_t (*cuMemcpyHtoD)(fz_cuda_deviceptr_t, const void*, size_t);
  fz_cuda_result_t (*cuMemcpyDtoH)(void*, fz_cuda_deviceptr_t, size_t);
  fz_cuda_result_t (*cuStreamCreate)(fz_cuda_stream_t*, unsigned int);
  fz_cuda_result_t (*cuStreamSynchronize)(fz_cuda_stream_t);
  fz_cuda_result_t (*cuStreamDestroy)(fz_cuda_stream_t);
  fz_cuda_result_t (*cuModuleLoadData)(fz_cuda_module_t*, const void*);
  fz_cuda_result_t (*cuModuleUnload)(fz_cuda_module_t);
  fz_cuda_result_t (*cuModuleGetFunction)(fz_cuda_function_t*, fz_cuda_module_t, const char*);
  fz_cuda_result_t (*cuLaunchKernel)(fz_cuda_function_t, unsigned int, unsigned int, unsigned int, unsigned int, unsigned int, unsigned int, unsigned int, fz_cuda_stream_t, void**, void**);
  fz_cuda_result_t (*cuGetErrorString)(fz_cuda_result_t, const char**);
  fz_nvrtc_result_t (*nvrtcCreateProgram)(fz_nvrtc_program_t*, const char*, const char*, int, const char* const*, const char* const*);
  fz_nvrtc_result_t (*nvrtcCompileProgram)(fz_nvrtc_program_t, int, const char* const*);
  fz_nvrtc_result_t (*nvrtcGetPTXSize)(fz_nvrtc_program_t, size_t*);
  fz_nvrtc_result_t (*nvrtcGetPTX)(fz_nvrtc_program_t, char*);
  fz_nvrtc_result_t (*nvrtcGetProgramLogSize)(fz_nvrtc_program_t, size_t*);
  fz_nvrtc_result_t (*nvrtcGetProgramLog)(fz_nvrtc_program_t, char*);
  fz_nvrtc_result_t (*nvrtcDestroyProgram)(fz_nvrtc_program_t*);
  const char* (*nvrtcGetErrorString)(fz_nvrtc_result_t);
} fz_cuda_api_state;

static fz_cuda_api_state fz_cuda;
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

static int fz_gpu_load_symbol_any(void* lib, const char* primary, const char* fallback, void** out) {
  *out = dlsym(lib, primary);
  if (*out != NULL) {
    return 0;
  }
  *out = dlsym(lib, fallback);
  return *out == NULL ? -1 : 0;
}

static const char* fz_gpu_cuda_error_string(fz_cuda_result_t error) {
  if (fz_cuda.cuGetErrorString != NULL) {
    const char* text = NULL;
    if (fz_cuda.cuGetErrorString(error, &text) == FZ_CUDA_SUCCESS && text != NULL) {
      return text;
    }
  }
  return "unknown CUDA driver error";
}

static void fz_gpu_runtime_init(void) {
  memset(&fz_cuda, 0, sizeof(fz_cuda));
  fz_gpu_runtime_error[0] = '\0';
  fz_cuda.cuda = fz_gpu_dlopen_first("libcuda.so.1", "libcuda.so", "/usr/lib/x86_64-linux-gnu/libcuda.so.1");
#if defined(FZ_GPU_BACKEND_NVPTX)
  fz_cuda.nvrtc = NULL;
  if (fz_cuda.cuda == NULL) {
    snprintf(fz_gpu_runtime_error, sizeof(fz_gpu_runtime_error), "NVPTX runtime load failed: libcuda unavailable");
    fz_gpu_device_count_cached = 0;
    return;
  }
#else
  fz_cuda.nvrtc = fz_gpu_dlopen_first("libnvrtc.so", "libnvrtc.so.12", "/usr/local/cuda/targets/x86_64-linux/lib/libnvrtc.so");
  if (fz_cuda.cuda == NULL || fz_cuda.nvrtc == NULL) {
    snprintf(fz_gpu_runtime_error, sizeof(fz_gpu_runtime_error), "CUDA runtime load failed: libcuda/libnvrtc unavailable");
    fz_gpu_device_count_cached = 0;
    return;
  }
#endif
#define FZ_LOAD_CUDA(name) do { if (fz_gpu_load_symbol(fz_cuda.cuda, #name, (void**)&fz_cuda.name) != 0) { snprintf(fz_gpu_runtime_error, sizeof(fz_gpu_runtime_error), "CUDA runtime load failed: missing %s", #name); fz_gpu_device_count_cached = 0; return; } } while (0)
#define FZ_LOAD_CUDA_ANY(field, primary, fallback) do { if (fz_gpu_load_symbol_any(fz_cuda.cuda, primary, fallback, (void**)&fz_cuda.field) != 0) { snprintf(fz_gpu_runtime_error, sizeof(fz_gpu_runtime_error), "CUDA runtime load failed: missing %s", primary); fz_gpu_device_count_cached = 0; return; } } while (0)
#define FZ_LOAD_NVRTC(name) do { if (fz_gpu_load_symbol(fz_cuda.nvrtc, #name, (void**)&fz_cuda.name) != 0) { snprintf(fz_gpu_runtime_error, sizeof(fz_gpu_runtime_error), "CUDA runtime load failed: missing %s", #name); fz_gpu_device_count_cached = 0; return; } } while (0)
  FZ_LOAD_CUDA(cuInit);
  FZ_LOAD_CUDA(cuDeviceGetCount);
  FZ_LOAD_CUDA(cuDeviceGet);
  FZ_LOAD_CUDA(cuDeviceGetName);
  FZ_LOAD_CUDA_ANY(cuDeviceTotalMem, "cuDeviceTotalMem_v2", "cuDeviceTotalMem");
  FZ_LOAD_CUDA(cuDeviceGetAttribute);
  FZ_LOAD_CUDA(cuDevicePrimaryCtxRetain);
  FZ_LOAD_CUDA(cuCtxSetCurrent);
  FZ_LOAD_CUDA_ANY(cuMemAlloc, "cuMemAlloc_v2", "cuMemAlloc");
  FZ_LOAD_CUDA_ANY(cuMemFree, "cuMemFree_v2", "cuMemFree");
  FZ_LOAD_CUDA_ANY(cuMemcpyHtoD, "cuMemcpyHtoD_v2", "cuMemcpyHtoD");
  FZ_LOAD_CUDA_ANY(cuMemcpyDtoH, "cuMemcpyDtoH_v2", "cuMemcpyDtoH");
  FZ_LOAD_CUDA(cuStreamCreate);
  FZ_LOAD_CUDA(cuStreamSynchronize);
  FZ_LOAD_CUDA_ANY(cuStreamDestroy, "cuStreamDestroy_v2", "cuStreamDestroy");
  FZ_LOAD_CUDA(cuModuleLoadData);
  FZ_LOAD_CUDA(cuModuleUnload);
  FZ_LOAD_CUDA(cuModuleGetFunction);
  FZ_LOAD_CUDA(cuLaunchKernel);
  FZ_LOAD_CUDA(cuGetErrorString);
#if !defined(FZ_GPU_BACKEND_NVPTX)
  FZ_LOAD_NVRTC(nvrtcCreateProgram);
  FZ_LOAD_NVRTC(nvrtcCompileProgram);
  FZ_LOAD_NVRTC(nvrtcGetPTXSize);
  FZ_LOAD_NVRTC(nvrtcGetPTX);
  FZ_LOAD_NVRTC(nvrtcGetProgramLogSize);
  FZ_LOAD_NVRTC(nvrtcGetProgramLog);
  FZ_LOAD_NVRTC(nvrtcDestroyProgram);
  FZ_LOAD_NVRTC(nvrtcGetErrorString);
#endif
#undef FZ_LOAD_CUDA
#undef FZ_LOAD_CUDA_ANY
#undef FZ_LOAD_NVRTC
  fz_cuda_result_t status = fz_cuda.cuInit(0);
  if (status != FZ_CUDA_SUCCESS) {
    snprintf(fz_gpu_runtime_error, sizeof(fz_gpu_runtime_error), "CUDA driver init failed: %s", fz_gpu_cuda_error_string(status));
    fz_gpu_device_count_cached = 0;
    return;
  }
  int count = 0;
  status = fz_cuda.cuDeviceGetCount(&count);
  if (status != FZ_CUDA_SUCCESS || count <= 0) {
    snprintf(fz_gpu_runtime_error, sizeof(fz_gpu_runtime_error), "CUDA device discovery failed: %s", fz_gpu_cuda_error_string(status));
    fz_gpu_device_count_cached = 0;
    return;
  }
  if (count > FZ_MAX_GPU_DEVICES) {
    count = FZ_MAX_GPU_DEVICES;
  }
  int live_count = 0;
  for (int index = 0; index < count; index++) {
    fz_cuda_device_t device = 0;
    fz_cuda_context_t context = NULL;
    if (fz_cuda.cuDeviceGet(&device, index) != FZ_CUDA_SUCCESS) {
      continue;
    }
    status = fz_cuda.cuDevicePrimaryCtxRetain(&context, device);
    if (status != FZ_CUDA_SUCCESS || context == NULL) {
      continue;
    }
    fz_gpu_devices[live_count].in_use = 1;
    fz_gpu_devices[live_count].device = (void*)(intptr_t)device;
    fz_gpu_devices[live_count].command_queue = context;
    live_count++;
  }
  fz_gpu_device_count_cached = live_count;
}

static int fz_gpu_cuda_device_for_handle(int32_t handle, fz_cuda_device_t* out_device, fz_cuda_context_t* out_context) {
  if (handle <= 0 || handle > FZ_MAX_GPU_DEVICES) {
    return -1;
  }
  fz_gpu_device_state* state = &fz_gpu_devices[handle - 1];
  if (!state->in_use || state->command_queue == NULL) {
    return -1;
  }
  *out_device = (fz_cuda_device_t)(intptr_t)state->device;
  *out_context = (fz_cuda_context_t)state->command_queue;
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
  if (fz_gpu_pipelines[slot - 1].module != NULL) {
#if defined(FZ_GPU_BACKEND_ROCM)
    if (fz_hip.hipModuleUnload != NULL) {
    fz_hip.hipModuleUnload((fz_hip_module_t)fz_gpu_pipelines[slot - 1].module);
    }
#elif defined(FZ_GPU_BACKEND_CUDA)
    if (fz_cuda.cuModuleUnload != NULL) {
      fz_cuda.cuModuleUnload((fz_cuda_module_t)fz_gpu_pipelines[slot - 1].module);
    }
#endif
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

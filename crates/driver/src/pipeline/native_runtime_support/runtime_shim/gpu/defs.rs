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

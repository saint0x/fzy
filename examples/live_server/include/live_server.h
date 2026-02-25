#ifndef FOZZY_LIVE_SERVER_H
#define FOZZY_LIVE_SERVER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

uint32_t server_hash32(const uint8_t* ptr, uint64_t len);
int32_t server_write(int32_t fd, const uint8_t* ptr, uint64_t len);

#ifdef __cplusplus
}
#endif

#endif

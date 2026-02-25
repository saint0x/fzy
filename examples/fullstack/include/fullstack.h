#ifndef FOZZY_FULLSTACK_H
#define FOZZY_FULLSTACK_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

int32_t fs_open(const uint8_t* path, uint64_t len);
int32_t fs_write(int32_t fd, const uint8_t* ptr, uint64_t len);
uint32_t hash32(const uint8_t* ptr, uint64_t len);

#ifdef __cplusplus
}
#endif

#endif

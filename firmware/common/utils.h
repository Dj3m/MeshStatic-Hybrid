#ifndef UTILS_H
#define UTILS_H
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

typedef enum { LOG_ERROR, LOG_WARN, LOG_INFO, LOG_DEBUG } LogLevel;

void log_message(LogLevel level, const char* format, ...);
char* byte_to_binary(uint8_t value, char* buf);
float calculate_average(float* values, uint8_t count);
bool is_valid_mac(const uint8_t* mac);
void copy_mac(uint8_t* dest, const uint8_t* src);
bool compare_mac(const uint8_t* mac1, const uint8_t* mac2);
uint16_t calculate_checksum(const void* data, size_t len);
void delay_ms(uint32_t ms);
uint32_t get_current_time(void);
bool is_time_elapsed(uint32_t start_time, uint32_t timeout_ms);
void memzero(void* data, size_t len);

#define MIN(a,b) ((a)<(b)?(a):(b))
#define MAX(a,b) ((a)>(b)?(a):(b))
#endif

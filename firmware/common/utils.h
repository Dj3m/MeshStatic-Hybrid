// utils.h - Заголовочный файл для вспомогательных функций
#ifndef UTILS_H
#define UTILS_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#define MAC_STR_LEN 18 // Длина строки MAC: 17 символов + нулевой терминатор

typedef enum {
    LOG_ERROR,
    LOG_WARN,
    LOG_INFO,
    LOG_DEBUG
} LogLevel;

// Функции работы с MAC-адресами
void mac_to_string(const uint8_t* mac, char* buffer);
bool string_to_mac(const char* str, uint8_t* mac);
bool is_broadcast_mac(const uint8_t* mac);
bool compare_mac(const uint8_t* mac1, const uint8_t* mac2);
void copy_mac(uint8_t* dest, const uint8_t* src);

// Утилиты
uint16_t fletcher16(const uint8_t* data, size_t len);
void log_message(LogLevel level, const char* format, ...);
const char* byte_to_binary(uint8_t value);
float calculate_average(const float* values, uint8_t count);
float clamp_float(float value, float min, float max);
float lerp(float a, float b, float t);
uint16_t simple_hash(const char* str);

#endif // UTILS_H
// utils.h
// Вспомогательные функции для безопасной работы с памятью.
#pragma once
#include <stdint.h>
#include <stddef.h>
#include <string.h>

// Сравнение данных за постоянное время (защита от атак по времени)
static inline bool constant_time_compare(const void *a, const void *b, size_t len) {
    const uint8_t *a_bytes = (const uint8_t *)a;
    const uint8_t *b_bytes = (const uint8_t *)b;
    uint8_t result = 0;
    
    for (size_t i = 0; i < len; i++) {
        result |= a_bytes[i] ^ b_bytes[i];
    }
    
    return result == 0;
}

// Безопасное затирание чувствительных данных из памяти
static inline void memzero(void *data, size_t len) {
    if (data == NULL) return;
    
    volatile uint8_t *volatile_ptr = (volatile uint8_t *)data;
    for (size_t i = 0; i < len; i++) {
        volatile_ptr[i] = 0;
    }
}

// Конвертация MAC-адреса в строку (для логов)
static inline void mac_to_str(char *buf, size_t buf_len, const uint8_t mac[6]) {
    if (buf_len < 18) return;
    snprintf(buf, buf_len, "%02X:%02X:%02X:%02X:%02X:%02X",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}
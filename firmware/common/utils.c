// utils.c - Реализация вспомогательных функций
#include "utils.h"

// Сравнение в постоянном времени
bool constant_time_compare(const void *a, const void *b, size_t len) {
    const uint8_t *pa = (const uint8_t *)a;
    const uint8_t *pb = (const uint8_t *)b;
    uint8_t result = 0;
    
    for (size_t i = 0; i < len; i++) {
        result |= pa[i] ^ pb[i];
    }
    
    return result == 0;
}

// Безопасное обнуление
void secure_zero(void *ptr, size_t len) {
    volatile uint8_t *p = (volatile uint8_t *)ptr;
    while (len--) {
        *p++ = 0;
    }
}

// Статический буфер для двоичного представления (не потокобезопасно)
static char binary_buf[9];

const char* byte_to_binary(uint8_t value) {
    for (int i = 7; i >= 0; i--) {
        binary_buf[7 - i] = (value & (1 << i)) ? '1' : '0';
    }
    binary_buf[8] = '\0';
    return binary_buf;
}

// Вычисление среднего
float calculate_average(const float values[], uint8_t count) {
    if (count == 0) return 0.0f;
    float sum = 0.0f;
    for (uint8_t i = 0; i < count; i++) {
        sum += values[i];
    }
    return sum / count;
}
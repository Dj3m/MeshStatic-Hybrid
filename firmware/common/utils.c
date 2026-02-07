// utils.c - Общие утилиты для MeshStatic
#include "utils.h"
#include <string.h>
#include <stdio.h>

// Простая реализация логгирования
void log_message(LogLevel level, const char* format, ...) {
    const char* level_str;
    switch(level) {
        case LOG_ERROR: level_str = "ERROR"; break;
        case LOG_WARN:  level_str = "WARN";  break;
        case LOG_INFO:  level_str = "INFO";  break;
        case LOG_DEBUG: level_str = "DEBUG"; break;
        default:        level_str = "UNKNOWN"; break;
    }
    
    // Для примера просто игнорируем вывод
    (void)level_str;
    (void)format;
}

// Конвертация байта в бинарную строку
char* byte_to_binary(uint8_t value, char* buf) {
    for (int i = 7; i >= 0; i--) {
        buf[7 - i] = (value & (1 << i)) ? '1' : '0';
    }
    buf[8] = '\0';
    return buf;
}

// Расчет среднего значения
float calculate_average(float* values, uint8_t count) {
    if (count == 0) return 0.0f;
    
    float sum = 0.0f;
    for (uint8_t i = 0; i < count; i++) {
        sum += values[i];
    }
    return sum / count;
}

// Проверка валидности MAC-адреса
bool is_valid_mac(const uint8_t* mac) {
    if (!mac) return false;
    
    // Проверяем, не является ли это broadcast или нулевым адресом
    bool all_zero = true;
    bool all_ff = true;
    
    for (int i = 0; i < 6; i++) {
        if (mac[i] != 0x00) all_zero = false;
        if (mac[i] != 0xFF) all_ff = false;
    }
    
    return !(all_zero || all_ff);
}

// Копирование MAC-адреса
void copy_mac(uint8_t* dest, const uint8_t* src) {
    if (dest && src) {
        memcpy(dest, src, 6);
    }
}

// Сравнение MAC-адресов
bool compare_mac(const uint8_t* mac1, const uint8_t* mac2) {
    if (!mac1 || !mac2) return false;
    return memcmp(mac1, mac2, 6) == 0;
}

// Генерация контрольной суммы (упрощенная версия)
uint16_t calculate_checksum(const void* data, size_t len) {
    if (!data || len == 0) return 0;
    
    const uint8_t* bytes = (const uint8_t*)data;
    uint16_t sum = 0;
    
    for (size_t i = 0; i < len; i++) {
        sum += bytes[i];
    }
    
    return sum;
}

// Задержка (заглушка для портирования)
void delay_ms(uint32_t ms) {
    // Реализация зависит от платформы
    // Для тестирования просто игнорируем
    (void)ms;
}

// Получение текущего времени (заглушка)
uint32_t get_current_time(void) {
    // Реализация зависит от платформы
    return 0;
}

// Проверка, истекло ли время
bool is_time_elapsed(uint32_t start_time, uint32_t timeout_ms) {
    uint32_t current = get_current_time();
    
    // Обработка переполнения
    if (current >= start_time) {
        return (current - start_time) >= timeout_ms;
    } else {
        // Случай переполнения uint32_t
        return ((UINT32_MAX - start_time) + current + 1) >= timeout_ms;
    }
}

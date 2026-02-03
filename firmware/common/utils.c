// utils.c - Вспомогательные функции для MeshStatic
#include "utils.h"
#include <string.h>
#include <stdio.h>

// Конвертация MAC-адреса в строку AA:BB:CC:DD:EE:FF
void mac_to_string(const uint8_t* mac, char* buffer) {
    if (!buffer) return;
    snprintf(buffer, MAC_STR_LEN, "%02X:%02X:%02X:%02X:%02X:%02X",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

// Конвертация строки с MAC в массив байт
bool string_to_mac(const char* str, uint8_t* mac) {
    if (!str || !mac) return false;
    
    int values[6];
    int count = sscanf(str, "%x:%x:%x:%x:%x:%x",
                       &values[0], &values[1], &values[2],
                       &values[3], &values[4], &values[5]);
    
    if (count != 6) return false;
    
    for (int i = 0; i < 6; i++) {
        mac[i] = (uint8_t)values[i];
    }
    return true;
}

// Проверка, является ли MAC широковещательным
bool is_broadcast_mac(const uint8_t* mac) {
    for (int i = 0; i < 6; i++) {
        if (mac[i] != 0xFF) return false;
    }
    return true;
}

// Сравнение двух MAC-адресов
bool compare_mac(const uint8_t* mac1, const uint8_t* mac2) {
    return memcmp(mac1, mac2, 6) == 0;
}

// Копирование MAC-адреса
void copy_mac(uint8_t* dest, const uint8_t* src) {
    memcpy(dest, src, 6);
}

// Расчет контрольной суммы Fletcher-16 (быстрая и простая)
uint16_t fletcher16(const uint8_t* data, size_t len) {
    uint16_t sum1 = 0;
    uint16_t sum2 = 0;
    
    for (size_t i = 0; i < len; i++) {
        sum1 = (sum1 + data[i]) % 255;
        sum2 = (sum2 + sum1) % 255;
    }
    
    return (sum2 << 8) | sum1;
}

// Простой логгер (заглушка, в реальности подключите нормальный логгер)
void log_message(LogLevel level, const char* format, ...) {
    // Для примера просто игнорируем вывод
    (void)level;
    (void)format;
    // В реальном проекте здесь будет:
    // va_list args;
    // va_start(args, format);
    // vprintf(format, args);
    // va_end(args);
}

// Конвертация байта в бинарную строку (для отладки)
const char* byte_to_binary(uint8_t value) {
    static char buf[9]; // 8 бит + нулевой терминатор
    for (int i = 7; i >= 0; i--) {
        buf[7 - i] = (value & (1 << i)) ? '1' : '0';
    }
    buf[8] = '\0';
    return buf;
}

// Расчет среднего значения массива
float calculate_average(const float* values, uint8_t count) {
    if (count == 0) return 0.0f;
    float sum = 0.0f;
    for (uint8_t i = 0; i < count; i++) {
        sum += values[i];
    }
    return sum / count;
}

// Ограничение значения в диапазоне
float clamp_float(float value, float min, float max) {
    if (value < min) return min;
    if (value > max) return max;
    return value;
}

// Линейная интерполяция
float lerp(float a, float b, float t) {
    return a + (b - a) * t;
}

// Простое хеширование строки (для групповых ID и т.д.)
uint16_t simple_hash(const char* str) {
    uint16_t hash = 0;
    while (*str) {
        hash = (hash << 5) + hash + *str++;
    }
    return hash;
}
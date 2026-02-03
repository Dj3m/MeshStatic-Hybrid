// utils.c - Общие утилиты для MeshStatic
#include "utils.h"
#include <string.h>
#include <stdio.h>
#include <stdarg.h>

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

// Подсчет количества установленных битов
uint8_t count_bits(uint32_t value) {
    uint8_t count = 0;
    while (value) {
        count += value & 1;
        value >>= 1;
    }
    return count;
}

// Безопасное копирование памяти
size_t safe_memcpy(void* dst, size_t dst_len, const void* src, size_t src_len) {
    if (!dst || !src || src_len > dst_len) {
        return 0;
    }
    
    memcpy(dst, src, src_len);
    return src_len;
}

// Сравнение в константном времени
bool constant_time_memcmp(const void* a, const void* b, size_t len) {
    const uint8_t* pa = (const uint8_t*)a;
    const uint8_t* pb = (const uint8_t*)b;
    uint8_t result = 0;
    
    for (size_t i = 0; i < len; i++) {
        result |= pa[i] ^ pb[i];
    }
    
    return result == 0;
}

// Преобразование uint32_t в little-endian байты
void write_le32(uint8_t* buf, uint32_t value) {
    buf[0] = (uint8_t)(value);
    buf[1] = (uint8_t)(value >> 8);
    buf[2] = (uint8_t)(value >> 16);
    buf[3] = (uint8_t)(value >> 24);
}

// Чтение uint32_t из little-endian байтов
uint32_t read_le32(const uint8_t* buf) {
    return ((uint32_t)buf[0]) |
           ((uint32_t)buf[1] << 8) |
           ((uint32_t)buf[2] << 16) |
           ((uint32_t)buf[3] << 24);
}

// Преобразование uint32_t в big-endian байты
void write_be32(uint8_t* buf, uint32_t value) {
    buf[0] = (uint8_t)(value >> 24);
    buf[1] = (uint8_t)(value >> 16);
    buf[2] = (uint8_t)(value >> 8);
    buf[3] = (uint8_t)(value);
}

// Чтение uint32_t из big-endian байтов
uint32_t read_be32(const uint8_t* buf) {
    return ((uint32_t)buf[0] << 24) |
           ((uint32_t)buf[1] << 16) |
           ((uint32_t)buf[2] << 8) |
           ((uint32_t)buf[3]);
}

// Генерация случайного числа в диапазоне
uint32_t random_range(uint32_t min, uint32_t max) {
    if (min > max) {
        uint32_t temp = min;
        min = max;
        max = temp;
    }
    
    // Простой псевдослучайный генератор
    static uint32_t seed = 123456789;
    seed = seed * 1103515245 + 12345;
    
    return min + (seed % (max - min + 1));
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
    static uint32_t time_counter = 0;
    return time_counter++;
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

// Безопасное обнуление памяти
void memzero(void* data, size_t len) {
    if (data && len > 0) {
        memset(data, 0, len);
    }
}

// Конвертация строки в нижний регистр (in-place)
void str_tolower(char* str) {
    if (!str) return;
    
    for (char* p = str; *p; ++p) {
        if (*p >= 'A' && *p <= 'Z') {
            *p += ('a' - 'A');
        }
    }
}

// Обрезка пробелов в начале и конце строки
char* str_trim(char* str) {
    if (!str) return NULL;
    
    // Пропускаем начальные пробелы
    char* start = str;
    while (*start == ' ' || *start == '\t' || *start == '\n' || *start == '\r') {
        start++;
    }
    
    // Если строка состоит только из пробелов
    if (*start == '\0') {
        str[0] = '\0';
        return str;
    }
    
    // Находим конец строки
    char* end = start;
    char* last_non_space = start;
    
    while (*end != '\0') {
        if (*end != ' ' && *end != '\t' && *end != '\n' && *end != '\r') {
            last_non_space = end;
        }
        end++;
    }
    
    // Обрезаем конечные пробелы
    *(last_non_space + 1) = '\0';
    
    // Сдвигаем строку если нужно
    if (start != str) {
        size_t len = strlen(start) + 1;
        memmove(str, start, len);
    }
    
    return str;
}

// Проверка, начинается ли строка с префикса
bool str_starts_with(const char* str, const char* prefix) {
    if (!str || !prefix) return false;
    
    while (*prefix) {
        if (*str != *prefix) return false;
        str++;
        prefix++;
    }
    
    return true;
}

// Проверка, заканчивается ли строка суффиксом
bool str_ends_with(const char* str, const char* suffix) {
    if (!str || !suffix) return false;
    
    size_t str_len = strlen(str);
    size_t suffix_len = strlen(suffix);
    
    if (suffix_len > str_len) return false;
    
    return strcmp(str + str_len - suffix_len, suffix) == 0;
}

// Форматирование MAC-адреса в строку
char* mac_to_string(const uint8_t* mac, char* buf, size_t buf_len) {
    if (!mac || !buf || buf_len < 18) {
        return NULL;
    }
    
    snprintf(buf, buf_len, "%02X:%02X:%02X:%02X:%02X:%02X",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    
    return buf;
}

// Разбор MAC-адреса из строки
bool string_to_mac(const char* str, uint8_t* mac) {
    if (!str || !mac) return false;
    
    int values[6];
    int count = sscanf(str, "%02X:%02X:%02X:%02X:%02X:%02X",
                       &values[0], &values[1], &values[2],
                       &values[3], &values[4], &values[5]);
    
    if (count != 6) {
        return false;
    }
    
    for (int i = 0; i < 6; i++) {
        mac[i] = (uint8_t)values[i];
    }
    
    return true;
}
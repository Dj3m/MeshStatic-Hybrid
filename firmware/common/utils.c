// utils.c
// Общие утилиты для MeshStatic-Hybrid. Безопасное копирование, преобразования, CRC32.

#include "utils.h"
#include <string.h>
#include <stdio.h>
#include <math.h>

// ==================== РАБОТА С MAC-АДРЕСАМИ ====================

char* mac_to_string(const uint8_t mac[6], char* buffer, size_t buf_len) {
    if (buffer == NULL || buf_len < 18) return NULL;
    snprintf(buffer, buf_len, "%02X:%02X:%02X:%02X:%02X:%02X",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return buffer;
}

bool string_to_mac(const char* str, uint8_t mac[6]) {
    if (str == NULL || mac == NULL) return false;
    
    int values[6];
    int count = sscanf(str, "%x:%x:%x:%x:%x:%x",
                      &values[0], &values[1], &values[2],
                      &values[3], &values[4], &values[5]);
    
    if (count != 6) return false;
    
    for (int i = 0; i < 6; i++) {
        if (values[i] < 0 || values[i] > 0xFF) return false;
        mac[i] = (uint8_t)values[i];
    }
    
    return true;
}

bool mac_equal(const uint8_t mac1[6], const uint8_t mac2[6]) {
    return memcmp(mac1, mac2, 6) == 0;
}

void copy_mac(uint8_t dst[6], const uint8_t src[6]) {
    memcpy(dst, src, 6);
}

bool is_broadcast_mac(const uint8_t mac[6]) {
    const uint8_t broadcast[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    return mac_equal(mac, broadcast);
}

bool is_zero_mac(const uint8_t mac[6]) {
    const uint8_t zero[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    return mac_equal(mac, zero);
}

// ==================== CRC32 РАСЧЕТ ====================

// Таблица для быстрого расчета CRC32
static const uint32_t crc32_table[256] = {
    0x00000000, 0x77073096, 0xee0e612c, 0x990951ba, 0x076dc419, 0x706af48f,
    0xe963a535, 0x9e6495a3, 0x0edb8832, 0x79dcb8a4, 0xe0d5e91e, 0x97d2d988,
    0x09b64c2b, 0x7eb17cbd, 0xe7b82d07, 0x90bf1d91, 0x1db71064, 0x6ab020f2,
    0xf3b97148, 0x84be41de, 0x1adad47d, 0x6ddde4eb, 0xf4d4b551, 0x83d385c7,
    0x136c9856, 0x646ba8c0, 0xfd62f97a, 0x8a65c9ec, 0x14015c4f, 0x63066cd9,
    0xfa0f3d63, 0x8d080df5, 0x3b6e20c8, 0x4c69105e, 0xd56041e4, 0xa2677172,
    0x3c03e4d1, 0x4b04d447, 0xd20d85fd, 0xa50ab56b, 0x35b5a8fa, 0x42b2986c,
    0xdbbbc9d6, 0xacbcf940, 0x32d86ce3, 0x45df5c75, 0xdcd60dcf, 0xabd13d59,
    0x26d930ac, 0x51de003a, 0xc8d75180, 0xbfd06116, 0x21b4f4b5, 0x56b3c423,
    0xcfba9599, 0xb8bda50f, 0x2802b89e, 0x5f058808, 0xc60cd9b2, 0xb10be924,
    0x2f6f7c87, 0x58684c11, 0xc1611dab, 0xb6662d3d, 0x76dc4190, 0x01db7106,
    0x98d220bc, 0xefd5102a, 0x71b18589, 0x06b6b51f, 0x9fbfe4a5, 0xe8b8d433,
    0x7807c9a2, 0x0f00f934, 0x9609a88e, 0xe10e9818, 0x7f6a0dbb, 0x086d3d2d,
    0x91646c97, 0xe6635c01, 0x6b6b51f4, 0x1c6c6162, 0x856530d8, 0xf262004e,
    0x6c0695ed, 0x1b01a57b, 0x8208f4c1, 0xf50fc457, 0x65b0d9c6, 0x12b7e950,
    0x8bbeb8ea, 0xfcb9887c, 0x62dd1ddf, 0x15da2d49, 0x8cd37cf3, 0xfbd44c65,
    0x4db26158, 0x3ab551ce, 0xa3bc0074, 0xd4bb30e2, 0x4adfa541, 0x3dd895d7,
    0xa4d1c46d, 0xd3d6f4fb, 0x4369e96a, 0x346ed9fc, 0xad678846, 0xda60b8d0,
    0x44042d73, 0x33031de5, 0xaa0a4c5f, 0xdd0d7cc9, 0x5005713c, 0x270241aa,
    0xbe0b1010, 0xc90c2086, 0x5768b525, 0x206f85b3, 0xb966d409, 0xce61e49f,
    0x5edef90e, 0x29d9c998, 0xb0d09822, 0xc7d7a8b4, 0x59b33d17, 0x2eb40d81,
    0xb7bd5c3b, 0xc0ba6cad, 0xedb88320, 0x9abfb3b6, 0x03b6e20c, 0x74b1d29a,
    0xead54739, 0x9dd277af, 0x04db2615, 0x73dc1683, 0xe3630b12, 0x94643b84,
    0x0d6d6a3e, 0x7a6a5aa8, 0xe40ecf0b, 0x9309ff9d, 0x0a00ae27, 0x7d079eb1,
    0xf00f9344, 0x8708a3d2, 0x1e01f268, 0x6906c2fe, 0xf762575d, 0x806567cb,
    0x196c3671, 0x6e6b06e7, 0xfed41b76, 0x89d32be0, 0x10da7a5a, 0x67dd4acc,
    0xf9b9df6f, 0x8ebeeff9, 0x17b7be43, 0x60b08ed5, 0xd6d6a3e8, 0xa1d1937e,
    0x38d8c2c4, 0x4fdff252, 0xd1bb67f1, 0xa6bc5767, 0x3fb506dd, 0x48b2364b,
    0xd80d2bda, 0xaf0a1b4c, 0x36034af6, 0x41047a60, 0xdf60efc3, 0xa867df55,
    0x316e8eef, 0x4669be79, 0xcb61b38c, 0xbc66831a, 0x256fd2a0, 0x5268e236,
    0xcc0c7795, 0xbb0b4703, 0x220216b9, 0x5505262f, 0xc5ba3bbe, 0xb2bd0b28,
    0x2bb45a92, 0x5cb36a04, 0xc2d7ffa7, 0xb5d0cf31, 0x2cd99e8b, 0x5bdeae1d,
    0x9b64c2b0, 0xec63f226, 0x756aa39c, 0x026d930a, 0x9c0906a9, 0xeb0e363f,
    0x72076785, 0x05005713, 0x95bf4a82, 0xe2b87a14, 0x7bb12bae, 0x0cb61b38,
    0x92d28e9b, 0xe5d5be0d, 0x7cdcefb7, 0x0bdbdf21, 0x86d3d2d4, 0xf1d4e242,
    0x68ddb3f8, 0x1fda836e, 0x81be16cd, 0xf6b9265b, 0x6fb077e1, 0x18b74777,
    0x88085ae6, 0xff0f6a70, 0x66063bca, 0x11010b5c, 0x8f659eff, 0xf862ae69,
    0x616bffd3, 0x166ccf45, 0xa00ae278, 0xd70dd2ee, 0x4e048354, 0x3903b3c2,
    0xa7672661, 0xd06016f7, 0x4969474d, 0x3e6e77db, 0xaed16a4a, 0xd9d65adc,
    0x40df0b66, 0x37d83bf0, 0xa9bcae53, 0xdebb9ec5, 0x47b2cf7f, 0x30b5ffe9,
    0xbdbdf21c, 0xcabac28a, 0x53b39330, 0x24b4a3a6, 0xbad03605, 0xcdd70693,
    0x54de5729, 0x23d967bf, 0xb3667a2e, 0xc4614ab8, 0x5d681b02, 0x2a6f2b94,
    0xb40bbe37, 0xc30c8ea1, 0x5a05df1b, 0x2d02ef8d
};

uint32_t calculate_crc32(const void* data, size_t length, uint32_t previous_crc) {
    const uint8_t* bytes = (const uint8_t*)data;
    uint32_t crc = previous_crc ^ 0xFFFFFFFF;
    
    for (size_t i = 0; i < length; i++) {
        uint8_t table_index = (crc ^ bytes[i]) & 0xFF;
        crc = (crc >> 8) ^ crc32_table[table_index];
    }
    
    return crc ^ 0xFFFFFFFF;
}

uint32_t calculate_crc32_simple(const void* data, size_t length) {
    return calculate_crc32(data, length, 0);
}

// ==================== БЕЗОПАСНОЕ КОПИРОВАНИЕ И СРАВНЕНИЕ ====================

void secure_copy(void* dst, const void* src, size_t len) {
    if (dst == NULL || src == NULL || len == 0) return;
    
    // Копируем байты
    uint8_t* d = (uint8_t*)dst;
    const uint8_t* s = (const uint8_t*)src;
    
    for (size_t i = 0; i < len; i++) {
        d[i] = s[i];
    }
}

bool secure_compare(const void* a, const void* b, size_t len) {
    if (a == NULL || b == NULL) return false;
    
    const uint8_t* pa = (const uint8_t*)a;
    const uint8_t* pb = (const uint8_t*)b;
    
    uint8_t result = 0;
    for (size_t i = 0; i < len; i++) {
        result |= pa[i] ^ pb[i];
    }
    
    return result == 0;
}

void secure_wipe(void* data, size_t len) {
    if (data == NULL || len == 0) return;
    
    volatile uint8_t* p = (volatile uint8_t*)data;
    for (size_t i = 0; i < len; i++) {
        p[i] = 0;
    }
}

// ==================== ПРЕОБРАЗОВАНИЯ И ФОРМАТИРОВАНИЕ ====================

uint16_t swap_uint16(uint16_t value) {
    return (value >> 8) | (value << 8);
}

uint32_t swap_uint32(uint32_t value) {
    return ((value >> 24) & 0xFF) |
           ((value >> 8) & 0xFF00) |
           ((value << 8) & 0xFF0000) |
           ((value << 24) & 0xFF000000);
}

float celsius_to_fahrenheit(float celsius) {
    return (celsius * 9.0f / 5.0f) + 32.0f;
}

float fahrenheit_to_celsius(float fahrenheit) {
    return (fahrenheit - 32.0f) * 5.0f / 9.0f;
}

int16_t map_value(int16_t x, int16_t in_min, int16_t in_max, int16_t out_min, int16_t out_max) {
    return (x - in_min) * (out_max - out_min) / (in_max - in_min) + out_min;
}

float map_value_float(float x, float in_min, float in_max, float out_min, float out_max) {
    return (x - in_min) * (out_max - out_min) / (in_max - in_min) + out_min;
}

bool is_in_range(int16_t value, int16_t min, int16_t max) {
    return value >= min && value <= max;
}

bool is_in_range_float(float value, float min, float max) {
    return value >= min && value <= max;
}

// ==================== РАБОТА С БИТАМИ ====================

bool check_bit(uint8_t byte, uint8_t bit_position) {
    if (bit_position > 7) return false;
    return (byte & (1 << bit_position)) != 0;
}

uint8_t set_bit(uint8_t byte, uint8_t bit_position) {
    if (bit_position > 7) return byte;
    return byte | (1 << bit_position);
}

uint8_t clear_bit(uint8_t byte, uint8_t bit_position) {
    if (bit_position > 7) return byte;
    return byte & ~(1 << bit_position);
}

uint8_t toggle_bit(uint8_t byte, uint8_t bit_position) {
    if (bit_position > 7) return byte;
    return byte ^ (1 << bit_position);
}

uint8_t get_bits(uint8_t byte, uint8_t start, uint8_t length) {
    if (start > 7 || length == 0 || (start + length) > 8) return 0;
    uint8_t mask = ((1 << length) - 1) << start;
    return (byte & mask) >> start;
}

uint8_t set_bits(uint8_t byte, uint8_t start, uint8_t length, uint8_t value) {
    if (start > 7 || length == 0 || (start + length) > 8) return byte;
    
    uint8_t mask = ((1 << length) - 1) << start;
    byte &= ~mask;
    byte |= (value << start) & mask;
    
    return byte;
}

const char* byte_to_binary_str(uint8_t value) {
    static char buffer[9];
    for (int i = 7; i >= 0; i--) {
        buffer[7 - i] = (value & (1 << i)) ? '1' : '0';
    }
    buffer[8] = '\0';
    return buffer;
}

// ==================== МАТЕМАТИЧЕСКИЕ УТИЛИТЫ ====================

float calculate_average(const float* values, uint8_t count) {
    if (count == 0 || values == NULL) return 0.0f;
    
    float sum = 0.0f;
    for (uint8_t i = 0; i < count; i++) {
        sum += values[i];
    }
    
    return sum / count;
}

float calculate_standard_deviation(const float* values, uint8_t count) {
    if (count <= 1 || values == NULL) return 0.0f;
    
    float mean = calculate_average(values, count);
    float sum_squared_diff = 0.0f;
    
    for (uint8_t i = 0; i < count; i++) {
        float diff = values[i] - mean;
        sum_squared_diff += diff * diff;
    }
    
    return sqrtf(sum_squared_diff / (count - 1));
}

float calculate_moving_average(float* buffer, uint8_t size, float new_value) {
    if (buffer == NULL || size == 0) return new_value;
    
    static uint8_t index = 0;
    static float sum = 0.0f;
    static bool initialized = false;
    
    if (!initialized) {
        for (uint8_t i = 0; i < size; i++) {
            buffer[i] = new_value;
        }
        sum = new_value * size;
        initialized = true;
        return new_value;
    }
    
    sum = sum - buffer[index] + new_value;
    buffer[index] = new_value;
    index = (index + 1) % size;
    
    return sum / size;
}

float clamp_float(float value, float min, float max) {
    if (value < min) return min;
    if (value > max) return max;
    return value;
}

int16_t clamp_int16(int16_t value, int16_t min, int16_t max) {
    if (value < min) return min;
    if (value > max) return max;
    return value;
}

// ==================== СТРУКТУРЫ ДАННЫХ ====================

bool queue_init(CircularQueue* queue, void* buffer, size_t item_size, uint16_t capacity) {
    if (queue == NULL || buffer == NULL || item_size == 0 || capacity == 0) {
        return false;
    }
    
    queue->buffer = buffer;
    queue->item_size = item_size;
    queue->capacity = capacity;
    queue->head = 0;
    queue->tail = 0;
    queue->count = 0;
    queue->full = false;
    
    return true;
}

bool queue_push(CircularQueue* queue, const void* item) {
    if (queue == NULL || item == NULL || queue->full) {
        return false;
    }
    
    uint8_t* dest = (uint8_t*)queue->buffer + (queue->tail * queue->item_size);
    memcpy(dest, item, queue->item_size);
    
    queue->tail = (queue->tail + 1) % queue->capacity;
    queue->count++;
    
    if (queue->tail == queue->head) {
        queue->full = true;
    }
    
    return true;
}

bool queue_pop(CircularQueue* queue, void* item) {
    if (queue == NULL || item == NULL || (queue->count == 0 && !queue->full)) {
        return false;
    }
    
    uint8_t* src = (uint8_t*)queue->buffer + (queue->head * queue->item_size);
    memcpy(item, src, queue->item_size);
    
    queue->head = (queue->head + 1) % queue->capacity;
    queue->count--;
    queue->full = false;
    
    return true;
}

bool queue_peek(const CircularQueue* queue, void* item) {
    if (queue == NULL || item == NULL || (queue->count == 0 && !queue->full)) {
        return false;
    }
    
    uint8_t* src = (uint8_t*)queue->buffer + (queue->head * queue->item_size);
    memcpy(item, src, queue->item_size);
    
    return true;
}

void queue_clear(CircularQueue* queue) {
    if (queue == NULL) return;
    
    queue->head = 0;
    queue->tail = 0;
    queue->count = 0;
    queue->full = false;
}

bool queue_is_empty(const CircularQueue* queue) {
    if (queue == NULL) return true;
    return (queue->count == 0 && !queue->full);
}

bool queue_is_full(const CircularQueue* queue) {
    if (queue == NULL) return false;
    return queue->full;
}

uint16_t queue_count(const CircularQueue* queue) {
    if (queue == NULL) return 0;
    return queue->count;
}

// ==================== РАБОТА СО СТРОКАМИ ====================

bool starts_with(const char* str, const char* prefix) {
    if (str == NULL || prefix == NULL) return false;
    
    while (*prefix) {
        if (*str++ != *prefix++) {
            return false;
        }
    }
    
    return true;
}

bool ends_with(const char* str, const char* suffix) {
    if (str == NULL || suffix == NULL) return false;
    
    size_t str_len = strlen(str);
    size_t suffix_len = strlen(suffix);
    
    if (suffix_len > str_len) return false;
    
    return strcmp(str + str_len - suffix_len, suffix) == 0;
}

bool contains(const char* str, const char* substr) {
    if (str == NULL || substr == NULL) return false;
    return strstr(str, substr) != NULL;
}

char* trim_whitespace(char* str) {
    if (str == NULL) return NULL;
    
    // Убираем пробелы в конце
    char* end = str + strlen(str) - 1;
    while (end >= str && (*end == ' ' || *end == '\t' || *end == '\n' || *end == '\r')) {
        *end = '\0';
        end--;
    }
    
    // Убираем пробелы в начале
    char* start = str;
    while (*start && (*start == ' ' || *start == '\t' || *start == '\n' || *start == '\r')) {
        start++;
    }
    
    // Сдвигаем строку если нужно
    if (start != str) {
        size_t len = strlen(start);
        memmove(str, start, len + 1);
    }
    
    return str;
}

bool split_string(const char* str, char delimiter, char* part1, size_t part1_size, 
                 char* part2, size_t part2_size) {
    if (str == NULL || part1 == NULL || part2 == NULL) return false;
    
    const char* delim_pos = strchr(str, delimiter);
    if (delim_pos == NULL) return false;
    
    size_t first_len = delim_pos - str;
    if (first_len >= part1_size) return false;
    
    strncpy(part1, str, first_len);
    part1[first_len] = '\0';
    
    size_t second_len = strlen(delim_pos + 1);
    if (second_len >= part2_size) return false;
    
    strncpy(part2, delim_pos + 1, second_len);
    part2[second_len] = '\0';
    
    return true;
}

// ==================== ЛОГИРОВАНИЕ ====================

void log_message(LogLevel level, const char* format, ...) {
    // Базовая реализация логирования
    // В реальной системе здесь было бы сохранение в файл или отправка по сети
    
    const char* level_str;
    switch (level) {
        case LOG_ERROR:   level_str = "ERROR"; break;
        case LOG_WARNING: level_str = "WARN"; break;
        case LOG_INFO:    level_str = "INFO"; break;
        case LOG_DEBUG:   level_str = "DEBUG"; break;
        default:          level_str = "UNKNOWN"; break;
    }
    
    // Для примера просто игнорируем вывод
    (void)level_str;
    (void)format;
    
    // В реальной реализации здесь был бы код вывода
}

// Конец файла utils.c
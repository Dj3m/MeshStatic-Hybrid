// utils.h - Общие утилиты для MeshStatic
#ifndef UTILS_H
#define UTILS_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

// Уровни логгирования
typedef enum {
    LOG_ERROR = 0,
    LOG_WARN  = 1,
    LOG_INFO  = 2,
    LOG_DEBUG = 3
} LogLevel;

// Логгирование
void log_message(LogLevel level, const char* format, ...);

// Конвертация байта в бинарную строку
char* byte_to_binary(uint8_t value, char* buf);

// Расчет среднего значения
float calculate_average(float* values, uint8_t count);

// Проверка валидности MAC-адреса
bool is_valid_mac(const uint8_t* mac);

// Копирование MAC-адреса
void copy_mac(uint8_t* dest, const uint8_t* src);

// Сравнение MAC-адресов
bool compare_mac(const uint8_t* mac1, const uint8_t* mac2);

// Генерация контрольной суммы
uint16_t calculate_checksum(const void* data, size_t len);

// Задержка в миллисекундах
void delay_ms(uint32_t ms);

// Получение текущего времени в миллисекундах
uint32_t get_current_time(void);

// Проверка, истекло ли время
bool is_time_elapsed(uint32_t start_time, uint32_t timeout_ms);

// Макрос для минимального значения
#ifndef MIN
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#endif

// Макрос для максимального значения
#ifndef MAX
#define MAX(a, b) ((a) > (b) ? (a) : (b))
#endif

// Макрос для проверки указателя
#ifndef CHECK_PTR
#define CHECK_PTR(ptr) ((ptr) != NULL)
#endif

#endif // UTILS_H

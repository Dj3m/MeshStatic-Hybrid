// utils.h - Вспомогательные функции для MeshStatic
#ifndef UTILS_H
#define UTILS_H

#include <stdint.h>
#include <stdbool.h>
#include <string.h>

// Сравнение массивов в постоянном времени (защита от атак по времени)
bool constant_time_compare(const void *a, const void *b, size_t len);

// Безопасное обнуление памяти (чтобы оптимизатор не удалил)
void secure_zero(void *ptr, size_t len);

// Конвертация байта в двоичную строку (для отладки)
const char* byte_to_binary(uint8_t value);

// Быстрое вычисление среднего значения для сглаживания показаний датчика
float calculate_average(const float values[], uint8_t count);

#endif // UTILS_H
// utils.h
// Набор общих утилитарных функций для проекта MeshStatic-Hybrid.
// Не зависит от платформы (ESP32/ESP8266) и конкретной логики устройств.

#pragma once
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>

// ==================== РАБОТА С MAC-АДРЕСАМИ ====================

/**
 * Преобразует массив из 6 байт в строку формата "AA:BB:CC:DD:EE:FF".
 * Результат хранится в статическом буфере, не потокобезопасно.
 * Для многопоточности используйте mac_to_string_r().
 *
 * @param mac Указатель на массив из 6 байт (MAC-адрес)
 * @return Указатель на строку-представление
 */
const char* mac_to_string(const uint8_t mac[6]);

/**
 * Преобразует массив из 6 байт в строку формата "AA:BB:CC:DD:EE:FF".
 * Результат записывается в предоставленный буфер (потокобезопасно).
 *
 * @param mac Указатель на массив из 6 байт (MAC-адрес)
 * @param buffer Буфер для результата (минимум 18 байт: 17 символов + '\0')
 * @return Указатель на buffer (для удобства)
 */
char* mac_to_string_r(const uint8_t mac[6], char buffer[18]);

/**
 * Парсит строку формата "AA:BB:CC:DD:EE:FF" или "AABBCCDDEEFF"
 * в массив из 6 байт.
 *
 * @param str Строка с MAC-адресом
 * @param out_mac Буфер для результата (6 байт)
 * @return true - успех, false - строка имеет неверный формат
 */
bool string_to_mac(const char* str, uint8_t out_mac[6]);

/**
 * Сравнивает два MAC-адреса (6 байт).
 * Аналог memcmp(), но с явной семантикой.
 *
 * @param mac1 Первый MAC-адрес
 * @param mac2 Второй MAC-адрес
 * @return 0 если равны, <0 если mac1 < mac2, >0 если mac1 > mac2
 */
int mac_compare(const uint8_t mac1[6], const uint8_t mac2[6]);

/**
 * Копирует MAC-адрес из src в dst.
 * Аналог memcpy(), но с явной семантикой.
 */
void mac_copy(uint8_t dst[6], const uint8_t src[6]);

/**
 * Проверяет, является ли MAC-адрес широковещательным (FF:FF:FF:FF:FF:FF).
 *
 * @param mac MAC-адрес для проверки
 * @return true если это broadcast адрес
 */
bool mac_is_broadcast(const uint8_t mac[6]);

// ==================== ВЫЧИСЛЕНИЕ CRC32 ====================
// Для проверки целостности пакетов. Использует полином 0xEDB88320 (стандарт IEEE 802.3).

/**
 * Инициализирует таблицу CRC32 (должна быть вызвана перед использованием crc32_update()).
 * Если используется crc32_calculate(), инициализация происходит автоматически.
 */
void crc32_init(void);

/**
 * Обновляет значение CRC32 новыми данными (побайтово).
 * Используется для больших данных, которые приходят частями.
 *
 * @param crc Текущее значение CRC32 (начать с 0xFFFFFFFF)
 * @param data Указатель на данные
 * @param len Длина данных в байтах
 * @return Обновлённое значение CRC32
 */
uint32_t crc32_update(uint32_t crc, const void* data, size_t len);

/**
 * Финализирует вычисление CRC32 (инвертирует биты).
 *
 * @param crc Значение CRC32 после обработки всех данных
 * @return Финальный CRC32
 */
uint32_t crc32_final(uint32_t crc);

/**
 * Всё-в-одном: вычисляет CRC32 для блока данных.
 *
 * @param data Указатель на данные
 * @param len Длина данных
 * @return CRC32 значения данных
 */
uint32_t crc32_calculate(const void* data, size_t len);

// ==================== РАБОТА С БАЙТОВЫМИ БУФЕРАМИ ====================

/**
 * Записывает 16-битное значение (uint16_t) в буфер в Big-Endian порядке (сетевой порядок байт).
 *
 * @param buffer Буфер для записи (должен иметь как минимум 2 свободных байта)
 * @param value Значение для записи
 */
void write_be16(uint8_t* buffer, uint16_t value);

/**
 * Читает 16-битное значение (uint16_t) из буфера в Big-Endian порядке.
 *
 * @param buffer Буфер для чтения
 * @return Прочитанное значение
 */
uint16_t read_be16(const uint8_t* buffer);

/**
 * Записывает 32-битное значение (uint32_t) в буфер в Big-Endian порядке.
 *
 * @param buffer Буфер для записи (должен иметь как минимум 4 свободных байта)
 * @param value Значение для записи
 */
void write_be32(uint8_t* buffer, uint32_t value);

/**
 * Читает 32-битное значение (uint32_t) из буфера в Big-Endian порядке.
 *
 * @param buffer Буфер для чтения
 * @return Прочитанное значение
 */
uint32_t read_be32(const uint8_t* buffer);

/**
 * Безопасное копирование памяти с проверкой границ.
 * Если dst_len меньше src_len, копируется только dst_len байт.
 *
 * @param dst Буфер назначения
 * @param dst_len Размер буфера назначения
 * @param src Исходный буфер
 * @param src_len Размер данных для копирования
 * @return Количество скопированных байт
 */
size_t safe_memcpy(void* dst, size_t dst_len, const void* src, size_t src_len);

// ==================== СЛУЖЕБНЫЕ ФУНКЦИИ ====================

/**
 * Затирает чувствительные данные (ключи, пароли) в памяти нулями.
 * Защищает от извлечения данных из памяти после освобождения.
 *
 * @param data Указатель на данные
 * @param len Размер данных в байтах
 */
void memzero(void* data, size_t len);

/**
 * Константное по времени сравнение памяти (защита от timing-атак).
 * Используется для сравнения ключей, хешей, кодов аутентификации.
 *
 * @param a Первый буфер
 * @param b Второй буфер
 * @param len Длина буферов
 * @return true если буферы идентичны, false иначе
 */
bool constant_time_compare(const void* a, const void* b, size_t len);

// ==================== ДЕБАГ И ЛОГИРОВАНИЕ ====================

/**
 * Преобразует байтовый буфер в hex-строку для отладки.
 * Результат в статическом буфере, не потокобезопасно.
 *
 * @param data Указатель на данные
 * @param len Длина данных
 * @return Указатель на hex-строку
 */
const char* hex_dump(const void* data, size_t len);

/**
 * Преобразует байтовый буфер в hex-строку в предоставленный буфер.
 *
 * @param data Указатель на данные
 * @param len Длина данных
 * @param buffer Буфер для результата (размер: len*2 + 1 байт)
 * @return Указатель на buffer
 */
char* hex_dump_r(const void* data, size_t len, char* buffer);

// ==================== МАТЕМАТИЧЕСКИЕ УТИЛИТЫ ====================

/**
 * Ограничивает значение заданными границами.
 *
 * @param value Входное значение
 * @param min Минимальное допустимое значение
 * @param max Максимальное допустимое значение
 * @return Ограниченное значение: min если value < min, max если value > max, иначе value
 */
float clamp_float(float value, float min, float max);

/**
 * Ограничивает целое значение заданными границами.
 */
int clamp_int(int value, int min, int max);

/**
 * Линейная интерполяция между двумя значениями.
 *
 * @param a Начальное значение
 * @param b Конечное значение
 * @param t Фактор интерполяции (0.0 = a, 1.0 = b, 0.5 = середина)
 * @return Интерполированное значение
 */
float lerp(float a, float b, float t);

// ==================== РАБОТА СО ВРЕМЕНЕМ ====================

/**
 * Получает текущее время в миллисекундах от загрузки системы.
 * Абстракция над millis() Arduino, но работает и в нативном тестировании.
 *
 * @return Текущее время в мс
 */
uint32_t get_current_time_ms(void);

/**
 * Проверяет, истекло ли время (для таймаутов).
 *
 * @param start_time Время начала отсчёта (в мс)
 * @param timeout Продолжительность таймаута (в мс)
 * @return true если (current_time - start_time) >= timeout
 */
bool has_timeout_elapsed(uint32_t start_time, uint32_t timeout);

// ==================== МАКРОСЫ ДЛЯ ОТЛАДКИ ====================

#ifdef DEBUG
    #define DEBUG_PRINT(fmt, ...) printf("[DEBUG] " fmt "\n", ##__VA_ARGS__)
    #define DEBUG_HEX(data, len) do { \
        char buf[(len)*2+1]; \
        hex_dump_r(data, len, buf); \
        printf("[DEBUG] %s\n", buf); \
    } while(0)
#else
    #define DEBUG_PRINT(fmt, ...) 
    #define DEBUG_HEX(data, len)
#endif

// Конец файла utils.h

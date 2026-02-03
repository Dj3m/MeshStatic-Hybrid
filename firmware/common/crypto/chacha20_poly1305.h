// chacha20_poly1305.h
// Реализация аутентифицированного шифрования ChaCha20-Poly1305 для ESP32.
// Алгоритм: ChaCha20 (потоковый шифр) + Poly1305 (код аутентификации).
// Стандарт: IETF RFC 8439.
// Особенность: Высокая скорость на 32-битных процессорах, устойчив к timing-атакам.

#pragma once
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>

// ==================== КОНСТАНТЫ АЛГОРИТМА ====================
#define CHACHA20_KEY_SIZE     32  // Длина ключа 256 бит (32 байта)
#define CHACHA20_NONCE_SIZE   12  // Длина одноразового номера 96 бит (12 байт)
#define POLY1305_TAG_SIZE     16  // Длина тега аутентификации 128 бит (16 байт)
#define CHACHA20_BLOCK_SIZE   64  // Размер блока ChaCha20 (64 байта)

// ==================== ВНУТРЕННЯЯ СТРУКТУРА CHACHA20 ====================
// Контекст - состояние шифратора/дешифратора ChaCha20.
typedef struct {
    uint32_t state[16];  // Текущее состояние алгоритма (16 слов по 32 бита)
    uint8_t  keystream[CHACHA20_BLOCK_SIZE]; // Сгенерированный ключевой поток
    size_t   position;   // Текущая позиция в keystream (0..63)
} chacha20_ctx_t;

// ==================== ВНУТРЕННЯЯ СТРУКТУРА POLY1305 ====================
// Контекст для вычисления кода аутентификации сообщения (MAC).
typedef struct {
    uint32_t r[5];      // Ключ 'r' (замаскированный)
    uint32_t h[5];      // Накопитель хеша (аккумулятор)
    uint32_t pad[4];    // Ключ 's' для финализации
    size_t   leftover;  // Количество байт во временном буфере
    uint8_t  buffer[16];// Буфер для неполных блоков
    uint8_t  final;     // Флаг завершения
} poly1305_ctx_t;

// ==================== ОСНОВНОЙ КОНТЕКСТ AEAD ====================
// Объединенный контекст для Authenticated Encryption with Associated Data (AEAD).
// AEAD = Шифрование (ChaCha20) + Аутентификация (Poly1305) в одном алгоритме.
typedef struct {
    chacha20_ctx_t cipher_ctx; // Контекст шифрования
    poly1305_ctx_t auth_ctx;   // Контекст аутентификации
    uint8_t        key[CHACHA20_KEY_SIZE];   // Ключ шифрования (256 бит)
    uint8_t        nonce[CHACHA20_NONCE_SIZE]; // Одноразовый номер (96 бит)
    uint64_t       aad_len;    // Длина дополнительных аутентифицированных данных (AAD)
    uint64_t       ciphertext_len; // Длина шифртекста
} chacha20_poly1305_ctx_t;

// ==================== ОСНОВНЫЕ ФУНКЦИИ AEAD ====================

/**
 * Инициализирует контекст шифрования ChaCha20-Poly1305.
 * Эта функция ДОЛЖНА быть вызвана перед использованием контекста.
 * 
 * @param ctx Указатель на контекст (память должна быть выделена)
 * @param key Ключ шифрования 32 байта (256 бит)
 * @param nonce Одноразовый номер 12 байт (96 бит). НИКОГДА не используйте один nonce дважды с одним ключом!
 * @return true - успех, false - ошибка (неверные параметры)
 */
bool chacha20_poly1305_init(chacha20_poly1305_ctx_t *ctx,
                           const uint8_t key[CHACHA20_KEY_SIZE],
                           const uint8_t nonce[CHACHA20_NONCE_SIZE]);

/**
 * Добавляет Additional Authenticated Data (AAD) - данные, которые будут
 * аутентифицированы, но НЕ зашифрованы (например, заголовок сетевого пакета).
 * Должна быть вызвана ПОСЛЕ init(), но ДО encrypt()/decrypt().
 * 
 * @param ctx Инициализированный контекст
 * @param aad Указатель на данные для аутентификации
 * @param aad_len Длина данных в байтах
 */
void chacha20_poly1305_aad(chacha20_poly1305_ctx_t *ctx,
                          const uint8_t *aad,
                          size_t aad_len);

/**
 * ШИФРУЕТ данные и вычисляет тег аутентификации (AEAD операция).
 * 
 * @param ctx Контекст с добавленными AAD данными (через aad())
 * @param plaintext Открытый текст для шифрования
 * @param ciphertext Буфер для шифртекста (должен иметь размер >= plaintext_len)
 * @param length Длина данных в байтах
 * @param tag Буфер для тега аутентификации (16 байт). Его нужно передать вместе с ciphertext.
 */
void chacha20_poly1305_encrypt(chacha20_poly1305_ctx_t *ctx,
                              const uint8_t *plaintext,
                              uint8_t *ciphertext,
                              size_t length,
                              uint8_t tag[POLY1305_TAG_SIZE]);

/**
 * ДЕШИФРУЕТ данные и ПРОВЕРЯЕТ тег аутентификации.
 * Если тег неверен, данные были изменены или ключ/nonce не совпадают.
 * 
 * @param ctx Контекст с добавленными AAD данными
 * @param ciphertext Шифртекст для расшифровки
 * @param plaintext Буфер для открытого текста
 * @param length Длина данных
 * @param tag Ожидаемый тег аутентификации (16 байт)
 * @return true - данные аутентичны и расшифрованы, false - ОШИБКА АУТЕНТИФИКАЦИИ
 */
bool chacha20_poly1305_decrypt(chacha20_poly1305_ctx_t *ctx,
                              const uint8_t *ciphertext,
                              uint8_t *plaintext,
                              size_t length,
                              const uint8_t tag[POLY1305_TAG_SIZE]);

// ==================== УПРОЩЕННЫЙ API ДЛЯ MESH-ПАКЕТОВ ====================
// Эти функции скрывают внутреннюю структуру контекста для удобства.

/**
 * ВСЁ-В-ОДНОМ: Шифрует полезную нагрузку (payload) Mesh-пакета.
 * Используется для пакетов с флагом FLAG_ENCRYPTED.
 * 
 * @param key Сессионный ключ (32 байта)
 * @param nonce Одноразовый номер (12 байт). Генерируется из packet_id + src_mac.
 * @param plaintext Полезная нагрузка для шифрования
 * @param plaintext_len Длина полезной нагрузки
 * @param aad Доп. данные для аутентификации (ЗАГОЛОВОК пакета, кроме payload)
 * @param aad_len Длина AAD
 * @param ciphertext Буфер для результата (шифртекст)
 * @param tag Буфер для тега аутентификации (16 байт)
 */
void mesh_encrypt_packet(const uint8_t key[CHACHA20_KEY_SIZE],
                        const uint8_t nonce[CHACHA20_NONCE_SIZE],
                        const uint8_t *plaintext,
                        size_t plaintext_len,
                        const uint8_t *aad,
                        size_t aad_len,
                        uint8_t *ciphertext,
                        uint8_t tag[POLY1305_TAG_SIZE]);

/**
 * ВСЁ-В-ОДНОМ: Расшифровывает и проверяет Mesh-пакет.
 * 
 * @param key Сессионный ключ (32 байта)
 * @param nonce Одноразовый номер (12 байт)
 * @param ciphertext Шифртекст из пакета
 * @param ciphertext_len Длина шифртекста
 * @param aad Доп. данные для аутентификации (заголовок)
 * @param aad_len Длина AAD
 * @param tag Тег аутентификации из пакета
 * @param plaintext Буфер для расшифрованного текста
 * @return true - пакет аутентичен и расшифрован, false - пакет подделан или ошибка
 */
bool mesh_decrypt_packet(const uint8_t key[CHACHA20_KEY_SIZE],
                        const uint8_t nonce[CHACHA20_NONCE_SIZE],
                        const uint8_t *ciphertext,
                        size_t ciphertext_len,
                        const uint8_t *aad,
                        size_t aad_len,
                        const uint8_t tag[POLY1305_TAG_SIZE],
                        uint8_t *plaintext);

// ==================== ФУНКЦИИ ДЕРИВАЦИИ КЛЮЧЕЙ (KDF) ====================
// Преобразуют мастер-ключ в сессионные ключи для безопасности.

/**
 * Генерирует сессионный ключ из мастер-ключа и идентификатора сессии.
 * Используется для смены ключей каждые 24 часа (период сессии).
 * 
 * @param master_key Мастер-ключ системы (хранится в безопасной памяти)
 * @param session_id Уникальный ID сессии (например, текущая дата)
 * @param session_key Буфер для сессионного ключа (32 байта)
 */
void derive_session_key(const uint8_t master_key[CHACHA20_KEY_SIZE],
                       uint32_t session_id,
                       uint8_t session_key[CHACHA20_KEY_SIZE]);

/**
 * Генерирует одноразовый номер (nonce) для пакета.
 * Nonce = session_id + packet_id + src_mac. Это гарантирует уникальность.
 * 
 * @param session_key Сессионный ключ
 * @param packet_id Уникальный ID пакета
 * @param src_mac MAC-адрес отправителя
 * @param output_nonce Буфер для nonce (12 байт)
 */
void derive_packet_nonce(const uint8_t session_key[CHACHA20_KEY_SIZE],
                        uint32_t packet_id,
                        const uint8_t src_mac[6],
                        uint8_t output_nonce[CHACHA20_NONCE_SIZE]);

// ==================== СЛУЖЕБНЫЕ ФУНКЦИИ ====================

/**
 * Безопасное сравнение двух ключей/тегов (константное время).
 * Защищает от timing-атак, в отличие от memcmp().
 * 
 * @param a Первый массив
 * @param b Второй массив
 * @param len Длина массивов в байтах
 * @return true - массивы идентичны, false - различаются
 */
bool constant_time_compare(const uint8_t *a, const uint8_t *b, size_t len);

/**
 * Безопасная очистка памяти от чувствительных данных (ключей).
 * Затирает память нулями, чтобы ключи не остались в ОЗУ.
 * 
 * @param data Указатель на чувствительные данные
 * @param len Длина данных
 */
void secure_wipe(void *data, size_t len);

// ==================== ESP32 СПЕЦИФИЧНЫЕ ОПТИМИЗАЦИИ ====================
#ifdef ESP32
/**
 * Использует аппаратный генератор случайных чисел ESP32 для создания ключей.
 * Намного безопаснее программных ГСЧ.
 * 
 * @param buffer Буфер для случайных данных
 * @param len Требуемое количество байт
 * @return true - успех, false - аппаратный ГСЧ недоступен
 */
bool esp32_hw_random(uint8_t *buffer, size_t len);

/**
 * Использует аппаратное ускорение AES (если доступно) для функций KDF.
 * Ускоряет производство ключей без потери безопасности.
 */
void hw_accelerated_kdf(const uint8_t *input, size_t input_len, uint8_t output_key[CHACHA20_KEY_SIZE]);
#endif // ESP32

// Конец заголовочного файла chacha20_poly1305.h

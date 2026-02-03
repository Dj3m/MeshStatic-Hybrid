// chacha20_poly1305.h
// Чистый файл без невидимых символов. Используется для шифрования пакетов.
#pragma once
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#define CHACHA20_KEY_SIZE     32  // 256-bit key
#define CHACHA20_NONCE_SIZE   12  // 96-bit nonce
#define POLY1305_TAG_SIZE     16  // 128-bit authentication tag

// Инициализация контекста шифрования с ключом и одноразовым номером
bool chacha20_poly1305_init(const uint8_t key[CHACHA20_KEY_SIZE],
                           const uint8_t nonce[CHACHA20_NONCE_SIZE]);

// Добавление дополнительных аутентифицированных данных (AAD)
void chacha20_poly1305_aad(const uint8_t *aad, size_t aad_len);

// Шифрование и аутентификация данных
void chacha20_poly1305_encrypt(const uint8_t *plaintext,
                              uint8_t *ciphertext,
                              size_t length,
                              uint8_t tag[POLY1305_TAG_SIZE]);

// Расшифровка и проверка аутентификации
bool chacha20_poly1305_decrypt(const uint8_t *ciphertext,
                              uint8_t *plaintext,
                              size_t length,
                              const uint8_t tag[POLY1305_TAG_SIZE]);

// Упрощенный API для Mesh-пакетов
void mesh_encrypt_payload(const uint8_t key[32],
                         const uint8_t nonce[12],
                         const uint8_t *plaintext,
                         size_t plaintext_len,
                         const uint8_t *aad,
                         size_t aad_len,
                         uint8_t *ciphertext,
                         uint8_t tag[16]);

bool mesh_decrypt_payload(const uint8_t key[32],
                         const uint8_t nonce[12],
                         const uint8_t *ciphertext,
                         size_t ciphertext_len,
                         const uint8_t *aad,
                         size_t aad_len,
                         const uint8_t tag[16],
                         uint8_t *plaintext);
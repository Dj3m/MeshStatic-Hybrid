// chacha20_poly1305.c
// Реализация алгоритма ChaCha20-Poly1305 (RFC 8439)
// Оптимизировано для 32-битных процессоров (ESP32)

#include "chacha20_poly1305.h"
#include "utils.h" // Для constant_time_compare и memzero

// ==================== ВНУТРЕННИЕ ФУНКЦИИ CHACHA20 ====================

// Константы алгоритма ChaCha20
#define CHACHA20_CONSTANT0 0x61707865
#define CHACHA20_CONSTANT1 0x3320646e
#define CHACHA20_CONSTANT2 0x79622d32
#define CHACHA20_CONSTANT3 0x6b206574

// Циклический поворот влево (ROTL)
static inline uint32_t rotl32(uint32_t x, int n) {
    return (x << n) | (x >> (32 - n));
}

// Четверть-раунд ChaCha20 (обрабатывает 4 слова состояния)
static inline void qr(uint32_t *a, uint32_t *b, uint32_t *c, uint32_t *d) {
    *a += *b; *d ^= *a; *d = rotl32(*d, 16);
    *c += *d; *b ^= *c; *b = rotl32(*b, 12);
    *a += *b; *d ^= *a; *d = rotl32(*d, 8);
    *c += *d; *b ^= *c; *b = rotl32(*b, 7);
}

// Инициализация состояния ChaCha20 из ключа и nonce
static void chacha20_init_state(uint32_t state[16],
                               const uint8_t key[32],
                               const uint8_t nonce[12],
                               uint32_t counter) {
    // Константы
    state[0] = CHACHA20_CONSTANT0;
    state[1] = CHACHA20_CONSTANT1;
    state[2] = CHACHA20_CONSTANT2;
    state[3] = CHACHA20_CONSTANT3;
    
    // Ключ (256 бит = 8 слов по 32 бита)
    for (int i = 0; i < 8; i++) {
        state[4 + i] = ((uint32_t)key[i*4] << 0)  | ((uint32_t)key[i*4+1] << 8) |
                       ((uint32_t)key[i*4+2] << 16) | ((uint32_t)key[i*4+3] << 24);
    }
    
    // Счётчик блока
    state[12] = counter;
    
    // Nonce (96 бит = 3 слова по 32 бита)
    state[13] = ((uint32_t)nonce[0] << 0)  | ((uint32_t)nonce[1] << 8) |
                ((uint32_t)nonce[2] << 16) | ((uint32_t)nonce[3] << 24);
    state[14] = ((uint32_t)nonce[4] << 0)  | ((uint32_t)nonce[5] << 8) |
                ((uint32_t)nonce[6] << 16) | ((uint32_t)nonce[7] << 24);
    state[15] = ((uint32_t)nonce[8] << 0)  | ((uint32_t)nonce[9] << 8) |
                ((uint32_t)nonce[10] << 16)| ((uint32_t)nonce[11] << 24);
}

// Генерация одного блока ключевого потока (64 байта)
static void chacha20_block(uint32_t state[16], uint8_t keystream[64]) {
    uint32_t workspace[16];
    
    // Копируем состояние в рабочую область
    for (int i = 0; i < 16; i++) {
        workspace[i] = state[i];
    }
    
    // 20 раундов (10 двойных раундов)
    for (int i = 0; i < 10; i++) {
        // Нечётный раунд
        qr(&workspace[0], &workspace[4], &workspace[8], &workspace[12]);
        qr(&workspace[1], &workspace[5], &workspace[9], &workspace[13]);
        qr(&workspace[2], &workspace[6], &workspace[10], &workspace[14]);
        qr(&workspace[3], &workspace[7], &workspace[11], &workspace[15]);
        
        // Чётный раунд
        qr(&workspace[0], &workspace[5], &workspace[10], &workspace[15]);
        qr(&workspace[1], &workspace[6], &workspace[11], &workspace[12]);
        qr(&workspace[2], &workspace[7], &workspace[8], &workspace[13]);
        qr(&workspace[3], &workspace[4], &workspace[9], &workspace[14]);
    }
    
    // Добавляем исходное состояние (mod 2^32)
    for (int i = 0; i < 16; i++) {
        workspace[i] += state[i];
    }
    
    // Преобразуем в little-endian байты
    for (int i = 0; i < 16; i++) {
        keystream[i*4 + 0] = (uint8_t)(workspace[i] >> 0);
        keystream[i*4 + 1] = (uint8_t)(workspace[i] >> 8);
        keystream[i*4 + 2] = (uint8_t)(workspace[i] >> 16);
        keystream[i*4 + 3] = (uint8_t)(workspace[i] >> 24);
    }
}

// ==================== ВНУТРЕННИЕ ФУНКЦИИ POLY1305 ====================

// Ключевые константы Poly1305
#define POLY1305_KEY_SIZE 32
#define POLY1305_TAG_SIZE 16
#define POLY1305_BLOCK_SIZE 16

// Маска для ключа r
static const uint32_t poly1305_clamp_r[4] = {
    0x0ffffffc, 0x0ffffffc, 0x0ffffffc, 0x0ffffffc
};

// Инициализация контекста Poly1305
static void poly1305_init(poly1305_ctx_t *ctx, const uint8_t key[32]) {
    // Обнуляем аккумулятор
    for (int i = 0; i < 5; i++) {
        ctx->h[i] = 0;
    }
    
    // Клонируем и зажимаем ключ r
    uint32_t t0 = ((uint32_t)key[0] << 0) | ((uint32_t)key[1] << 8) |
                  ((uint32_t)key[2] << 16) | ((uint32_t)key[3] << 24);
    uint32_t t1 = ((uint32_t)key[4] << 0) | ((uint32_t)key[5] << 8) |
                  ((uint32_t)key[6] << 16) | ((uint32_t)key[7] << 24);
    uint32_t t2 = ((uint32_t)key[8] << 0) | ((uint32_t)key[9] << 8) |
                  ((uint32_t)key[10] << 16) | ((uint32_t)key[11] << 24);
    uint32_t t3 = ((uint32_t)key[12] << 0) | ((uint32_t)key[13] << 8) |
                  ((uint32_t)key[14] << 16) | ((uint32_t)key[15] << 24);
    
    ctx->r[0] = t0 & poly1305_clamp_r[0];
    ctx->r[1] = t1 & poly1305_clamp_r[1];
    ctx->r[2] = t2 & poly1305_clamp_r[2];
    ctx->r[3] = t3 & poly1305_clamp_r[3];
    ctx->r[4] = 0;
    
    // Сохраняем ключ s
    ctx->pad[0] = ((uint32_t)key[16] << 0) | ((uint32_t)key[17] << 8) |
                  ((uint32_t)key[18] << 16) | ((uint32_t)key[19] << 24);
    ctx->pad[1] = ((uint32_t)key[20] << 0) | ((uint32_t)key[21] << 8) |
                  ((uint32_t)key[22] << 16) | ((uint32_t)key[23] << 24);
    ctx->pad[2] = ((uint32_t)key[24] << 0) | ((uint32_t)key[25] << 8) |
                  ((uint32_t)key[26] << 16) | ((uint32_t)key[27] << 24);
    ctx->pad[3] = ((uint32_t)key[28] << 0) | ((uint32_t)key[29] << 8) |
                  ((uint32_t)key[30] << 16) | ((uint32_t)key[31] << 24);
    
    ctx->leftover = 0;
    ctx->final = 0;
}

// Добавление блока данных в Poly1305
static void poly1305_blocks(poly1305_ctx_t *ctx, const uint8_t *data, size_t len) {
    uint32_t h0 = ctx->h[0], h1 = ctx->h[1], h2 = ctx->h[2],
             h3 = ctx->h[3], h4 = ctx->h[4];
    uint32_t r0 = ctx->r[0], r1 = ctx->r[1], r2 = ctx->r[2],
             r3 = ctx->r[3], r4 = ctx->r[4];
    
    uint32_t s1 = r1 * 5;
    uint32_t s2 = r2 * 5;
    uint32_t s3 = r3 * 5;
    uint32_t s4 = r4 * 5;
    
    while (len >= 16) {
        // Читаем блок как little-endian
        uint32_t d0 = ((uint32_t)data[0] << 0) | ((uint32_t)data[1] << 8) |
                      ((uint32_t)data[2] << 16) | ((uint32_t)data[3] << 24);
        uint32_t d1 = ((uint32_t)data[4] << 0) | ((uint32_t)data[5] << 8) |
                      ((uint32_t)data[6] << 16) | ((uint32_t)data[7] << 24);
        uint32_t d2 = ((uint32_t)data[8] << 0) | ((uint32_t)data[9] << 8) |
                      ((uint32_t)data[10] << 16) | ((uint32_t)data[11] << 24);
        uint32_t d3 = ((uint32_t)data[12] << 0) | ((uint32_t)data[13] << 8) |
                      ((uint32_t)data[14] << 16) | ((uint32_t)data[15] << 24);
        
        // Добавляем 1 к верхнему биту (для Padding)
        h0 += d0 & 0x3ffffff;
        h1 += ((d0 >> 26) | (d1 << 6)) & 0x3ffffff;
        h2 += ((d1 >> 20) | (d2 << 12)) & 0x3ffffff;
        h3 += ((d2 >> 14) | (d3 << 18)) & 0x3ffffff;
        h4 += (d3 >> 8) | (1 << 24);
        
        // Умножение и редукция по модулю 2^130-5
        uint64_t t0 = ((uint64_t)h0 * r0) + ((uint64_t)h1 * s4) +
                      ((uint64_t)h2 * s3) + ((uint64_t)h3 * s2) +
                      ((uint64_t)h4 * s1);
        uint64_t t1 = ((uint64_t)h0 * r1) + ((uint64_t)h1 * r0) +
                      ((uint64_t)h2 * s4) + ((uint64_t)h3 * s3) +
                      ((uint64_t)h4 * s2);
        uint64_t t2 = ((uint64_t)h0 * r2) + ((uint64_t)h1 * r1) +
                      ((uint64_t)h2 * r0) + ((uint64_t)h3 * s4) +
                      ((uint64_t)h4 * s3);
        uint64_t t3 = ((uint64_t)h0 * r3) + ((uint64_t)h1 * r2) +
                      ((uint64_t)h2 * r1) + ((uint64_t)h3 * r0) +
                      ((uint64_t)h4 * s4);
        uint64_t t4 = ((uint64_t)h0 * r4) + ((uint64_t)h1 * r3) +
                      ((uint64_t)h2 * r2) + ((uint64_t)h3 * r1) +
                      ((uint64_t)h4 * r0);
        
        // Частичная редукция
        h0 = (uint32_t)t0 & 0x3ffffff; t1 += t0 >> 26;
        h1 = (uint32_t)t1 & 0x3ffffff; t2 += t1 >> 26;
        h2 = (uint32_t)t2 & 0x3ffffff; t3 += t2 >> 26;
        h3 = (uint32_t)t3 & 0x3ffffff; t4 += t3 >> 26;
        h4 = (uint32_t)t4 & 0x3ffffff;
        
        // Полная редукция
        h0 += (uint32_t)(t4 >> 26) * 5;
        h1 += h0 >> 26; h0 &= 0x3ffffff;
        h2 += h1 >> 26; h1 &= 0x3ffffff;
        h3 += h2 >> 26; h2 &= 0x3ffffff;
        h4 += h3 >> 26; h3 &= 0x3ffffff;
        h0 += (h4 >> 26) * 5; h4 &= 0x3ffffff;
        h1 += h0 >> 26; h0 &= 0x3ffffff;
        
        data += 16;
        len -= 16;
    }
    
    ctx->h[0] = h0; ctx->h[1] = h1; ctx->h[2] = h2;
    ctx->h[3] = h3; ctx->h[4] = h4;
}

// Финализация Poly1305 (вычисление тега)
static void poly1305_final(poly1305_ctx_t *ctx, uint8_t tag[16]) {
    // Обработка оставшихся байт
    if (ctx->leftover) {
        ctx->buffer[ctx->leftover] = 1;
        for (size_t i = ctx->leftover + 1; i < 16; i++) {
            ctx->buffer[i] = 0;
        }
        poly1305_blocks(ctx, ctx->buffer, 16);
    }
    
    // Финальная редукция
    uint32_t h0 = ctx->h[0], h1 = ctx->h[1], h2 = ctx->h[2],
             h3 = ctx->h[3], h4 = ctx->h[4];
    
    h1 += h0 >> 26; h0 &= 0x3ffffff;
    h2 += h1 >> 26; h1 &= 0x3ffffff;
    h3 += h2 >> 26; h2 &= 0x3ffffff;
    h4 += h3 >> 26; h3 &= 0x3ffffff;
    h0 += (h4 >> 26) * 5; h4 &= 0x3ffffff;
    h1 += h0 >> 26; h0 &= 0x3ffffff;
    
    // Вычисление h + (-p)
    uint32_t g0 = h0 + 5;
    uint32_t g1 = h1 + (g0 >> 26); g0 &= 0x3ffffff;
    uint32_t g2 = h2 + (g1 >> 26); g1 &= 0x3ffffff;
    uint32_t g3 = h3 + (g2 >> 26); g2 &= 0x3ffffff;
    uint32_t g4 = h4 + (g3 >> 26) - (1 << 26); g3 &= 0x3ffffff;
    
    // Выбор h или h-p
    uint32_t mask = (g4 >> 31) - 1;
    h0 = (h0 & mask) | (g0 & ~mask);
    h1 = (h1 & mask) | (g1 & ~mask);
    h2 = (h2 & mask) | (g2 & ~mask);
    h3 = (h3 & mask) | (g3 & ~mask);
    h4 = (h4 & mask) | (g4 & ~mask);
    
    // h % 2^128
    uint64_t f = (uint64_t)h0 + ((uint64_t)h1 << 26) +
                 ((uint64_t)h2 << 52) + ((uint64_t)h3 << 78);
    
    // Добавляем ключ s
    f += ((uint64_t)ctx->pad[0] + ((uint64_t)ctx->pad[1] << 32));
    
    // Записываем little-endian
    tag[0] = (uint8_t)(f >> 0);  tag[1] = (uint8_t)(f >> 8);
    tag[2] = (uint8_t)(f >> 16); tag[3] = (uint8_t)(f >> 24);
    tag[4] = (uint8_t)(f >> 32); tag[5] = (uint8_t)(f >> 40);
    tag[6] = (uint8_t)(f >> 48); tag[7] = (uint8_t)(f >> 56);
    
    f = ((uint64_t)h4 << 104) | ((uint64_t)(h3 >> 4) << 80) |
        ((uint64_t)(h2 >> 30) << 56) | ((uint64_t)(h1 >> 24) << 32) |
        ((uint64_t)(h0 >> 20) << 8);
    
    f += ((uint64_t)ctx->pad[2] + ((uint64_t)ctx->pad[3] << 32));
    
    tag[8] = (uint8_t)(f >> 0);  tag[9] = (uint8_t)(f >> 8);
    tag[10] = (uint8_t)(f >> 16); tag[11] = (uint8_t)(f >> 24);
    tag[12] = (uint8_t)(f >> 32); tag[13] = (uint8_t)(f >> 40);
    tag[14] = (uint8_t)(f >> 48); tag[15] = (uint8_t)(f >> 56);
}

// ==================== ОСНОВНЫЕ ФУНКЦИИ AEAD ====================

bool chacha20_poly1305_init(chacha20_poly1305_ctx_t *ctx,
                           const uint8_t key[CHACHA20_KEY_SIZE],
                           const uint8_t nonce[CHACHA20_NONCE_SIZE]) {
    if (!ctx || !key || !nonce) return false;
    
    // Инициализируем контекст ChaCha20 нулевым счётчиком
    chacha20_init_state(ctx->cipher_ctx.state, key, nonce, 1);
    ctx->cipher_ctx.position = CHACHA20_BLOCK_SIZE; // Принудительно генерируем первый блок
    
    // Генерируем ключ для Poly1305
    uint8_t poly_key[32];
    chacha20_block(ctx->cipher_ctx.state, poly_key);
    poly1305_init(&ctx->auth_ctx, poly_key);
    memzero(poly_key, sizeof(poly_key));
    
    // Обновляем счётчик для шифрования данных
    chacha20_init_state(ctx->cipher_ctx.state, key, nonce, 1);
    ctx->cipher_ctx.position = 0;
    
    // Сохраняем ключ и nonce
    memcpy(ctx->key, key, CHACHA20_KEY_SIZE);
    memcpy(ctx->nonce, nonce, CHACHA20_NONCE_SIZE);
    ctx->aad_len = 0;
    ctx->ciphertext_len = 0;
    
    return true;
}

void chacha20_poly1305_aad(chacha20_poly1305_ctx_t *ctx,
                          const uint8_t *aad,
                          size_t aad_len) {
    if (!ctx || !aad || aad_len == 0) return;
    
    // Добавляем AAD в Poly1305
    poly1305_blocks(&ctx->auth_ctx, aad, aad_len);
    if (ctx->auth_ctx.leftover) {
        size_t i = ctx->auth_ctx.leftover;
        ctx->auth_ctx.buffer[i++] = 1;
        for (; i < 16; i++) ctx->auth_ctx.buffer[i] = 0;
        poly1305_blocks(&ctx->auth_ctx, ctx->auth_ctx.buffer, 16);
    }
    
    ctx->aad_len += aad_len;
}

void chacha20_poly1305_encrypt(chacha20_poly1305_ctx_t *ctx,
                              const uint8_t *plaintext,
                              uint8_t *ciphertext,
                              size_t length,
                              uint8_t tag[POLY1305_TAG_SIZE]) {
    if (!ctx || !plaintext || !ciphertext) return;
    
    // Шифрование ChaCha20
    size_t pos = 0;
    while (pos < length) {
        if (ctx->cipher_ctx.position >= CHACHA20_BLOCK_SIZE) {
            chacha20_block(ctx->cipher_ctx.state, ctx->cipher_ctx.keystream);
            ctx->cipher_ctx.position = 0;
        }
        
        size_t to_process = CHACHA20_BLOCK_SIZE - ctx->cipher_ctx.position;
        if (to_process > length - pos) {
            to_process = length - pos;
        }
        
        for (size_t i = 0; i < to_process; i++) {
            ciphertext[pos + i] = plaintext[pos + i] ^ 
                                 ctx->cipher_ctx.keystream[ctx->cipher_ctx.position + i];
        }
        
        ctx->cipher_ctx.position += to_process;
        pos += to_process;
    }
    
    // Добавляем шифртекст в Poly1305
    poly1305_blocks(&ctx->auth_ctx, ciphertext, length);
    if (ctx->auth_ctx.leftover) {
        size_t i = ctx->auth_ctx.leftover;
        ctx->auth_ctx.buffer[i++] = 1;
        for (; i < 16; i++) ctx->auth_ctx.buffer[i] = 0;
        poly1305_blocks(&ctx->auth_ctx, ctx->auth_ctx.buffer, 16);
    }
    
    // Финализируем с длинами AAD и шифртекста
    uint8_t length_block[16] = {0};
    uint64_t aad_len_bits = ctx->aad_len * 8;
    uint64_t cipher_len_bits = (ctx->ciphertext_len + length) * 8;
    
    for (int i = 0; i < 8; i++) {
        length_block[i] = (uint8_t)(aad_len_bits >> (i * 8));
        length_block[i + 8] = (uint8_t)(cipher_len_bits >> (i * 8));
    }
    
    poly1305_blocks(&ctx->auth_ctx, length_block, 16);
    poly1305_final(&ctx->auth_ctx, tag);
    
    ctx->ciphertext_len += length;
}

bool chacha20_poly1305_decrypt(chacha20_poly1305_ctx_t *ctx,
                              const uint8_t *ciphertext,
                              uint8_t *plaintext,
                              size_t length,
                              const uint8_t tag[POLY1305_TAG_SIZE]) {
    if (!ctx || !ciphertext || !plaintext || !tag) return false;
    
    // Вычисляем тег аутентификации
    uint8_t computed_tag[POLY1305_TAG_SIZE];
    chacha20_poly1305_ctx_t verify_ctx = *ctx;
    
    poly1305_blocks(&verify_ctx.auth_ctx, ciphertext, length);
    if (verify_ctx.auth_ctx.leftover) {
        size_t i = verify_ctx.auth_ctx.leftover;
        verify_ctx.auth_ctx.buffer[i++] = 1;
        for (; i < 16; i++) verify_ctx.auth_ctx.buffer[i] = 0;
        poly1305_blocks(&verify_ctx.auth_ctx, verify_ctx.auth_ctx.buffer, 16);
    }
    
    uint8_t length_block[16] = {0};
    uint64_t aad_len_bits = verify_ctx.aad_len * 8;
    uint64_t cipher_len_bits = (verify_ctx.ciphertext_len + length) * 8;
    
    for (int i = 0; i < 8; i++) {
        length_block[i] = (uint8_t)(aad_len_bits >> (i * 8));
        length_block[i + 8] = (uint8_t)(cipher_len_bits >> (i * 8));
    }
    
    poly1305_blocks(&verify_ctx.auth_ctx, length_block, 16);
    poly1305_final(&verify_ctx.auth_ctx, computed_tag);
    
    // Проверяем тег (константное время)
    if (!constant_time_compare(computed_tag, tag, POLY1305_TAG_SIZE)) {
        memzero(computed_tag, sizeof(computed_tag));
        return false;
    }
    
    memzero(computed_tag, sizeof(computed_tag));
    
    // Расшифровываем ChaCha20
    size_t pos = 0;
    while (pos < length) {
        if (ctx->cipher_ctx.position >= CHACHA20_BLOCK_SIZE) {
            chacha20_block(ctx->cipher_ctx.state, ctx->cipher_ctx.keystream);
            ctx->cipher_ctx.position = 0;
        }
        
        size_t to_process = CHACHA20_BLOCK_SIZE - ctx->cipher_ctx.position;
        if (to_process > length - pos) {
            to_process = length - pos;
        }
        
        for (size_t i = 0; i < to_process; i++) {
            plaintext[pos + i] = ciphertext[pos + i] ^ 
                                ctx->cipher_ctx.keystream[ctx->cipher_ctx.position + i];
        }
        
        ctx->cipher_ctx.position += to_process;
        pos += to_process;
    }
    
    ctx->ciphertext_len += length;
    return true;
}

// ==================== УПРОЩЁННЫЙ API ДЛЯ MESH ====================

void mesh_encrypt_packet(const uint8_t key[CHACHA20_KEY_SIZE],
                        const uint8_t nonce[CHACHA20_NONCE_SIZE],
                        const uint8_t *plaintext,
                        size_t plaintext_len,
                        const uint8_t *aad,
                        size_t aad_len,
                        uint8_t *ciphertext,
                        uint8_t tag[POLY1305_TAG_SIZE]) {
    chacha20_poly1305_ctx_t ctx;
    if (!chacha20_poly1305_init(&ctx, key, nonce)) return;
    
    if (aad_len > 0) {
        chacha20_poly1305_aad(&ctx, aad, aad_len);
    }
    
    chacha20_poly1305_encrypt(&ctx, plaintext, ciphertext, plaintext_len, tag);
    secure_wipe(&ctx, sizeof(ctx));
}

bool mesh_decrypt_packet(const uint8_t key[CHACHA20_KEY_SIZE],
                        const uint8_t nonce[CHACHA20_NONCE_SIZE],
                        const uint8_t *ciphertext,
                        size_t ciphertext_len,
                        const uint8_t *aad,
                        size_t aad_len,
                        const uint8_t tag[POLY1305_TAG_SIZE],
                        uint8_t *plaintext) {
    chacha20_poly1305_ctx_t ctx;
    if (!chacha20_poly1305_init(&ctx, key, nonce)) return false;
    
    if (aad_len > 0) {
        chacha20_poly1305_aad(&ctx, aad, aad_len);
    }
    
    bool result = chacha20_poly1305_decrypt(&ctx, ciphertext, plaintext, 
                                           ciphertext_len, tag);
    secure_wipe(&ctx, sizeof(ctx));
    return result;
}

// ==================== ФУНКЦИИ KDF ====================

void derive_session_key(const uint8_t master_key[CHACHA20_KEY_SIZE],
                       uint32_t session_id,
                       uint8_t session_key[CHACHA20_KEY_SIZE]) {
    // Простой KDF на основе ChaCha20
    uint8_t input[36];
    memcpy(input, master_key, 32);
    write_be32(input + 32, session_id);
    
    uint8_t nonce[12] = {0}; // Нулевой nonce для KDF
    
    chacha20_poly1305_ctx_t ctx;
    chacha20_poly1305_init(&ctx, master_key, nonce);
    
    uint8_t tag[16];
    chacha20_poly1305_encrypt(&ctx, input, session_key, 32, tag);
    
    secure_wipe(input, sizeof(input));
    secure_wipe(&ctx, sizeof(ctx));
    memzero(tag, sizeof(tag));
}

void derive_packet_nonce(const uint8_t session_key[CHACHA20_KEY_SIZE],
                        uint32_t packet_id,
                        const uint8_t src_mac[6],
                        uint8_t output_nonce[CHACHA20_NONCE_SIZE]) {
    // Формируем уникальный nonce: packet_id + src_mac
    write_be32(output_nonce, packet_id);
    memcpy(output_nonce + 4, src_mac, 6);
    memset(output_nonce + 10, 0, 2); // Резервные байты
}

// ==================== СЛУЖЕБНЫЕ ФУНКЦИИ ====================

bool constant_time_compare(const uint8_t *a, const uint8_t *b, size_t len) {
    uint8_t result = 0;
    for (size_t i = 0; i < len; i++) {
        result |= a[i] ^ b[i];
    }
    return result == 0;
}

void secure_wipe(void *data, size_t len) {
    volatile uint8_t *p = (volatile uint8_t *)data;
    while (len--) {
        *p++ = 0;
    }
}

// Конец файла chacha20_poly1305.c
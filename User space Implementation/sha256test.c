#include "kernel/types.h"
#include "user/user.h"
#include <stdint.h>
#include <stddef.h>

// SHA-256 Constants (K array)
const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

uint32_t H[8] = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
};

// Helper function for right rotate
uint32_t right_rotate(uint32_t value, unsigned int count) {
    return (value >> count) | (value << (32 - count));
}

// SHA-256 Padding Function
void sha256_pad(const uint8_t *input, size_t len, uint8_t **output, size_t *padded_len) {
    size_t total_len = len + 1 + 8;
    size_t padding_len = (64 - (total_len % 64)) % 64;
    *padded_len = len + 1 + padding_len + 8;

    *output = malloc(*padded_len);
    if (!*output) {
        printf("Memory allocation failed\n");
        exit(1);
    }

    memcpy(*output, input, len);
    (*output)[len] = 0x80; // Append '1' bit
    memset(*output + len + 1, 0, padding_len);

    uint64_t bit_len = len * 8;
    for (size_t i = 0; i < 8; i++) {
        (*output)[*padded_len - 8 + i] = (bit_len >> (56 - 8 * i)) & 0xFF;
    }
}

// SHA-256 Transform Function (unchanged)
void sha256_transform(uint32_t *state, const uint8_t *block) {
    uint32_t w[64];
    uint32_t a, b, c, d, e, f, g, h;

    for (int i = 0; i < 16; i++) {
        w[i] = (block[i * 4] << 24) | (block[i * 4 + 1] << 16) |
               (block[i * 4 + 2] << 8) | block[i * 4 + 3];
    }
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = right_rotate(w[i - 15], 7) ^ right_rotate(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = right_rotate(w[i - 2], 17) ^ right_rotate(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    a = state[0];
    b = state[1];
    c = state[2];
    d = state[3];
    e = state[4];
    f = state[5];
    g = state[6];
    h = state[7];

    for (int i = 0; i < 64; i++) {
        uint32_t S1 = right_rotate(e, 6) ^ right_rotate(e, 11) ^ right_rotate(e, 25);
        uint32_t ch = (e & f) ^ (~e & g);
        uint32_t temp1 = h + S1 + ch + K[i] + w[i];
        uint32_t S0 = right_rotate(a, 2) ^ right_rotate(a, 13) ^ right_rotate(a, 22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t temp2 = S0 + maj;

        h = g;
        g = f;
        f = e;
        e = d + temp1;
        d = c;
        c = b;
        b = a;
        a = temp1 + temp2;
    }

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
    state[5] += f;
    state[6] += g;
    state[7] += h;
}

// SHA-256 Function
void sha256(const uint8_t *input, size_t len, uint8_t *output) {
    uint32_t state[8];
    memcpy(state, H, sizeof(H));

    uint8_t *padded_input;
    size_t padded_len;
    sha256_pad(input, len, &padded_input, &padded_len);

    for (size_t i = 0; i < padded_len; i += 64) {
        sha256_transform(state, padded_input + i);
    }
    free(padded_input);

    for (int i = 0; i < 8; i++) {
        output[i * 4] = (state[i] >> 24) & 0xFF;
        output[i * 4 + 1] = (state[i] >> 16) & 0xFF;
        output[i * 4 + 2] = (state[i] >> 8) & 0xFF;
        output[i * 4 + 3] = state[i] & 0xFF;
    }
}

// Hexadecimal characters
const char hex_chars[] = "0123456789abcdef";


// Implement getchar for xv6
int getchar(void) {
    char c;
    if (read(0, &c, 1) == 1) { // Read from stdin (fd = 0)
        return c;
    } else {
        return -1; // EOF
    }
}

// Custom realloc implementation for xv6
void* realloc(void *ptr, size_t new_size) {
    if (ptr == NULL) {
        return malloc(new_size); // Behave like malloc if ptr is NULL
    }
    if (new_size == 0) {
        free(ptr); // Behave like free if new_size is 0
        return NULL;
    }

    // Allocate new memory
    void *new_ptr = malloc(new_size);
    if (new_ptr == NULL) {
        return NULL; // Allocation failed
    }

    // Copy old data to new memory
    memcpy(new_ptr, ptr, new_size); // Note: assumes new_size is not less than old size
    free(ptr); // Free old memory
    return new_ptr;
}

int main() {
    printf("Enter the input string:\n");

    size_t buffer_size = 1024;
    char *input = malloc(buffer_size);
    if (input == NULL) {
        printf("Memory allocation failed!\n");
        exit(1);
    }

    size_t input_len = 0;
    int c;
    while ((c = getchar()) != -1 && c != '\n') { // Use -1 for EOF in xv6
        if (input_len + 1 >= buffer_size) {
            buffer_size *= 2;
            input = realloc(input, buffer_size); // Use custom realloc
            if (input == NULL) {
                printf("Memory reallocation failed!\n");
                exit(1);
            }
        }
        input[input_len++] = c;
    }
    input[input_len] = '\0';

    uint8_t hash_output[32];
    int start_ticks = uptime();
    sha256((const uint8_t *)input, input_len, hash_output);
    int end_ticks = uptime();

    char hash_string[65];
    for (int i = 0; i < 32; i++) {
        uint8_t byte = hash_output[i];
        hash_string[i * 2] = hex_chars[byte >> 4];
        hash_string[i * 2 + 1] = hex_chars[byte & 0x0F];
    }
    hash_string[64] = '\0';

    printf("SHA256 Hash: %s\n", hash_string);
    printf("Time taken: %d ticks\n", end_ticks - start_ticks);

    free(input);
    return 0;
}

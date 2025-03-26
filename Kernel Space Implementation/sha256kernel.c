#include "types.h"
#include "spinlock.h"

extern struct spinlock tickslock; // Synchronization for ticks
void acquire(struct spinlock *lk);
void release(struct spinlock *lk);

int consolewrite(int user_src, uint64 src, int n);

// Constants for SHA-256
static const uint K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

static uint H[8] = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
};

// Helper functions
static uint right_rotate(uint value, unsigned int count) {
    return (value >> count) | (value << (32 - count));
}

static void sha256_transform(uint *state, const uchar *block) {
    uint W[64];
    uint a, b, c, d, e, f, g, h;

    // Prepare message schedule
    for (int i = 0; i < 16; ++i) {
        W[i] = (block[i * 4] << 24) | (block[i * 4 + 1] << 16) |
               (block[i * 4 + 2] << 8) | block[i * 4 + 3];
    }
    for (int i = 16; i < 64; ++i) {
        uint s0 = right_rotate(W[i - 15], 7) ^ right_rotate(W[i - 15], 18) ^ (W[i - 15] >> 3);
        uint s1 = right_rotate(W[i - 2], 17) ^ right_rotate(W[i - 2], 19) ^ (W[i - 2] >> 10);
        W[i] = W[i - 16] + s0 + W[i - 7] + s1;
    }

    // Initialize working variables
    a = state[0];
    b = state[1];
    c = state[2];
    d = state[3];
    e = state[4];
    f = state[5];
    g = state[6];
    h = state[7];

    // Main computation
    for (int i = 0; i < 64; ++i) {
        uint S1 = right_rotate(e, 6) ^ right_rotate(e, 11) ^ right_rotate(e, 25);
        uint ch = (e & f) ^ (~e & g);
        uint temp1 = h + S1 + ch + K[i] + W[i];
        uint S0 = right_rotate(a, 2) ^ right_rotate(a, 13) ^ right_rotate(a, 22);
        uint maj = (a & b) ^ (a & c) ^ (b & c);
        uint temp2 = S0 + maj;

        h = g;
        g = f;
        f = e;
        e = d + temp1;
        d = c;
        c = b;
        b = a;
        a = temp1 + temp2;
    }

    // Add the compressed chunk to the current state
    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
    state[5] += f;
    state[6] += g;
    state[7] += h;
}

void sha256(const uchar *input, uint len, uchar *output) {
    uint state[8];
    uchar block[64];
    uint i, j;

    for (i = 0; i < 8; ++i) state[i] = H[i];

    // Process complete 64-byte blocks
    for (i = 0; i + 64 <= len; i += 64) {
        sha256_transform(state, input + i);
    }

    // Handle padding for the last block
    j = len % 64;
    for (int k = 0; k < j; ++k) block[k] = input[i + k];
    block[j++] = 0x80;
    if (j > 56) {
        while (j < 64) block[j++] = 0;
        sha256_transform(state, block);
        j = 0;
    }
    while (j < 56) block[j++] = 0;
    unsigned long bit_len = len * 8;
    for (int k = 0; k < 8; ++k) block[63 - k] = (bit_len >> (k * 8)) & 0xff;
    sha256_transform(state, block);

    // Output the final hash
    for (i = 0; i < 8; ++i) {
        output[i * 4] = (state[i] >> 24) & 0xff;
        output[i * 4 + 1] = (state[i] >> 16) & 0xff;
        output[i * 4 + 2] = (state[i] >> 8) & 0xff;
        output[i * 4 + 3] = state[i] & 0xff;
    }
}

// Kernel-compatible string length function
int kernel_strlen(const char *str) {
    int len = 0;
    while (str[len] != '\0') len++;
    return len;
}

void sha256_test(void) {
    char *message = "a quick brown fox jumps over the lazy dog";
    uchar hash[32];

    sha256((uchar *)message, kernel_strlen(message), hash);

    // Output buffer to store the formatted hash and ticks
    char output[256]; // Increased size to accommodate ticks
    int offset = 0;

    // Write the prefix
    const char *prefix = "SHA-256 hash: ";
    for (int i = 0; prefix[i] != '\0'; i++) {
        output[offset++] = prefix[i];
    }

    // Write the hash in hexadecimal
    for (int i = 0; i < 32; ++i) {
        uchar byte = hash[i];
        const char *hex = "0123456789abcdef";
        output[offset++] = hex[byte >> 4];       // High nibble
        output[offset++] = hex[byte & 0x0F];    // Low nibble
    }

    // Add a newline after the hash
    output[offset++] = '\n';

    // Retrieve the tick count
    extern uint64 ticks; // Use xv6's global ticks variable
    acquire(&tickslock); // Locking for thread safety
    uint64 current_ticks = ticks;
    release(&tickslock);

    // Write the ticks
    const char *tick_prefix = "Number of ticks: ";
    for (int i = 0; tick_prefix[i] != '\0'; i++) {
        output[offset++] = tick_prefix[i];
    }

    // Convert ticks to string
    char tick_buffer[32];
    int tick_offset = 0;
    if (current_ticks == 0) {
        tick_buffer[tick_offset++] = '0';
    } else {
        while (current_ticks > 0) {
            tick_buffer[tick_offset++] = '0' + (current_ticks % 10);
            current_ticks /= 10;
        }
        // Reverse the tick_buffer as we constructed it backward
        for (int i = tick_offset - 1; i >= 0; i--) {
            output[offset++] = tick_buffer[i];
        }
    }

    // Add a newline
    output[offset++] = '\n';

    // Null-terminate the string for safety (not required by consolewrite)
    output[offset] = '\0';

    // Write to the console
    consolewrite(0, (uint64)output, offset);
}

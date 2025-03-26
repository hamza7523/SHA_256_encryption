#include "types.h"
#include "riscv.h"
#include "defs.h"
#include "param.h"
#include "memlayout.h"
#include "spinlock.h"
#include "proc.h"
#include <stdint.h>

uint64
sys_exit(void)
{
  int n;
  argint(0, &n);
  exit(n);
  return 0;  // not reached
}

uint64
sys_getpid(void)
{
  return myproc()->pid;
}

uint64
sys_fork(void)
{
  return fork();
}

uint64
sys_wait(void)
{
  uint64 p;
  argaddr(0, &p);
  return wait(p);
}

uint64
sys_sbrk(void)
{
  uint64 addr;
  int n;

  argint(0, &n);
  addr = myproc()->sz;
  if(growproc(n) < 0)
    return -1;
  return addr;
}

uint64
sys_sleep(void)
{
  int n;
  uint ticks0;

  argint(0, &n);
  if(n < 0)
    n = 0;
  acquire(&tickslock);
  ticks0 = ticks;
  while(ticks - ticks0 < n){
    if(killed(myproc())){
      release(&tickslock);
      return -1;
    }
    sleep(&ticks, &tickslock);
  }
  release(&tickslock);
  return 0;
}

uint64
sys_kill(void)
{
  int pid;

  argint(0, &pid);
  return kill(pid);
}

// return how many clock tick interrupts have occurred
// since start.
uint64
sys_uptime(void)
{
  uint xticks;

  acquire(&tickslock);
  xticks = ticks;
  release(&tickslock);
  return xticks;
}


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

// Initial hash values (H0, H1, ..., H7)
static uint H[8] = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
};

// Helper function for right rotation
static uint right_rotate(uint value, unsigned int count) {
    return (value >> count) | (value << (32 - count));
}

// SHA-256 transformation (main calculation for each block)
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

    // Main computation loop
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

// SHA-256 hashing function
void sha256encrypt(const uchar *input, uint len, uchar *output) {
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

// System call to compute SHA-256
uint64 sys_sha256encrypt(void) {
    uint64 input, output;
    int len;

    // Retrieve arguments
    argaddr(0, &input);  // Input buffer address
    argint(1, &len);     // Input length
    argaddr(2, &output); // Output buffer address

    // Validate arguments manually
    if (input == 0 || len <= 0 || len > 1024 || output == 0 || input >= MAXVA || output >= MAXVA) {
        return -1; // Invalid arguments
    }

    // Allocate kernel buffers
    char buf[1024];  // Maximum input size
    char hash[32];   // Fixed hash size for SHA-256

    // Copy input data from user space to kernel space
    if (copyin(myproc()->pagetable, buf, input, len) < 0) {
        return -1; // Failed to copy input
    }

    // Perform SHA-256 computation
    sha256encrypt((uchar *)buf, len, (uchar *)hash);

    // Copy the hash result back to user space
    if (copyout(myproc()->pagetable, output, hash, 32) < 0) {
        return -1; // Failed to copy output
    }

    return 0; // Success
}

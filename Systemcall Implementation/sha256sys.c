#include <stddef.h>
#include "user.h"

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
    printf("Enter the input string (press Enter to submit):\n");

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

    uchar hash[32]; // SHA-256 hash output (32 bytes)

    // Record the start time in ticks
    int start_ticks = uptime();

    // Call the sys_syssha256 system call
    if (sha256encrypt(input, input_len, hash) < 0) {
        printf("SHA-256 system call failed\n");
        free(input); // Free the allocated memory before exiting
        exit(1);
    }

    // Record the end time in ticks
    int end_ticks = uptime();

    // Output buffer to store the formatted hash
    char output[128];
    size_t offset = 0;

    // Write the prefix "SHA-256 hash: "
    const char *prefix = "SHA-256 hash: ";
    for (int i = 0; prefix[i] != '\0'; i++) {
        output[offset++] = prefix[i];
    }

    // Write the hash in hexadecimal
    const char *hex = "0123456789abcdef";
    for (int i = 0; i < 32; ++i) {
        uchar byte = hash[i];
        output[offset++] = hex[byte >> 4];       // High nibble
        output[offset++] = hex[byte & 0x0F];    // Low nibble
    }

    // Add a newline
    output[offset++] = '\n';

    // Null-terminate the string for safety
    output[offset] = '\0';

    // Write to the console (using printf in user space)
    printf("%s", output);
    printf("Time taken: %d ticks\n", end_ticks - start_ticks);

    // Free the allocated memory
    free(input);

    exit(0);
}

/*
 * Simple test program for timedexec
 * Usage:
 *   ./test_program               - infinite loop (CPU test)
 *   ./test_program mem <size_mb> - allocate size_mb and sleep (memory test)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char *argv[]) {
    if (argc > 1 && strcmp(argv[1], "mem") == 0) {
        if (argc < 3) {
            fprintf(stderr, "Usage: %s mem <size_mb>\n", argv[0]);
            return 1;
        }
        size_t mb = (size_t)atoi(argv[2]);
        size_t bytes = mb * 1024 * 1024;
        char *buf = malloc(bytes);
        if (!buf) {
            perror("malloc");
            return 1;
        }
        /* Touch one byte per page to force physical allocation */
        for (size_t i = 0; i < bytes; i += 4096) {
            buf[i] = 0;
        }
        printf("Allocated %zu MB, sleeping...\n", mb);
        fflush(stdout);
        sleep(3600);  /* Wait to be killed by timedexec */
        free(buf);
    } else {
        printf("Infinite loop (CPU test)\n");
        fflush(stdout);
        while (1) {
            /* busy wait */
        }
    }
    return 0;
}
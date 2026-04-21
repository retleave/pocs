#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>

static int read_line(char *buf, int max) {
    int i = 0;
    while (i < max - 1) {
        char c;
        if (read(0, &c, 1) <= 0) return -1;
        if (c == '\n') break;
        buf[i++] = c;
    }
    buf[i] = '\0';
    return i;
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);

    printf("stdin: %p\n", (void *)stdin);

    char line[64];
    long delta;
    unsigned int byte;

    puts("format: <delta> <hex_byte>");

    for (int i = 0; i < 400; i++) {
        if (read_line(line, sizeof(line)) < 0) break;
        if (sscanf(line, "%ld %x", &delta, &byte) != 2)
            break;
        ((unsigned char *)stdin)[delta] = (unsigned char)byte;
    }

    getchar();
    return 0;
}

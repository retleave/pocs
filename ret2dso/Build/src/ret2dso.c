#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <link.h>
#include <string.h>

extern struct r_debug _r_debug;

static void get_distance(void) {
    struct link_map *lm = _r_debug.r_map;
    uintptr_t stdin_addr = (uintptr_t)stdin;

    while (lm) {
        if (lm->l_name && strstr(lm->l_name, "ld-linux")) {
            uintptr_t ld_base = (uintptr_t)lm->l_addr;
            intptr_t drift = (intptr_t)ld_base - (intptr_t)stdin_addr;
            printf("ld distance: %lx\n", (uint64_t)drift);
            break;
        }
        lm = lm->l_next;
    }
}

static void drift_write(void) {
    long delta;
    unsigned int byte;

    puts("format: <delta> <byte>");

    for (int i = 0; i < 30; i++) {
        if (scanf("%ld %x", &delta, &byte) != 2)
            break;

        /*
         * stdin is used as a globally reachable anchor into libc memory.
         * The attacker controls only a relative offset and a single byte.
         */
        ((unsigned char*)stdin)[delta] = (unsigned char)byte;
    }
}

int main(void) {
    setbuf(stdout, NULL);
    setbuf(stdin, NULL);

    /* Establish relative layout between stdin and ld.so */
    get_distance();

    /* Expose relative byte-wise write primitive */
    drift_write();

    _exit(0);
}
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MAX 8
#define MAX_SZ 0x90

void *heapbase;
char *table[MAX];

void getheap(void){
    void *a = malloc(0x500);
    free(a);
    heapbase = (void *)((char *)a - 0x290);
}

void create(void) {
    int idx, size;
    scanf("%d", &idx);
    scanf("%d", &size);

    if (idx >= MAX || size <= 0 || size > MAX_SZ)
        return;

    getchar();

    table[idx] = malloc(size);
    fgets(table[idx], size, stdin);
}

void edit(void) {
    int idx;
    int off;
    unsigned char val;

    scanf("%d", &idx);
    if (idx >= MAX) return;

    scanf("%d", &off);
    scanf("%hhx", &val);
    table[idx][off] = val;
}

void destroy(void) {
    int idx;

    scanf("%d", &idx);
    if (idx >= MAX)
        return;

    free(table[idx]);
    table[idx] = NULL;
}

int main(void) {
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    getheap();

    while (1) {
        int c;
        scanf("%d", &c);

        if (c == 1) create();
        if (c == 2) edit();
        if (c == 3) destroy();
        if (c == 4) _exit(0);
    }
}
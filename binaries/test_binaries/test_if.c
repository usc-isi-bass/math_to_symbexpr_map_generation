#include <stdio.h>
#include <stdlib.h>
#include <math.h>

int f_if(int a, int b) {
    if (a % 2 == 0) {
        return b + 1;
    } else {
        return b + 2;
    
    }
}

int main(int argc, char *argv[]) {

    if (argc < 3) {
        fprintf(stderr, "usage: %s a b\n", argv[0]);
        return EXIT_FAILURE;
    }
    printf("%d\n", f_if(atoi(argv[1]), atoi(argv[2])));
    return EXIT_SUCCESS;
}

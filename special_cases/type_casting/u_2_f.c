#include <stdio.h>
#include <stdlib.h>
#include <math.h>

float f_003(unsigned int a, unsigned int b, unsigned int c) {
    return (float)((a - b) * c);
}

int main(int argc, char *argv[]) {

    if (argc < 4) {
        fprintf(stderr, "usage: %s a c b\n", argv[0]);
        return EXIT_FAILURE;
    }
    printf("%f\n", f_003(atoi(argv[1]), atoi(argv[2]), atoi(argv[3])));
    return EXIT_SUCCESS;
}


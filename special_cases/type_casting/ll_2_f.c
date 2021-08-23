#include <stdio.h>
#include <stdlib.h>
#include <math.h>

float f_003(long long a, long long b, long long c) {
    return (float)((a - b) * c);
}

int main(int argc, char *argv[]) {

    if (argc < 4) {
        fprintf(stderr, "usage: %s a c b\n", argv[0]);
        return EXIT_FAILURE;
    }
    printf("%f\n", f_003(atol(argv[1]), atol(argv[2]), atol(argv[3])));
    return EXIT_SUCCESS;
}

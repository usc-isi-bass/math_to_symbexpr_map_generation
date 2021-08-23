#include <stdio.h>
#include <stdlib.h>
#include <math.h>

float f_002(float a, float b) {
    return (float)(a + log(b));
}

int main(int argc, char *argv[]) {

    if (argc < 3) {
        fprintf(stderr, "usage: %s a b\n", argv[0]);
        return EXIT_FAILURE;
    }
    printf("%f\n", f_002(atof(argv[1]), atof(argv[2])));
    return EXIT_SUCCESS;
}
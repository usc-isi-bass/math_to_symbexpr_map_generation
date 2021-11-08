#include <stdio.h>
#include <stdlib.h>
#include <math.h>


float f_001(float a, float b) {
    return 3.0 * a / b;
}

float f_002(float a, int b) {
    if (b) {
        return a / 2;
    } else {
        return 3.0 * a;
    }
}

float f_003(float a, float b, float c) {
    return pow(a * b, 4) + cos(c);
}

float f_004(float a, float b) {
    return 2.0 * a + b;
}

int f_005(int a, int b) {
    return (a / 5) * b;
}


float f_006(float a, float b) {
    if (a <= b) {
        return a;
    } else {
        return b;
    }
}






int main(int argc, char *argv[]) {
    float a;

    if (argc < 3) {
        fprintf(stderr, "usage: %s a b c\n", argv[0]);
        return EXIT_FAILURE;
    }
    a = f_001(atof(argv[1]), atof(argv[2]));
    printf("%f\n", a);
    a = f_002(atof(argv[1]), (int)atof(argv[2]));
    printf("%f\n", a);
    a = f_003(atof(argv[1]), atof(argv[2]), atof(argv[3]));
    printf("%f\n", a);
    a = f_004(atof(argv[1]), atof(argv[2]));
    printf("%f\n", a);
    return EXIT_SUCCESS;
}

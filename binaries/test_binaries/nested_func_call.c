#include <stdio.h>
#include <stdlib.h>
#include <math.h>

float f_inner(float y) 
{
    // Something to blow up symbolic execution
    while (1) {
        y++;
    }
    return y;
}


float f01(float x, float y)
{

    return x + f_inner(y);
}

float f02(float x, float y)
{

    return sin(x) + f_inner(y);
}

int main(int argc, char *argv[])
{
    float x, y, a;
    if (argc < 3) {
        fprintf(stderr, "usage: %s x y\n", argv[0]);
        return EXIT_FAILURE;
    }
    x = atof(argv[1]);
    y = atof(argv[2]);
    a = f01(x, y);
    printf("a: %f\n", a);

    a = f02(x, y);
    printf("a: %f\n", a);
    return EXIT_SUCCESS;
}

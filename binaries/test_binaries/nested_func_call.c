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

int f_inner2(int x, int y)
{
    // Something to blow up symbolic execution
    while (1) {
        x++;
        y++;
    }
    return x + y;
}

int f_inner3(int x, float y)
{
    // Something to blow up symbolic execution
    while (1) {
        x++;
        y++;
    }
    return x + (int)y;
}

float f_inner4(float x, int y)
{
    // Something to blow up symbolic execution
    while (1) {
        x++;
        y++;
    }
    return x + (float)y;
}

int f_inner5(void)
{
    int x;
    // Something to blow up symbolic execution
    while (1) {
        x++;
    }
    return x;
}


float f01(float x, float y)
{

    return x + f_inner(y);
}

float f02(float x, float y)
{

    return sin(x) + f_inner(y);
}

int f03(int x, int y)
{
    return f_inner2(x, y);
}

int f04(int x, float y)
{
    return f_inner3(x, y);
}

float f05(float x, int y)
{
    return f_inner4(x, y);
}

int f06(float x)
{
    return (int)x + f_inner5();
}

float f07(float x, float (*f_indirect)(float))
{
    return (int)x + (*f_indirect)(x);
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

    a = f03((int)x, (int)y);
    printf("a: %f\n", a);
    return EXIT_SUCCESS;
}

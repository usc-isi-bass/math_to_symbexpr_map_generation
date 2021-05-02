#include <stdio.h>
#include <stdlib.h>
#include <math.h>

double branch_double(double q1, double q2) {
    double tmp = q1 + 5;
    double x = 0;
    if (tmp > q2) {
        if (tmp > 0)
            x = 1;
        else
            x = 2;
    } else
        x = 3;
    return x + q1 + q2;
}

int branch_int1(int q1, int q2) {
    int tmp = q1 + 5;
    int x = 0;
    if (tmp > q2) {
        if (tmp > 0)
            x = 1;
        else
            x = 2;
    } else
        x = 3;
    return x + q1 + q2;
}

int branch_int2(int q1, int q2) {
    int x = 0;
    if (q1 + 5 > q2) {
        if (q1 + 5 > 0)
            x = 1;
        else
            x = 2;
    } else
        x = 3;
    return x + q1 + q2;
}

int main(int argc, char *argv[])
{
    return EXIT_SUCCESS;
}

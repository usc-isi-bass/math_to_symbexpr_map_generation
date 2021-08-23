#include <stdio.h>
#include <stdlib.h>
#include <math.h>

int f_011(int a_5, int a_3, int a_4, int a_2, int a_10, int a_1, int a_8, int a_7, int a_0, int a_6, int a_9) {
    return (int)((a_5 + (a_3 + (((a_4 + a_2) + (a_10 - ((a_1 - a_8) - a_7))) - a_0))) + (a_6 - a_9));
}

int main(int argc, char *argv[]) {

    if (argc < 12) {
        fprintf(stderr, "usage: %s a_5 a_3 a_4 a_2 a_10 a_1 a_8 a_7 a_0 a_6 a_9\n", argv[0]);
        return EXIT_FAILURE;
    }
    printf("%d\n", f_011(atoi(argv[1]), atoi(argv[2]), atoi(argv[3]), atoi(argv[4]), atoi(argv[5]), atoi(argv[6]), atoi(argv[7]), atoi(argv[8]), atoi(argv[9]), atoi(argv[10]), atoi(argv[11])));
    return EXIT_SUCCESS;
}
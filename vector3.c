#include <stdlib.h>

struct vector3_t {
    int v1;
    int v2;
    int v3;
};

struct vector3_t *vector3(int v1, int v2, int v3)
{
    struct vector3_t *v = malloc(sizeof (struct vector3_t));

    v->v1 = v1;
    v->v2 = v2;
    v->v3 = v3;

    return v;
}


void v3_cross1(struct vector3_t *x, struct vector3_t *y, struct vector3_t *out)
{
    out->v1 = x->v2 * y->v3 + x->v3 * y->v2;
    out->v2 = x->v3 * y->v1 + x->v1 * y->v3;
    out->v3 = x->v1 * y->v2 + x->v2 * y->v1;
}

struct vector3_t *v3_cross2(struct vector3_t *x, struct vector3_t *y)
{
    return vector3(x->v2 * y->v3 + x->v3 * y->v2, x->v3 * y->v1 + x->v1 * y->v3, x->v1 * y->v2 + x->v2 * y->v1);
}

int main(void)
{

    return EXIT_SUCCESS;
}

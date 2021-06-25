
#include "AP_AHRS.h"

// return a ground speed estimate in m/s
Vector2f AP_AHRS::groundspeed_vector(void)
{
    return Vector2f(0.0f, 0.0f);
}

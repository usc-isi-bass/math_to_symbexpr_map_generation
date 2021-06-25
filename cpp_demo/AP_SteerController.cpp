#include "AP_SteerController.h"

int32_t AP_SteerController::get_steering_out_rate(float desired_rate)
{
    float speed = _ahrs.groundspeed();
    if (speed > _minspeed) {
        return 1;
    } else {
        return 0;
    }
}


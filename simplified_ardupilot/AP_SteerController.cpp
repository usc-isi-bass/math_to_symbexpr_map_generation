#include "AP_SteerController.h"

float AP_SteerController::get_steering_out_rate(float desired_rate)
{
    float speed = _ahrs.groundspeed();
    if (speed > _minspeed) {
        return desired_rate + _minspeed;
    } else {
        return desired_rate - _minspeed;
    }
}

float AP_SteerController::simple_return(float desired_rate)
{
    float speed = _ahrs.groundspeed();
    return speed;
}


float AP_SteerController::simple_compare(float desired_rate)
{
    if (desired_rate > _minspeed) {
        return desired_rate + _minspeed;
    } else {
        return desired_rate - _minspeed;
    }
}

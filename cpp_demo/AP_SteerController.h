#include "AP_AHRS.h"

class AP_SteerController {
public:
    AP_SteerController(AP_AHRS &ahrs)
        : _ahrs(ahrs)
    {
    }
    /*
      return a steering servo output from -4500 to 4500 given a
      desired yaw rate in degrees/sec. Positive yaw is to the right.
     */
	int32_t get_steering_out_rate(float desired_rate);

private:
    float _tau;
	float _K_FF;
	float _K_P;
	float _K_I;
	float _K_D;
	float _minspeed;
    float  _imax;
	uint32_t _last_t;
	float _last_out;

	float _deratespeed;
	float _deratefactor;
	float _mindegree;

	AP_AHRS &_ahrs;

    bool _reverse;
};


/*
  steering rate controller. Returns servo out -4500 to 4500 given
  desired yaw rate in degrees/sec. Positive yaw rate means clockwise yaw.
*/
int32_t AP_SteerController::get_steering_out_rate(float desired_rate)
{
	uint32_t tnow = AP_HAL::millis();
	uint32_t dt = tnow - _last_t;
	if (_last_t == 0 || dt > 1000) {
		dt = 0;
	}
	_last_t = tnow;

    float speed = _ahrs.groundspeed();
    if (speed < _minspeed) {
        // assume a minimum speed. This stops oscillations when first starting to move
        speed = _minspeed;
    }

    // this is a linear approximation of the inverse steering
    // equation for a ground vehicle. It returns steering as an angle from -45 to 45
    float scaler = 1.0f / speed;

    _pid_info.target = desired_rate;

	// Calculate the steering rate error (deg/sec) and apply gain scaler
    // We do this in earth frame to allow for rover leaning over in hard corners
    float yaw_rate_earth = ToDeg(_ahrs.get_yaw_rate_earth());
    if (_reverse) {
        yaw_rate_earth *= -1.0f;
    }
    _pid_info.actual = yaw_rate_earth;

    float rate_error = (desired_rate - yaw_rate_earth) * scaler;
	
	// Calculate equivalent gains so that values for K_P and K_I can be taken across from the old PID law
    // No conversion is required for K_D
	float ki_rate = _K_I * _tau * 45.0f;
	float kp_ff = MAX((_K_P - _K_I * _tau) * _tau  - _K_D , 0) * 45.0f;
	float k_ff = _K_FF * 45.0f;
	float delta_time    = (float)dt * 0.001f;
	
	// Multiply yaw rate error by _ki_rate and integrate
	// Don't integrate if in stabilize mode as the integrator will wind up against the pilots inputs
	if (ki_rate > 0 && speed >= _minspeed) {
		// only integrate if gain and time step are positive.
		if (dt > 0) {
		    float integrator_delta = rate_error * ki_rate * delta_time * scaler;
			// prevent the integrator from increasing if steering defln demand is above the upper limit
			if (_last_out < -45) {
                integrator_delta = MAX(integrator_delta , 0);
            } else if (_last_out > 45) {
                // prevent the integrator from decreasing if steering defln demand is below the lower limit
                integrator_delta = MIN(integrator_delta, 0);
            }
			_pid_info.I += integrator_delta;
		}
	} else {
		_pid_info.I = 0;
	}
	
    // Scale the integration limit
    float intLimScaled = _imax * 0.01f;

    // Constrain the integrator state
    _pid_info.I = constrain_float(_pid_info.I, -intLimScaled, intLimScaled);

    _pid_info.D = rate_error * _K_D * 4.0f; 
    _pid_info.P = (ToRad(desired_rate) * kp_ff) * scaler;
    _pid_info.FF = (ToRad(desired_rate) * k_ff) * scaler;
	
    // Calculate the demanded control surface deflection
    _last_out = _pid_info.D + _pid_info.FF + _pid_info.P + _pid_info.I;
	
    float derate_constraint = 4500;

    // Calculate required constrain based on speed
    if (!is_zero(_deratespeed) && speed > _deratespeed) {
        derate_constraint = 4500 - (speed - _deratespeed) * _deratefactor * 100;
        if (derate_constraint < _mindegree) {
            derate_constraint = _mindegree;
        }
    }

    // Convert to centi-degrees and constrain
    return constrain_float(_last_out * 100, -derate_constraint, derate_constraint);
}

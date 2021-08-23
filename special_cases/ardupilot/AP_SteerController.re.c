
/* AP_SteerController::get_steering_out_rate(float) 
 *
 * ardupilot/libraries/APM_Control/AP_SteerController.cpp:123
 * ardupilot/build/linux/libraries/APM_Control/AP_SteerController.cpp.0.o
 */

undefined8 __thiscall
AP_SteerController::get_steering_out_rate(AP_SteerController *this,float param_1)

{
  long *plVar1;
  int iVar2;
  undefined4 extraout_var;
  Vector3<float> *this_00;
  long lVar3;
  long lVar4;
  uint uVar5;
  float extraout_XMM0_Da;
  float fVar6;
  float extraout_XMM0_Da_00;
  float fVar7;
  float fVar8;
  float fVar9;
  float fVar10;
  float fVar11;
  float fVar12;
  
  /* 
    uint32_t tnow = AP_HAL::millis();
   */
  iVar2 = AP_HAL::_ZN6AP_HAL6millisEv();

  /* 
	uint32_t dt = tnow - _last_t;
   */
  uVar5 = iVar2 - *(int *)(this + 0x1c);

  /* 
	if (_last_t == 0 || dt > 1000) {
		dt = 0;
	}
   */
  if ((*(int *)(this + 0x1c) == 0) || (1000 < uVar5)) {
    uVar5 = 0;
  }

  /* 
    float speed = _ahrs.groundspeed();
   */
  *(int *)(this + 0x1c) = iVar2;
  (**(code **)(**(long **)(this + 0x58) + 0xf8))();
  Vector2<float>::_ZNK7Vector2IfE6lengthEv();
  plVar1 = *(long **)(this + 0x58);
  fVar8 = *(float *)(this + 0x14);
  *(float *)(this + 0x30) = param_1;
  lVar4 = *plVar1;
  /* 
    if (speed < _minspeed) {
        // assume a minimum speed. This stops oscillations when first starting to move
        speed = _minspeed;
    }
   */
  if (fVar8 <= extraout_XMM0_Da) {
    fVar8 = extraout_XMM0_Da;
  }

  /*
    // this is a linear approximation of the inverse steering
    // equation for a ground vehicle. It returns steering as an angle from -45 to 45
    float scaler = 1.0f / speed;
   */
  fVar6 = 1.0 / fVar8;


  /*
	// Calculate the steering rate error (deg/sec) and apply gain scaler
    // We do this in earth frame to allow for rover leaning over in hard corners
    float yaw_rate_earth = ToDeg(_ahrs.get_yaw_rate_earth());
   */
  if (*(code **)(lVar4 + 0xb8) == AP_AHRS_DCM::get_rotation_body_to_ned) {
    lVar3 = (long)plVar1 + 0x1dc;
  }
  else {
    lVar3 = (**(code **)(lVar4 + 0xb8))(plVar1);
    lVar4 = *plVar1;
  }
  if (*(code **)(lVar4 + 0x80) == AP_AHRS_DCM::get_gyro) {
    this_00 = (Vector3<float> *)((long)plVar1 + 0x234);
  }
  else {
    this_00 = (Vector3<float> *)(**(code **)(lVar4 + 0x80))(plVar1);
  }
  Vector3<float>::_ZNK7Vector3IfEmlERKS0_(this_00,(Vector3 *)(lVar3 + 0x18));
  fVar7 = extraout_XMM0_Da_00 * 57.29578;

  /*
    if (_reverse) {
        yaw_rate_earth *= -1.0f;
    }
   */
  if (this[0x60] != (AP_SteerController)0x0) {
    fVar7 = (float)((uint)fVar7 ^ 0x80000000);
  }
  /*
    _pid_info.actual = yaw_rate_earth;
   */
  *(float *)(this + 0x34) = fVar7;

  /*
    float rate_error = (desired_rate - yaw_rate_earth) * scaler;
   */
  fVar10 = *(float *)(this + 0xc) * *(float *)this;
  fVar9 = (param_1 - fVar7) * fVar6;


  /*
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
   */
  fVar11 = 0.0;
  fVar12 = fVar10 * 45.0;
  fVar7 = (*(float *)(this + 8) - fVar10) * *(float *)this - *(float *)(this + 0x10);
  if (0.0 < fVar7) {
    fVar11 = fVar7 * 45.0;
  }
  fVar7 = *(float *)(this + 4);
  if ((fVar12 <= 0.0) || (fVar8 < *(float *)(this + 0x14))) {
    *(undefined4 *)(this + 0x40) = 0;
    fVar10 = 0.0;
  }
  else {
    fVar10 = *(float *)(this + 0x40);
    if (uVar5 != 0) {
      fVar12 = (float)uVar5 * 0.001 * fVar12 * fVar9 * fVar6;
      if (-45.0 <= *(float *)(this + 0x20)) {
        if ((45.0 < *(float *)(this + 0x20)) && (0.0 <= fVar12)) {
          fVar12 = 0.0;
        }
      }
      else {
        if (fVar12 <= 0.0) {
          fVar12 = 0.0;
        }
      }
      fVar10 = fVar10 + fVar12;
      *(float *)(this + 0x40) = fVar10;
    }
  }


  /*
    // Scale the integration limit
    float intLimScaled = _imax * 0.01f;

    // Constrain the integrator state
    _pid_info.I = constrain_float(_pid_info.I, -intLimScaled, intLimScaled);
   */
  fVar10 = _Z20constrain_value_lineIfET_S0_S0_S0_j
                     (fVar10,(float)((uint)((float)(int)*(short *)(this + 0x18) * 0.01) ^ 0x80000000
                                    ),(float)(int)*(short *)(this + 0x18) * 0.01,0xb8);


  /*
    _pid_info.D = rate_error * _K_D * 4.0f; 
    _pid_info.P = (ToRad(desired_rate) * kp_ff) * scaler;
    _pid_info.FF = (ToRad(desired_rate) * k_ff) * scaler;
   */
  *(float *)(this + 0x40) = fVar10;
  fVar12 = fVar9 * *(float *)(this + 0x10) * 4.0;
  fVar9 = param_1 * 0.01745329 * fVar7 * 45.0 * fVar6;
  fVar6 = fVar11 * param_1 * 0.01745329 * fVar6;
  *(float *)(this + 0x44) = fVar12;
  *(float *)(this + 0x48) = fVar9;
  fVar7 = *(float *)(this + 0x24);
  *(float *)(this + 0x3c) = fVar6;
  fVar10 = fVar10 + fVar12 + fVar9 + fVar6;
  *(float *)(this + 0x20) = fVar10;


  /*
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
   */

  if (((float)((uint)fVar7 & 0x7fffffff) < 1.192093e-07) || (fVar8 <= fVar7)) {
    fVar6 = -4500.0;
    fVar8 = 4500.0;
  }
  else {
    fVar8 = 4500.0 - (fVar8 - fVar7) * *(float *)(this + 0x28) * 100.0;
    fVar7 = *(float *)(this + 0x2c);
    if (fVar7 <= fVar8) {
      fVar6 = (float)((uint)fVar8 ^ 0x80000000);
    }
    else {
      fVar6 = (float)((uint)fVar7 ^ 0x80000000);
      fVar8 = fVar7;
    }
  }

  /*
    // Convert to centi-degrees and constrain
    return constrain_float(_last_out * 100, -derate_constraint, derate_constraint);
   */
  fVar8 = _Z20constrain_value_lineIfET_S0_S0_S0_j(fVar10 * 100.0,fVar6,fVar8,0xcc);
  return CONCAT44(extraout_var,(int)fVar8);
}

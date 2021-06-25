#include <cstdint>
#include "vector2.h"

class AP_AHRS
{
public:
    // Constructor
    AP_AHRS() :
        _cos_yaw(1.0f)
    {
        _singleton = this;
    }

    // empty virtual destructor
    virtual ~AP_AHRS() {}

    float cos_yaw() const   {
        return _cos_yaw;
    }

    // return a ground vector estimate in meters/second, in North/East order
    virtual Vector2f groundspeed_vector(void);

    // return ground speed estimate in meters/second. Used by ground vehicles.
    float groundspeed(void) {
        return groundspeed_vector().length();
    }

protected:
    // helper trig variables
    float _cos_roll, _cos_pitch, _cos_yaw;
    float _sin_roll, _sin_pitch, _sin_yaw;

private:
    static AP_AHRS *_singleton;
};


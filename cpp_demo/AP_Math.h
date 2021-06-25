
template<typename T>
float sq(const T val)
{
    float v = static_cast<float>(val);
    return v*v;
}

/*
 * Variadic template for calculating the square norm of a vector of any
 * dimension.
 */
template<typename T, typename... Params>
float sq(const T first, const Params... parameters)
{
    return sq(first) + sq(parameters...);
}

/*
 * Variadic template for calculating the norm (pythagoras) of a vector of any
 * dimension.
 */
template<typename T, typename U, typename... Params>
float norm(const T first, const U second, const Params... parameters)
{
    return sqrtf(sq(first, second, parameters...));
}

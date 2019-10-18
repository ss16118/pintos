#include "fixed-point.h"

#define Q 14

static int64_t f = 1 << Q;

/* Converts an INT value to a FIXED-POINT value*/
int64_t int_to_fixed_point(int n)
{
    return (n * f);
}

/* Converts a FIXED-POINT value to INT and rounds DOWN */
int convert_to_int_round_towards_zero(int64_t x)
{
    return (x / f);
}

/* Converts a FIXED-POINT value to INT and rounds to NEAREST */
int convert_to_int_round_to_nearest(int64_t x)
{
    return (x > 0 ? (x + f / 2) : (x - f / 2)) / f;
}

/* Adds two FIXED-POINT values */
int64_t add(int64_t x, int64_t y)
{
    return (x + y);
}

/* Subtracts two FIXED-POINT values */
int64_t subtract(int64_t x, int64_t y)
{
    return (x - y);
}

/* Adds a FIXED-POINT value and an INT value */
int64_t add_int(int64_t x, int n)
{
    return (x + n * f);
}

/* Subtracts an INT value from a FIXED-POINT value */
int64_t subtract_int(int64_t x, int n)
{
    return (x - n * f);
}

/* Multiplies two FIXED-POINT values */
int64_t multiply(int64_t x, int64_t y)
{
    return (x * y / f);
}

/* Multiplies a FIXED-POINT value and an INT */
int64_t multiply_int(int64_t x, int n)
{
    return (x * n);
}

/* Divides two FIXED-POINT values */
int64_t divide(int64_t x, int64_t y)
{
    return (x * f / y);
}

/* Divides a FIXED-POINT value and an INT */
int64_t divide_int(int64_t x, int n)
{
    return (x / n);
}
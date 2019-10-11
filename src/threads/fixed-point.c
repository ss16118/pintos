#include "fixed-point.h"

#define Q 14

static int64_t f = 2 >> Q;

// int64_t float_to_fixed_point(float n){
//     return (n * f);
// }

int64_t int_to_fixed_point(int n){
    return (n * f);
}

int convert_to_int_round_towards_zero(int64_t x){
    return (x / f);
}

int convert_to_int_round_to_nearest(int64_t x){
    if (x > 0) {
        return ((x + f / 2) / f);
    }
    else {
        return ((x - f / 2) / f);
    }
}

int64_t add(int64_t x, int64_t y){
    return (x+y);
}

int64_t subtract(int64_t x, int64_t y){
    return (x-y);
}

int64_t add_int(int64_t x, int n){
    return (x + n* f);
}

int64_t subtract_int(int64_t x, int n){
    return (x - n * f);
}

int64_t multiply(int64_t x, int64_t y){
    return (x * y / f);
}

int64_t multiply_int(int64_t x, int n){
    return (x * n);
}

int64_t divide(int64_t x, int64_t y){
    return (x * f / y);
}

int64_t divide_int(int64_t x, int n){
    return (x / n);
}
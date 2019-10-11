#include <stdint.h>
#include <inttypes.h>

int64_t to_fixed_point(float n);

int convert_to_int_round_towards_zero(int64_t x);

int convert_to_int_round_to_nearest(int64_t x);

int64_t add(int64_t x, int64_t y);

int64_t subtract(int64_t x, int64_t y);

int64_t add_int(int64_t x, int n);

int64_t subtract_int(int64_t x, int n);

int64_t multiply(int64_t x, int64_t y):

int64_t multiply_int(int64_t x, int n);

int64_t divide(int64_t x, int64_t y);

int64_t divide_int(int64_t x, int n);

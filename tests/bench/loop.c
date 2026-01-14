#include <stdio.h>
#include <stdint.h>

int main(void) {
    const int n = 5000000;
    int64_t sum = 0;
    for (int i = 1; i <= n; i++) sum += i;
    printf("%lld\n", (long long)sum);
    return 0;
}

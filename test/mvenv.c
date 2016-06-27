#include <stdio.h>
#include <stdlib.h>

int main(void)
{
    printf("MV_VARIANT = '%s'\n", getenv("MV_VARIANT"));
    return 0;
}

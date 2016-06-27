#include <stdio.h>

int main(int argc, char **argv, char **envp)
{
    char **p = envp;
    do
    {
        printf("%s\n", *p);
    }
    while (*(++p));
    return 0;
}

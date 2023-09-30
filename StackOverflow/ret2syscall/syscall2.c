#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/syscall.h>
void exploit()
{
    system("/bin/sh");
}
void func()
{
char str[0x20];
read(0,str,0x50);
}
int main()
{
func();
return 0;
}
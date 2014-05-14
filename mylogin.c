#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc,char *argv[])
{
        char buf[16385];
        int i;
        strcpy(buf,"/mylogin/mylogin.py ");
        for(i=1;i<argc;i++)
        {
                strcat(buf,argv[i]);
                strcat(buf," ");
        }
        printf("execute %s\n",buf);
        setuid(0);
        return system(buf);
}


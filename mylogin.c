#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc,char *argv[])
{
        char fname[255];
        char buf[2048];
        FILE *fp;
        int i,j;
        char *p;
        p=argv[0];
        j=strlen(p);
        for(i=j;i>0;i--)
        {
            if (p[i]=='/')
                break;
        }
        if(p[i]=='/')
            p=p+i+1;
        sprintf(fname,"/etc/spdb/%s.cfg",p);
        //printf("load cfg file %s\n",fname);
        fp=fopen(fname,"r");
        if (NULL==fp)
        {
            printf("open %s error!\n",fname);
            exit(-1);
        }
        if ( fgets(buf,1024,fp) != NULL)
        {
            i=strlen(buf);
            buf[i-1]=' ';
            buf[i] =0;
            for(i=1;i<argc;i++)
            {
                strcat(buf,argv[i]);
                strcat(buf," ");
            }
            //printf("execute %s\n",buf);
            setuid(0);
            return system(buf);
        }
        else
        {
            printf("Error reading %s\n",fname);
        }
}


#include <CoreFoundation/CoreFoundation.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int main(void) {
    const char *config="/Library/Preferences/Parallels/network.desktop.xml";
    int fd=open(config,O_RDONLY); if (fd<0) return 1;
    char buf[32]={0}; ssize_t n=read(fd,buf,sizeof(buf)); close(fd);
    if (n!=15 || memcmp(buf,"isolated-config",15)) return 2;
    errno=0; fd=openat(AT_FDCWD,config,O_RDONLY);
    if (fd>=0) { close(fd); return 3; }
    if (errno!=EPERM && errno!=EACCES) return 4;
    errno=0; fd=openat(AT_FDCWD,"/Library/Logs/parallels.log",O_RDONLY);
    if (fd>=0) { close(fd); return 5; }
    if (errno!=EPERM && errno!=EACCES) return 6;
    FILE *log=fopen("/Library/Logs/parallels.log","a");
    if (!log || fputs("isolated log probe\n",log)<0 || fclose(log)) return 7;
    CFMessagePortRef port=CFMessagePortCreateRemote(NULL,CFSTR("com.parallels.disp.net.ipc"));
    if (!port) return 8;
    CFDataRef reply=NULL;
    SInt32 result=CFMessagePortSendRequest(port,0,NULL,2,2,kCFRunLoopDefaultMode,&reply);
    CFRelease(port);
    if (result || !reply) return 9;
    CFRelease(reply);
    puts("Private config and IPC remapping work; original Parallels files are inaccessible");
    return 0;
}

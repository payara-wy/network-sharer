#include <CoreFoundation/CoreFoundation.h>
#include <stdio.h>

int main(int argc,char **argv) {
    if (argc!=2) return 2;
    CFStringRef name=CFStringCreateWithCString(NULL,argv[1],kCFStringEncodingUTF8);
    if (!name) return 2;
    CFMessagePortRef port=CFMessagePortCreateRemote(NULL,name); CFRelease(name);
    if (!port) return 3;
    for (int i=0;i<1000;i++) {
        CFDataRef result=NULL;
        if (CFMessagePortSendRequest(port,0,NULL,2,2,kCFRunLoopDefaultMode,&result) || !result) { CFRelease(port); return 4; }
        CFRelease(result);
    }
    CFRelease(port); puts("1000 private dispatcher requests passed"); return 0;
}

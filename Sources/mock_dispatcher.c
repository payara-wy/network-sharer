#include <CoreFoundation/CoreFoundation.h>
#include <stdio.h>
#include <stdlib.h>
#include "parent_guard.h"

static CFDataRef reply(CFMessagePortRef port,SInt32 message_id,CFDataRef data,void *context) __attribute__((cf_returns_retained));
static CFDataRef reply(CFMessagePortRef port,SInt32 message_id,CFDataRef data,void *context) {
    (void)port; (void)data; (void)context;
    if (message_id!=0) return NULL;
    CFMutableDictionaryRef dict=CFDictionaryCreateMutable(NULL,0,&kCFTypeDictionaryKeyCallBacks,&kCFTypeDictionaryValueCallBacks);
    CFArrayRef networks=CFArrayCreate(NULL,NULL,0,&kCFTypeArrayCallBacks);
    CFDictionarySetValue(dict,CFSTR("all_networks"),networks);
    CFDataRef result=CFPropertyListCreateData(NULL,dict,kCFPropertyListXMLFormat_v1_0,0,NULL);
    CFRelease(networks); CFRelease(dict); return result;
}
int main(void) {
    if (!hotspot_start_parent_guard()) return 5;
    setvbuf(stderr,NULL,_IONBF,0);
    const char *value=getenv("NAPTD_DISPATCHER_PORT");
    if (!value || !*value) { fputs("missing_dispatcher_name\n",stderr); return 2; }
    CFStringRef name=CFStringCreateWithCString(NULL,value,kCFStringEncodingUTF8);
    if (!name) return 2;
    Boolean released=false;
    CFMessagePortRef port=CFMessagePortCreateLocal(NULL,name,reply,NULL,&released);
    CFRelease(name);
    if (!port) { fputs("dispatcher_port_unavailable\n",stderr); return 3; }
    CFRunLoopSourceRef source=CFMessagePortCreateRunLoopSource(NULL,port,0);
    if (!source) { CFRelease(port); return 4; }
    CFRunLoopAddSource(CFRunLoopGetCurrent(),source,kCFRunLoopDefaultMode);
    fputs("dispatcher_ready\n",stderr); CFRunLoopRun();
    CFRelease(source); CFRelease(port); return 0;
}

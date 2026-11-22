/* Own one sharing session and watch its user interface without disk heartbeats. */
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <libproc.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/event.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef NETWORKSHARER_SESSION_ROOT
#define NETWORKSHARER_SESSION_ROOT "/private/tmp"
#endif
#ifndef NETWORKSHARER_LOCK_PATH
#define NETWORKSHARER_LOCK_PATH "/private/tmp/com.local.lansharer.session.lock"
#endif

#define SESSION_PREFIX "lanproxy."
#define SESSION_MARKER "NetworkSharerSession/1\n"

static int session_name_valid(const char *name) {
    size_t n=strlen(SESSION_PREFIX);
    if (strncmp(name,SESSION_PREFIX,n) || strlen(name)!=n+8) return 0;
    for (const unsigned char *p=(const unsigned char *)name+n;*p;p++)
        if (!((*p>='0' && *p<='9') || (*p>='a' && *p<='z') || (*p>='A' && *p<='Z'))) return 0;
    return 1;
}
static int open_session(const char *path) {
    const char *base=strrchr(path,'/');
    if (!base || (size_t)(base-path)!=strlen(NETWORKSHARER_SESSION_ROOT) ||
        strncmp(path,NETWORKSHARER_SESSION_ROOT,strlen(NETWORKSHARER_SESSION_ROOT)) || !session_name_valid(base+1)) return -1;
    int fd=open(path,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    struct stat st;
    if (fd<0) return -1;
    if (fstat(fd,&st) || !S_ISDIR(st.st_mode) || st.st_uid!=geteuid() || (st.st_mode&0022)) { close(fd); return -1; }
    return fd;
}
static int marked_session(int dir) {
    int fd=openat(dir,"session.marker",O_RDONLY|O_NOFOLLOW|O_CLOEXEC);
    if (fd<0) return 0;
    struct stat st; char buf[sizeof(SESSION_MARKER)]={0};
    ssize_t n=read(fd,buf,sizeof(buf));
    int ok=!fstat(fd,&st) && S_ISREG(st.st_mode) && st.st_uid==geteuid() && st.st_nlink==1 &&
        n==(ssize_t)(sizeof(SESSION_MARKER)-1) && !memcmp(buf,SESSION_MARKER,sizeof(SESSION_MARKER)-1);
    close(fd); return ok;
}
static int session_owner_gone(int dir) {
    int fd=openat(dir,"session.owner",O_RDONLY|O_NOFOLLOW|O_CLOEXEC);
    if (fd<0) return 0;
    struct stat st; char buf[32]={0}; ssize_t n=read(fd,buf,sizeof(buf)-1);
    int safe=!fstat(fd,&st) && S_ISREG(st.st_mode) && st.st_uid==geteuid() && st.st_nlink==1;
    close(fd);
    if (!safe || n<1) return 0;
    char *end=NULL; long pid=strtol(buf,&end,10);
    if (pid<2 || (*end && *end!='\n')) return 0;
    return kill((pid_t)pid,0)<0 && errno==ESRCH;
}
/* Session state is shared with the graphical app, so an empty daemon_pid is
 * normal for a LAN-only session; a stale record must still be collectable. */
static int session_finished(int dir) {
    int fd=openat(dir,"state",O_RDONLY|O_NOFOLLOW|O_CLOEXEC);
    if (fd<0) return 0;
    struct stat st; char buf[4096]; ssize_t n=read(fd,buf,sizeof(buf)-1);
    int safe=!fstat(fd,&st) && S_ISREG(st.st_mode) && st.st_uid==geteuid() && st.st_nlink==1;
    close(fd);
    if (!safe || n<1) return 0;
    buf[n]='\0'; char *save=NULL, *line=strtok_r(buf,"\n",&save);
    int finished=0; long daemon=0,gateway=0;
    while (line) {
        if (!strcmp(line,"state=stopped") || !strcmp(line,"state=error")) finished=1;
        if (!strncmp(line,"daemon_pid=",11)) {
            char *end=NULL; long value=strtol(line+11,&end,10);
            if (end && !*end && value>1) daemon=value;
        }
        if (!strncmp(line,"gateway_pid=",12)) {
            char *end=NULL; long value=strtol(line+12,&end,10);
            if (end && !*end && value>1) gateway=value;
        }
        line=strtok_r(NULL,"\n",&save);
    }
    int daemon_gone=daemon>1 && kill((pid_t)daemon,0)<0 && errno==ESRCH;
    int gateway_gone=gateway>1 && kill((pid_t)gateway,0)<0 && errno==ESRCH;
    return finished || daemon_gone || gateway_gone;
}
static int write_file(int dir,const char *name,const char *value) {
    int fd=openat(dir,name,O_WRONLY|O_CREAT|O_TRUNC|O_NOFOLLOW|O_CLOEXEC,0600);
    if (fd<0) return 0;
    struct stat st; size_t n=strlen(value); int ok=0;
    if (!fstat(fd,&st) && S_ISREG(st.st_mode) && st.st_uid==geteuid() && st.st_nlink==1)
        ok=write(fd,value,n)==(ssize_t)n;
    close(fd); return ok;
}
static void remove_session(const char *path) {
    int dir=open_session(path);
    if (dir<0) return;
    int valid=marked_session(dir); close(dir);
    if (!valid) return;
    pid_t child=fork();
    if (child==0) { execl("/bin/rm","rm","-rf","--",path,(char *)NULL); _exit(127); }
    if (child>0) { int status; while (waitpid(child,&status,0)<0 && errno==EINTR) {} }
}
static void recover_interfaces(const char *engine,const char *session);
static void clean_old_sessions(const char *current,const char *engine) {
    DIR *root=opendir(NETWORKSHARER_SESSION_ROOT); if (!root) return;
    struct dirent *item;
    while ((item=readdir(root))) {
        if (!session_name_valid(item->d_name)) continue;
        char path[4096];
        int n=snprintf(path,sizeof(path),"%s/%s",NETWORKSHARER_SESSION_ROOT,item->d_name);
        if (n<0 || (size_t)n>=sizeof(path) || !strcmp(path,current)) continue;
        int dir=open_session(path);
        if (dir<0) continue;
        int stale=marked_session(dir) && (session_owner_gone(dir) || session_finished(dir));
        close(dir);
        if (stale) { recover_interfaces(engine,path); remove_session(path); }
    }
    closedir(root);
}
static int watch_process(int queue,pid_t pid) {
    struct kevent event;
    EV_SET(&event,(uintptr_t)pid,EVFILT_PROC,EV_ADD|EV_ENABLE|EV_ONESHOT,NOTE_EXIT,0,NULL);
    return kevent(queue,&event,1,NULL,0,NULL)==0;
}
static void publish_error(int dir) {
    const char *message="state=error\nphase=stopped\nmessage=后台组件异常退出，共享已停止，请重新开启。\n";
    if (write_file(dir,"state.recover",message)) (void)renameat(dir,"state.recover",dir,"state");
    (void)unlinkat(dir,"auth",0);
}
/* The controller's EXIT trap cannot run after SIGKILL. Re-run its guarded,
 * idempotent interface cleanup before dropping the session lock. */
static void recover_interfaces(const char *engine,const char *session) {
    char path[4096];
    int n=snprintf(path,sizeof(path),"%s/interfaces",session);
    if (n<0 || (size_t)n>=sizeof(path) || access(path,F_OK)!=0) return;
    pid_t child=fork();
    if (child==0) {
        execl("/bin/bash","bash",engine,"_recover",session,(char *)NULL);
        _exit(127);
    }
    if (child>0) {
        int status;
        while (waitpid(child,&status,0)<0 && errno==EINTR) {}
    }
}
int main(int argc,char **argv) {
    /* dir, engine, owner uid, owner pid, source, mode, proxy, dns, backup, port...
     * The port list may be empty: a LAN-only proxy session has no downstream port. */
    if (argc<10) return 2;
    int dir=open_session(argv[1]);
    if (dir<0 || !marked_session(dir)) return 2;
    char *end=NULL; long owner=strtol(argv[3],&end,10);
    if (*end || owner<0) { write_file(dir,"supervisor.status","invalid\n"); return 2; }
    long gui=strtol(argv[4],&end,10);
    if (*end || gui<2) { write_file(dir,"supervisor.status","invalid\n"); return 2; }
    struct proc_bsdinfo info;
    if (proc_pidinfo((int)gui,PROC_PIDTBSDINFO,0,&info,sizeof(info))!=(int)sizeof(info) || (long)info.pbi_uid!=owner) {
        write_file(dir,"supervisor.status","owner_gone\n"); return 2;
    }
    umask(077);
    int lock=open(NETWORKSHARER_LOCK_PATH,O_RDWR|O_CREAT|O_NOFOLLOW,0600);
    struct stat st;
    if (lock<0 || fstat(lock,&st) || !S_ISREG(st.st_mode) || st.st_uid!=geteuid() || st.st_nlink!=1 || (st.st_mode&0022)) {
        write_file(dir,"supervisor.status","lock_error\n"); return 3;
    }
    if (flock(lock,LOCK_EX|LOCK_NB)) { write_file(dir,"supervisor.status","busy\n"); return 3; }
    int queue=kqueue();
    if (queue<0 || !watch_process(queue,(pid_t)gui)) { write_file(dir,"supervisor.status","owner_gone\n"); return 3; }
    clean_old_sessions(argv[1],argv[2]);
    pid_t controller=fork();
    if (controller==0) {
        char **args=calloc((size_t)argc+2,sizeof(char *));
        if (!args) _exit(127);
        args[0]="/bin/bash"; args[1]=argv[2]; args[2]="_run"; args[3]=argv[1]; args[4]=argv[4];
        for (int i=5;i<argc;i++) args[i]=argv[i];
        args[argc]=NULL;
        execv(args[0],args); _exit(127);
    }
    if (controller<0) { write_file(dir,"supervisor.status","start_error\n"); return 3; }
    int watching_child=watch_process(queue,controller);
    if (!write_file(dir,"supervisor.status","ready\n")) { kill(controller,SIGTERM); }
    if (watching_child) {
        for (;;) {
            struct kevent event; int result=kevent(queue,NULL,0,&event,1,NULL);
            if (result<0 && errno==EINTR) continue;
            if (result<=0) { kill(controller,SIGTERM); break; }
            if ((pid_t)event.ident==(pid_t)gui) kill(controller,SIGTERM);
            if ((pid_t)event.ident==controller) break;
        }
    }
    int status=0;
    while (waitpid(controller,&status,0)<0 && errno==EINTR) {}
    recover_interfaces(argv[2],argv[1]);
    /* A fatal controller signal skips the shell's EXIT trap. Children watch
       their parent and stop; keep the lock while they release their sockets. */
    if (access(argv[1],F_OK)==0) {
        if (WIFSIGNALED(status)) { publish_error(dir); sleep(3); }
        /* Leave the status briefly for the UI without delaying a new session. */
        pid_t janitor=fork();
        if (janitor==0) {
            close(lock); close(queue); close(dir);
            sleep(5); remove_session(argv[1]); _exit(0);
        }
        if (janitor<0) remove_session(argv[1]);
    }
    close(dir); close(queue); close(lock);
    return 0;
}

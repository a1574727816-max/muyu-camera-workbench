#define _GNU_SOURCE
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <sys/resource.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <poll.h>
#include <fcntl.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* A single parent owns each log and drains a pipe, never a size-limited daemon.
 * Lock mode alone owns flock: no script, service or exec descendant inherits it.
 * Its child script cleans managed orphans on every start, including SIGKILL recovery.
 */
#define CHUNK 65536
static volatile sig_atomic_t stopping;
static void interrupted(int sig){(void)sig;stopping=1;}
static double now(void){struct timespec t;clock_gettime(CLOCK_MONOTONIC,&t);return t.tv_sec+t.tv_nsec/1e9;}
static unsigned long long started(pid_t pid){
 char path[80],buf[4096];snprintf(path,sizeof(path),"/proc/%ld/stat",(long)pid);
 int fd=open(path,O_RDONLY|O_CLOEXEC);if(fd<0)return 0;
 ssize_t n=read(fd,buf,sizeof(buf)-1);close(fd);if(n<=0)return 0;buf[n]=0;
 char *p=strrchr(buf,')');if(!p||p[1]!=' ')return 0;p+=2;if(*p=='Z'||*p=='X')return 0;
 for(int field=3;field<22;field++){p=strchr(p,' ');if(!p)return 0;p++;}
 return strtoull(p,NULL,10);
}
static int alive(pid_t pid,unsigned long long birth){return pid>1&&birth&&started(pid)==birth;}
static int terminate_old(pid_t pid,unsigned long long birth){
 if(!alive(pid,birth))return 0;
 kill(pid,SIGTERM);double until=now()+5;
 while(alive(pid,birth)&&now()<until)usleep(50000);
 if(alive(pid,birth)){kill(pid,SIGKILL);until=now()+2;while(alive(pid,birth)&&now()<until)usleep(20000);}
 return alive(pid,birth)?-1:0;
}
static int save(const char *path,const char *value){
 char temp[1024];if(snprintf(temp,sizeof(temp),"%s.new.%ld",path,(long)getpid())>=(int)sizeof(temp))return -1;
 int fd=open(temp,O_WRONLY|O_CREAT|O_TRUNC|O_CLOEXEC,0600);if(fd<0)return -1;
 size_t n=strlen(value);int ok=write(fd,value,n)==(ssize_t)n&&fsync(fd)==0;close(fd);
 if(!ok||rename(temp,path)){unlink(temp);return -1;}return 0;
}
static void remove_own_pid(const char *path,pid_t expected){
 FILE *f=fopen(path,"r");long p=0;if(!f)return;int rc=fscanf(f,"%ld",&p);fclose(f);
 if(rc==1&&p==expected)unlink(path);
}
typedef struct {int fd;size_t size;char current[1024],previous[1024];} Log;
static int log_open(Log *l){
 l->fd=open(l->current,O_RDWR|O_APPEND|O_CREAT|O_CLOEXEC,0600);if(l->fd<0)return -1;
 struct stat s;if(fstat(l->fd,&s)){close(l->fd);l->fd=-1;return -1;}l->size=(size_t)s.st_size;
 if(l->size>CHUNK){
  char *tail=malloc(CHUNK);if(!tail)return -1;
  ssize_t n=pread(l->fd,tail,CHUNK,(off_t)l->size-CHUNK);
  if(n!=CHUNK||ftruncate(l->fd,0)){free(tail);return -1;}
  size_t copied=0;while(copied<CHUNK){n=write(l->fd,tail+copied,CHUNK-copied);if(n<0&&errno==EINTR)continue;if(n<=0){free(tail);return -1;}copied+=(size_t)n;}
  free(tail);l->size=CHUNK;
 }
 return 0;
}
static int log_write(Log *l,const char *buf,size_t n){
 while(n){
  if(l->fd<0&&log_open(l))return -1;
  if(l->size>=CHUNK){
   close(l->fd);l->fd=-1;
   if(rename(l->current,l->previous)&&errno!=ENOENT)return -1;
   if(log_open(l))return -1;
  }
  size_t take=n;if(take>CHUNK-l->size)take=CHUNK-l->size;
  ssize_t k=write(l->fd,buf,take);if(k<0&&errno==EINTR)continue;if(k<=0)return -1;
  l->size+=(size_t)k;buf+=k;n-=(size_t)k;
 }return 0;
}
int main(int argc,char **argv){
 int lockmode=argc>1&&!strcmp(argv[1],"lock");
 if((lockmode&&argc<6)||(!lockmode&&(argc<5||strcmp(argv[1],"log"))))return 2;
 const char *lockpath=lockmode?argv[2]:NULL;
 const char *pidpath=argv[lockmode?3:2],*prefix=argv[lockmode?4:3];
 int command=lockmode?5:4,lockfd=-1,pipefd[2],status=0;
 char guardpath[1024],value[256];
 if(snprintf(guardpath,sizeof(guardpath),"%s.guard",pidpath)>=(int)sizeof(guardpath))return 2;
 struct rlimit limit={RLIM_INFINITY,RLIM_INFINITY};
 if(setrlimit(RLIMIT_FSIZE,&limit)){perror("netguard file limit");return 3;}
 limit.rlim_cur=limit.rlim_max=0;setrlimit(RLIMIT_CORE,&limit);
 if(lockmode){
  if(mkdir(lockpath,0700)&&errno!=EEXIST)return 3;
  lockfd=open(lockpath,O_RDONLY|O_DIRECTORY|O_CLOEXEC);if(lockfd<0)return 3;
  if(flock(lockfd,LOCK_EX|LOCK_NB)){int busy=errno==EWOULDBLOCK;close(lockfd);return busy?0:3;}
  /* Only stop a former child if its kernel start time still matches. */
  FILE *old=fopen(pidpath,"r");long oldguard=0,oldchild=0;unsigned long long gb=0,cb=0;
  if(old){int fields=fscanf(old,"%ld %llu %ld %llu",&oldguard,&gb,&oldchild,&cb);fclose(old);
   if(fields==4&&oldguard!=getpid()&&terminate_old((pid_t)oldchild,cb))return 3;
  }
 }
 Log log={.fd=-1};
 if(snprintf(log.current,sizeof(log.current),"%s.log",prefix)>=(int)sizeof(log.current)
    ||snprintf(log.previous,sizeof(log.previous),"%s.previous",prefix)>=(int)sizeof(log.previous))return 2;
 if(log_open(&log)||pipe2(pipefd,O_CLOEXEC)){perror("netguard output");return 3;}
 signal(SIGPIPE,SIG_IGN);signal(SIGTERM,interrupted);signal(SIGINT,interrupted);signal(SIGHUP,interrupted);
 pid_t parent=getpid(),child=fork();if(child<0)return 3;
 if(child==0){
  if(lockfd>=0)close(lockfd);
  close(pipefd[0]);close(log.fd);
  signal(SIGPIPE,SIG_DFL);signal(SIGTERM,SIG_DFL);signal(SIGINT,SIG_DFL);signal(SIGHUP,SIG_DFL);
  if(prctl(PR_SET_PDEATHSIG,SIGTERM)||getppid()!=parent)_exit(125);
  if(lockmode&&setsid()<0)_exit(125);
  int input=open("/dev/null",O_RDONLY);if(input<0||dup2(input,0)<0||dup2(pipefd[1],1)<0||dup2(pipefd[1],2)<0)_exit(125);
  if(input>2)close(input);
  if(pipefd[1]>2)close(pipefd[1]);
  execvp(argv[command],argv+command);_exit(127);
 }
 close(pipefd[1]);
 if(lockmode)snprintf(value,sizeof(value),"%ld %llu %ld %llu\n",(long)parent,started(parent),(long)child,started(child));
 else snprintf(value,sizeof(value),"%ld\n",(long)child);
 if(save(pidpath,value)){kill(child,SIGTERM);stopping=1;}
 if(!lockmode){snprintf(value,sizeof(value),"%ld\n",(long)parent);if(save(guardpath,value))stopping=1;}
 double deadline=0,drain_until=0;int done=0,eof=0,iofailed=0;
 for(;;){
  if(stopping&&!deadline){kill(child,SIGTERM);deadline=now()+5;}
  if(!done&&deadline&&now()>=deadline){kill(child,SIGKILL);deadline=now()+1;}
  if(!done){pid_t p=waitpid(child,&status,WNOHANG);if(p==child||(p<0&&errno==ECHILD)){done=1;drain_until=now()+.3;}}
  if(done&&(eof||now()>=drain_until))break;
  struct pollfd p={eof?-1:pipefd[0],POLLIN|POLLHUP,0};int ready=poll(&p,1,50);
  if(ready>0&&(p.revents&(POLLIN|POLLHUP))){
   char buf[4096];ssize_t n=read(pipefd[0],buf,sizeof(buf));
   if(n==0)eof=1;
   if(n>0&&log_write(&log,buf,(size_t)n)){iofailed=1;stopping=1;}
  }
 }
 close(pipefd[0]);if(log.fd>=0)close(log.fd);
 remove_own_pid(pidpath,lockmode?parent:child);if(!lockmode)remove_own_pid(guardpath,parent);
 if(lockfd>=0)close(lockfd);
 if(iofailed)return 3;
 return WIFEXITED(status)?WEXITSTATUS(status):WIFSIGNALED(status)?128+WTERMSIG(status):3;
}

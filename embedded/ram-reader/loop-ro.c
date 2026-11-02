/* Fixed RAM-backed, read-only SquashFS probe; never opens a Flash device. */
#include <errno.h>
#include <fcntl.h>
#include <linux/loop.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>
int main(int argc,char **argv){
 const char *image="/tmp/ptz-bcj-probe/image.squashfs";
 if(argc!=2)return 2;
 int loop=open("/dev/loop7",O_RDWR);if(loop<0){perror("loop");return 1;}
 struct loop_info64 info={0};int status=ioctl(loop,LOOP_GET_STATUS64,&info);
 if(!strcmp(argv[1],"detach")){
  if(status||strcmp((char*)info.lo_file_name,image)){close(loop);return 2;}
  status=ioctl(loop,LOOP_CLR_FD,0);close(loop);return status?1:0;
 }
 if(strcmp(argv[1],"attach")||status==0||errno!=ENXIO){close(loop);return 2;}
 int fd=open(image,O_RDONLY);if(fd<0){perror("image");close(loop);return 1;}
 if(ioctl(loop,LOOP_SET_FD,fd)){perror("set fd");close(fd);close(loop);return 1;}
 close(fd);memset(&info,0,sizeof(info));info.lo_flags=LO_FLAGS_READ_ONLY;
 strcpy((char*)info.lo_file_name,image);
 if(ioctl(loop,LOOP_SET_STATUS64,&info)){perror("set ro");ioctl(loop,LOOP_CLR_FD,0);close(loop);return 1;}
 memset(&info,0,sizeof(info));status=ioctl(loop,LOOP_GET_STATUS64,&info);
 if(status||!(info.lo_flags&LO_FLAGS_READ_ONLY)){ioctl(loop,LOOP_CLR_FD,0);close(loop);return 1;}
 close(loop);puts("RAM_LOOP_READONLY_READY");return 0;
}

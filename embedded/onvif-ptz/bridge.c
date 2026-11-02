/* Local ONVIF PTZ adapter. Stock device/media SOAP stays with nvid.
 * No Flash writes or shell evaluation. Auth file stores HTTP-Digest HA1 only.
 * A separate process stops motion on deadlines or loss of the server pipe.
 */
#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <expat.h>
#include <fcntl.h>
#include <math.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include "md5.h"

#define SOAP "http://www.w3.org/2003/05/soap-envelope"
#define SOAP11 "http://schemas.xmlsoap.org/soap/envelope/"
#define PTZ "http://www.onvif.org/ver20/ptz/wsdl"
#define TT "http://www.onvif.org/ver10/schema"
#define DEVICE "http://www.onvif.org/ver10/device/wsdl"
#define MEDIA "http://www.onvif.org/ver10/media/wsdl"
#define POS "http://www.onvif.org/ver10/tptz/PanTiltSpaces/PositionGenericSpace"
#define REL "http://www.onvif.org/ver10/tptz/PanTiltSpaces/TranslationGenericSpace"
#define VEL "http://www.onvif.org/ver10/tptz/PanTiltSpaces/VelocityGenericSpace"
#define SPEED "http://www.onvif.org/ver10/tptz/PanTiltSpaces/GenericSpeedSpace"
#define REALM "LocalCamera"
#define MAXBODY 32768
#define MAXREPLY 131072
#define MAXNODE 512

static char address[16]="127.0.0.1",backend[16]="127.0.0.1",username[65],ha1[33];
static char uuid[65]="urn:uuid:00000000-0000-4000-8000-000000000001";
static char endpoint[160],ptz_endpoint[160];
static int port=8899,backend_port=8888,watch_write=-1,watch_ack=-1;
static const char *ubus_path="/bin/ubus";
static const char *soap_ns=SOAP;
static char message_id[512],addressing[128],reply_action[320];
static volatile sig_atomic_t quitting;
static double mono(void){struct timespec t;clock_gettime(CLOCK_MONOTONIC,&t);return t.tv_sec+t.tv_nsec/1e9;}
static void signal_exit(int sig){(void)sig;quitting=1;}
static void *alloc(size_t n){void *p=calloc(1,n);if(!p){perror("allocate");exit(1);}return p;}
static void copy(char *to,size_t n,const char *from){if(strlen(from)>=n){fprintf(stderr,"oversized configuration\n");exit(2);}memcpy(to,from,strlen(from)+1);}
static char *format(const char *fmt,...){va_list ap;char *s=NULL;va_start(ap,fmt);if(vasprintf(&s,fmt,ap)<0)exit(1);va_end(ap);return s;}
static int sendall(int fd,const void *data,size_t n){const char *p=data;while(n){ssize_t z=send(fd,p,n,MSG_NOSIGNAL);if(z<0&&errno==EINTR)continue;if(z<=0)return -1;p+=z;n-=z;}return 0;}

/* Small bounded tree, namespace-aware through Expat. DTDs are rejected. */
typedef struct{char *name,*attrs[34];char text[512];size_t a,b,c,d;int parent;}Node;
typedef struct{XML_Parser parser;Node *nodes;int count,current,bad,depth;}Tree;
static const char *local(const char *n){const char *p=strchr(n,'|');return p?p+1:n;}
static int named(Node *n,const char *ns,const char *name){size_t k=strlen(ns);return !strncmp(n->name,ns,k)&&n->name[k]=='|'&&!strcmp(n->name+k+1,name);}
static void XMLCALL start(void *arg,const char *name,const char **attrs){
 Tree *t=arg;if(t->bad)return;if(t->count==MAXNODE||++t->depth>32){t->bad=1;XML_StopParser(t->parser,XML_FALSE);return;}
 Node *n=&t->nodes[t->count];n->name=strdup(name);n->parent=t->current;n->a=(size_t)XML_GetCurrentByteIndex(t->parser);n->b=n->a+XML_GetCurrentByteCount(t->parser);
 int i=0;for(;attrs[i];i+=2){if(i>=32||strlen(attrs[i+1])>4096){t->bad=1;XML_StopParser(t->parser,XML_FALSE);break;}n->attrs[i]=strdup(attrs[i]);n->attrs[i+1]=strdup(attrs[i+1]);}
 t->current=t->count++;
}
static void XMLCALL end(void *arg,const char *name){(void)name;Tree *t=arg;if(t->bad||t->current<0)return;Node *n=&t->nodes[t->current];n->c=(size_t)XML_GetCurrentByteIndex(t->parser);n->d=n->c+XML_GetCurrentByteCount(t->parser);t->current=n->parent;t->depth--;}
static void XMLCALL chars(void *arg,const char *text,int length){Tree *t=arg;if(t->bad||t->current<0)return;Node *n=&t->nodes[t->current];size_t used=strlen(n->text);if(used+(size_t)length>=sizeof(n->text)){t->bad=1;XML_StopParser(t->parser,XML_FALSE);return;}memcpy(n->text+used,text,length);}
static void XMLCALL doctype(void *arg,const char *a,const char *b,const char *c,int d){(void)a;(void)b;(void)c;(void)d;Tree *t=arg;t->bad=1;XML_StopParser(t->parser,XML_FALSE);}
static int parse(Tree *t,const char *data,size_t length){memset(t,0,sizeof(*t));t->current=-1;t->nodes=alloc(sizeof(Node)*MAXNODE);t->parser=XML_ParserCreateNS(NULL,'|');if(!t->parser)return 0;XML_SetUserData(t->parser,t);XML_SetElementHandler(t->parser,start,end);XML_SetCharacterDataHandler(t->parser,chars);XML_SetStartDoctypeDeclHandler(t->parser,doctype);return XML_Parse(t->parser,data,(int)length,XML_TRUE)==XML_STATUS_OK&&!t->bad&&t->count>0;}
static void tree_free(Tree *t){if(t->parser)XML_ParserFree(t->parser);for(int i=0;i<t->count;i++){free(t->nodes[i].name);for(int j=0;j<34;j++)free(t->nodes[i].attrs[j]);}free(t->nodes);}
static Node *child(Tree *t,Node *p,const char *ns,const char *name){int parent=(int)(p-t->nodes);Node *found=NULL;for(int i=parent+1;i<t->count;i++){Node *n=t->nodes+i;if(n->parent==parent&&named(n,ns,name)){if(found)return NULL;found=n;}}return found;}
static const char *attr(Node *n,const char *name){if(n)for(int i=0;n->attrs[i]&&i<32;i+=2)if(!strcmp(n->attrs[i],name))return n->attrs[i+1];return NULL;}
static int number(const char *s,double *v){if(!s||!*s)return 0;char *end;errno=0;*v=strtod(s,&end);return !errno&&end!=s&&!*end&&isfinite(*v);}

/* No command shell: JSON arguments are formatted from validated numbers. */
static int rpc(const char *method,const char *json,char *output,size_t cap){
 int fds[2];if(pipe2(fds,O_CLOEXEC))return -1;pid_t pid=fork();if(pid<0){close(fds[0]);close(fds[1]);return -1;}
 if(!pid){dup2(fds[1],STDOUT_FILENO);close(fds[0]);close(fds[1]);execl(ubus_path,"ubus","-t","2","call","motord",method,json?json:"{}",(char*)NULL);_exit(127);}
 close(fds[1]);fcntl(fds[0],F_SETFL,O_NONBLOCK);size_t n=0;double until=mono()+2.5;int status=-1,done=0;
 while(mono()<until){ssize_t z=read(fds[0],output+n,cap-1-n);if(z>0){n+=(size_t)z;if(n>=cap-1)break;}if(waitpid(pid,&status,WNOHANG)==pid){done=1;while(n<cap-1&&(z=read(fds[0],output+n,cap-1-n))>0)n+=(size_t)z;break;}struct pollfd p={fds[0],POLLIN,0};poll(&p,1,10);}
 if(!done){kill(pid,SIGKILL);waitpid(pid,&status,0);}close(fds[0]);output[n]=0;
 if(!done||!WIFEXITED(status)||WEXITSTATUS(status))return -1;
 const char *s=strstr(output,"\"error_code\"");if(!s||(s=strchr(s,':'))==NULL)return -1;return strtol(s+1,NULL,10)==0?0:-1;
}
static int motor_stop(void){char out[512];return rpc("stop",NULL,out,sizeof(out));}
static int json_int(const char *json,const char *key,int *value){char label[80];snprintf(label,sizeof(label),"\"%s\"",key);const char *s=strstr(json,label);if(!s||(s=strchr(s,':'))==NULL)return 0;s++;while(isspace((unsigned char)*s)||*s=='"')s++;char *e;long x=strtol(s,&e,10);if(e==s||x< -10000||x>10000)return 0;*value=(int)x;return 1;}
static int motor_status(int *x,int *y,int *sx,int *sy){char out[2048];return rpc("getStatus",NULL,out,sizeof(out))==0&&json_int(out,"x_coord",x)&&json_int(out,"y_coord",y)&&json_int(out,"x_speed",sx)&&json_int(out,"y_speed",sy);}

typedef struct{int milliseconds,sequence;}Watch;
static void supervisor(int input,int ack){
 signal(SIGTERM,SIG_IGN);signal(SIGINT,SIG_IGN);signal(SIGPIPE,SIG_IGN);double deadline=0;
 for(;;){struct pollfd p={input,POLLIN,0};int ms=deadline? (int)fmax(0,(deadline-mono())*1000): -1;int result=poll(&p,1,ms);
  if(result<0&&errno==EINTR)continue;
  if(result>0){Watch w;ssize_t n=read(input,&w,sizeof(w));if(n!=sizeof(w)){motor_stop();_exit(0);}deadline=w.milliseconds>0?mono()+w.milliseconds/1000.0:0;if(write(ack,&w.sequence,sizeof(w.sequence))!=sizeof(w.sequence)){motor_stop();_exit(1);}}
  if(deadline&&mono()>=deadline){int rc=motor_stop();fprintf(stderr,"PTZ_WATCHDOG_STOP result=%d\n",rc);deadline=0;}
 }
}
static int watch_set(int milliseconds){static int seq;Watch w={milliseconds,++seq};if(write(watch_write,&w,sizeof(w))!=sizeof(w))return -1;struct pollfd p={watch_ack,POLLIN,0};int answer=0;if(poll(&p,1,3000)<=0||read(watch_ack,&answer,sizeof(answer))!=sizeof(answer)||answer!=seq)return -1;return 0;}

/* HTTP Digest: per-challenge random nonce, client binding and monotonic nc. */
typedef struct{char nonce[33];uint32_t peer,nc;double issued;}Nonce;
static Nonce nonces[32];static unsigned next_nonce;
static void random_hex(char out[33]){unsigned char b[16];int fd=open("/dev/urandom",O_RDONLY|O_CLOEXEC);if(fd<0||read(fd,b,sizeof(b))!=sizeof(b)){perror("random");exit(1);}close(fd);const char *h="0123456789abcdef";for(int i=0;i<16;i++){out[2*i]=h[b[i]>>4];out[2*i+1]=h[b[i]&15];}out[32]=0;}
typedef struct{char key[32],value[256];}Pair;
static int digest_pairs(const char *s,Pair pairs[16]){if(strncmp(s,"Digest ",7))return -1;s+=7;int count=0;while(*s){while(*s==','||isspace((unsigned char)*s))s++;if(!*s)break;if(count==16)return -1;Pair *p=pairs+count;int k=0;while(isalnum((unsigned char)*s)||*s=='_'){if(k==31)return -1;p->key[k++]=*s++;}p->key[k]=0;while(isspace((unsigned char)*s))s++;if(!k||*s++!='=')return -1;while(isspace((unsigned char)*s))s++;k=0;if(*s=='"'){s++;while(*s&&*s!='"'){if(k==255||*s=='\\'||(unsigned char)*s<32)return -1;p->value[k++]=*s++;}if(*s++!='"')return -1;}else{while(*s&&*s!=','&&!isspace((unsigned char)*s)){if(k==255)return -1;p->value[k++]=*s++;}}p->value[k]=0;for(int i=0;i<count;i++)if(!strcmp(pairs[i].key,p->key))return -1;count++;while(isspace((unsigned char)*s))s++;if(*s&&*s!=',')return -1;}return count;}
static const char *pair(Pair *p,int n,const char *key){for(int i=0;i<n;i++)if(!strcmp(p[i].key,key))return p[i].value;return "";}
static int auth(const char *header,const char *path,uint32_t peer){
 Pair p[16]={0};int n=digest_pairs(header,p);if(n<0)return 0;
 const char *nonce=pair(p,n,"nonce"),*nc=pair(p,n,"nc"),*cn=pair(p,n,"cnonce"),*response=pair(p,n,"response");
 if(strcmp(pair(p,n,"username"),username)||strcmp(pair(p,n,"realm"),REALM)||strcmp(pair(p,n,"uri"),path)||strcmp(pair(p,n,"qop"),"auth")||strlen(nc)!=8||!*cn||strlen(response)!=32)return 0;
 if(*pair(p,n,"algorithm")&&strcasecmp(pair(p,n,"algorithm"),"MD5"))return 0;
 for(int i=0;i<8;i++)if(!isxdigit((unsigned char)nc[i]))return 0;
 uint32_t counter=(uint32_t)strtoul(nc,NULL,16);if(!counter)return 0;
 Nonce *entry=NULL;for(int i=0;i<32;i++)if(!strcmp(nonces[i].nonce,nonce)&&nonces[i].peer==peer&&mono()-nonces[i].issued<300)entry=nonces+i;if(!entry||counter<=entry->nc)return 0;
 char a2[33],expected[33];char *tmp=format("POST:%s",path);md5hex(tmp,strlen(tmp),a2);free(tmp);tmp=format("%s:%s:%s:%s:auth:%s",ha1,nonce,nc,cn,a2);md5hex(tmp,strlen(tmp),expected);free(tmp);unsigned diff=0;for(int i=0;i<32;i++)diff|=(unsigned char)expected[i]^(unsigned char)tolower((unsigned char)response[i]);if(diff)return 0;entry->nc=counter;return 1;
}
static void respond(int fd,int status,const char *body,const char *extra){char *h=format("HTTP/1.1 %d %s\r\nContent-Type: %s; charset=utf-8\r\nContent-Length: %zu\r\nConnection: close\r\n%s\r\n",status,status==200?"OK":status==401?"Unauthorized":status==400?"Bad Request":status==503?"Service Unavailable":"Internal Server Error",!strcmp(soap_ns,SOAP11)?"text/xml":"application/soap+xml",strlen(body),extra?extra:"");sendall(fd,h,strlen(h));sendall(fd,body,strlen(body));free(h);}
static void unauthorized(int fd,uint32_t peer){Nonce *n=nonces+next_nonce++%32;random_hex(n->nonce);n->peer=peer;n->nc=0;n->issued=mono();char *h=format("WWW-Authenticate: Digest realm=\"" REALM "\", nonce=\"%s\", algorithm=MD5, qop=\"auth\"\r\n",n->nonce);respond(fd,401,"",h);free(h);}

static char *xml_escape(const char *text){char *out=alloc(strlen(text)*6+1),*p=out;for(;*text;text++){const char *s=*text=='&'?"&amp;":*text=='<'?"&lt;":*text=='>'?"&gt;":*text=='\"'?"&quot;":*text=='\''?"&apos;":NULL;if(s){size_t n=strlen(s);memcpy(p,s,n);p+=n;}else *p++=*text;}*p=0;return out;}
static char *envelope(const char *body){char *id=xml_escape(message_id);char *header=*message_id?format("<s:Header><a:Action xmlns:a=\"%s\">%s</a:Action><a:RelatesTo xmlns:a=\"%s\">%s</a:RelatesTo></s:Header>",addressing,reply_action,addressing,id):strdup("");char *out=format("<?xml version=\"1.0\" encoding=\"UTF-8\"?><s:Envelope xmlns:s=\"%s\" xmlns:tptz=\"" PTZ "\" xmlns:tt=\"" TT "\" xmlns:ter=\"http://www.onvif.org/ver10/error\" xmlns:tds=\"" DEVICE "\" xmlns:trt=\"" MEDIA "\">%s<s:Body>%s</s:Body></s:Envelope>",soap_ns,header,body);free(id);free(header);return out;}
static void result(int fd,const char *operation,const char *body){char *b=format("<tptz:%sResponse>%s</tptz:%sResponse>",operation,body,operation);char *xml=envelope(b);respond(fd,200,xml,NULL);free(xml);free(b);}
static void fault(int fd,const char *subcode,const char *reason){char *b=!strcmp(soap_ns,SOAP11)?format("<s:Fault><faultcode>ter:%s</faultcode><faultstring>%s</faultstring></s:Fault>",subcode,reason):format("<s:Fault><s:Code><s:Value>s:Sender</s:Value><s:Subcode><s:Value>ter:%s</s:Value></s:Subcode></s:Code><s:Reason><s:Text xml:lang=\"en\">%s</s:Text></s:Reason></s:Fault>",subcode,reason);char *xml=envelope(b);respond(fd,500,xml,NULL);free(xml);free(b);}
static char *space2(const char *name,const char *uri){return format("<tt:%s><tt:URI>%s</tt:URI><tt:XRange><tt:Min>-1</tt:Min><tt:Max>1</tt:Max></tt:XRange><tt:YRange><tt:Min>-1</tt:Min><tt:Max>1</tt:Max></tt:YRange></tt:%s>",name,uri,name);}
static char *spaces(void){char *a=space2("AbsolutePanTiltPositionSpace",POS),*r=space2("RelativePanTiltTranslationSpace",REL),*v=space2("ContinuousPanTiltVelocitySpace",VEL);char *s=format("%s%s%s<tt:PanTiltSpeedSpace><tt:URI>" SPEED "</tt:URI><tt:XRange><tt:Min>0</tt:Min><tt:Max>1</tt:Max></tt:XRange></tt:PanTiltSpeedSpace>",a,r,v);free(a);free(r);free(v);return s;}
static char *config(void){return strdup("<tt:Name>LocalPanTilt</tt:Name><tt:UseCount>2</tt:UseCount><tt:NodeToken>ptz_node_1</tt:NodeToken><tt:DefaultAbsolutePantTiltPositionSpace>" POS "</tt:DefaultAbsolutePantTiltPositionSpace><tt:DefaultRelativePanTiltTranslationSpace>" REL "</tt:DefaultRelativePanTiltTranslationSpace><tt:DefaultContinuousPanTiltVelocitySpace>" VEL "</tt:DefaultContinuousPanTiltVelocitySpace><tt:DefaultPTZSpeed><tt:PanTilt x=\"0.5\" y=\"0.5\" space=\"" SPEED "\"/></tt:DefaultPTZSpeed><tt:DefaultPTZTimeout>PT1S</tt:DefaultPTZTimeout><tt:PanTiltLimits><tt:Range><tt:URI>" POS "</tt:URI><tt:XRange><tt:Min>-1</tt:Min><tt:Max>1</tt:Max></tt:XRange><tt:YRange><tt:Min>-1</tt:Min><tt:Max>1</tt:Max></tt:YRange></tt:Range></tt:PanTiltLimits>");}
static char *caps(void){return strdup("<tptz:Capabilities xmlns:tptz=\"" PTZ "\" EFlip=\"false\" Reverse=\"false\" GetCompatibleConfigurations=\"true\" MoveStatus=\"true\" StatusPosition=\"true\"/>");}
static char *device_ptz(void){return format("<tt:PTZ xmlns:tt=\"" TT "\"><tt:XAddr>%s</tt:XAddr></tt:PTZ>",ptz_endpoint);}
static int token(Tree *t,Node *op,const char *name,const char *expected){Node *n=child(t,op,PTZ,name);return n&&!strcmp(n->text,expected);}
static int vector(Tree *t,Node *op,const char *name,const char *space,double *x,double *y){Node *n=child(t,op,PTZ,name);if(!n)return 0;Node *v=child(t,n,TT,"PanTilt"),*z=child(t,n,TT,"Zoom");if(z)return 0;const char *s=attr(v,"space");return v&&(!s||!strcmp(s,space))&&number(attr(v,"x"),x)&&number(attr(v,"y"),y)&&fabs(*x)<=1&&fabs(*y)<=1;}
static int speed(Tree *t,Node *op,double *x,double *y){*x=*y=.5;Node *s=child(t,op,PTZ,"Speed");if(!s)return 1;return vector(t,op,"Speed",SPEED,x,y)&&*x>=0&&*y>=0;}
static int duration(const char *s,double *out){if(strncmp(s,"PT",2))return 0;s+=2;double seconds=0;int last=-1;while(*s){char *e;errno=0;double n=strtod(s,&e);if(errno||e==s||!isfinite(n)||n<0)return 0;int rank=*e=='H'?0:*e=='M'?1:*e=='S'?2:-1;if(rank<=last||rank<0)return 0;seconds+=n*(rank==0?3600:rank==1?60:1);last=rank;s=e+1;}if(last<0||seconds<.1||seconds>5)return 0;*out=seconds;return 1;}
static int move_to(int target_x,int target_y,double speed_x,double speed_y,int milliseconds){
 int x,y,sx,sy;if(watch_set(0)||motor_stop()||!motor_status(&x,&y,&sx,&sy))return -1;
 if(speed_x==0)target_x=x;
 if(speed_y==0)target_y=y;
 int dx=target_x-x,dy=target_y-y;if(!dx&&!dy)return 0;
 if((dx&&speed_x<=0)||(dy&&speed_y<=0))return -1;
 int ax=(int)lround(speed_x*9),ay=(int)lround(speed_y*9);if(ax<1)ax=1;if(ay<1)ay=1;
 char json[180],out[1024];snprintf(json,sizeof(json),"{\"x_coord\":\"%d\",\"y_coord\":\"%d\",\"x_speed\":\"%d\",\"y_speed\":\"%d\"}",dx,dy,ax,ay);
 if(rpc("targetTrack",json,out,sizeof(out))||watch_set(milliseconds)){motor_stop();return -1;}return 0;
}

static void ptz(int fd,Tree *t,Node *op){
 const char *name=local(op->name);char *b=NULL;
 if(!strcmp(name,"GetServiceCapabilities")){b=caps();result(fd,name,b);free(b);return;}
 if(!strcmp(name,"GetNodes")||!strcmp(name,"GetNode")){
  if(!strcmp(name,"GetNode")&&!token(t,op,"NodeToken","ptz_node_1")){fault(fd,"InvalidArgVal","Unknown node token");return;}
  char *s=spaces();b=format("<tptz:PTZNode token=\"ptz_node_1\" FixedHomePosition=\"true\"><tt:Name>LocalPanTilt</tt:Name><tt:SupportedPTZSpaces>%s</tt:SupportedPTZSpaces><tt:MaximumNumberOfPresets>0</tt:MaximumNumberOfPresets><tt:HomeSupported>true</tt:HomeSupported></tptz:PTZNode>",s);free(s);result(fd,name,b);free(b);return;
 }
 if(!strcmp(name,"GetConfigurations")||!strcmp(name,"GetConfiguration")||!strcmp(name,"GetCompatibleConfigurations")){
  if(!strcmp(name,"GetConfiguration")&&!token(t,op,"PTZConfigurationToken","ptz_config_1")){fault(fd,"InvalidArgVal","Unknown configuration token");return;}
  if(!strcmp(name,"GetCompatibleConfigurations")){Node *p=child(t,op,PTZ,"ProfileToken");if(!p||(strcmp(p->text,"profile_1")&&strcmp(p->text,"profile_2"))){fault(fd,"InvalidArgVal","Unknown profile token");return;}}
  char *c=config();b=format("<tptz:PTZConfiguration token=\"ptz_config_1\">%s</tptz:PTZConfiguration>",c);free(c);result(fd,name,b);free(b);return;
 }
 if(!strcmp(name,"GetConfigurationOptions")){
  if(!token(t,op,"ConfigurationToken","ptz_config_1")){fault(fd,"InvalidArgVal","Unknown configuration token");return;}
  char *s=spaces();b=format("<tptz:PTZConfigurationOptions><tt:Spaces>%s</tt:Spaces><tt:PTZTimeout><tt:Min>PT0.1S</tt:Min><tt:Max>PT5S</tt:Max></tt:PTZTimeout></tptz:PTZConfigurationOptions>",s);free(s);result(fd,name,b);free(b);return;
 }
 Node *profile=child(t,op,PTZ,"ProfileToken");if(!profile||(strcmp(profile->text,"profile_1")&&strcmp(profile->text,"profile_2"))){fault(fd,"InvalidArgVal","Unknown profile token");return;}
 if(!strcmp(name,"GetPresets")){result(fd,name,"");return;}
 if(!strcmp(name,"GetStatus")){
  int x,y,sx,sy;if(!motor_status(&x,&y,&sx,&sy)){fault(fd,"Action","Motor status unavailable");return;}
  time_t now=time(NULL);struct tm tm;gmtime_r(&now,&tm);char stamp[32];strftime(stamp,sizeof(stamp),"%Y-%m-%dT%H:%M:%SZ",&tm);
  b=format("<tptz:PTZStatus><tt:Position><tt:PanTilt x=\"%.6f\" y=\"%.6f\" space=\"" POS "\"/></tt:Position><tt:MoveStatus><tt:PanTilt>%s</tt:PanTilt></tt:MoveStatus><tt:UtcTime>%s</tt:UtcTime></tptz:PTZStatus>",x/158.0,y/90.0,(sx||sy)?"MOVING":"IDLE",stamp);result(fd,name,b);free(b);return;
 }
 if(!strcmp(name,"Stop")){
  Node *pan=child(t,op,PTZ,"PanTilt");if(pan&&strcmp(pan->text,"true")&&strcmp(pan->text,"1")&&strcmp(pan->text,"false")&&strcmp(pan->text,"0")){fault(fd,"InvalidArgVal","Invalid boolean");return;}
  if(!pan||!strcmp(pan->text,"true")||!strcmp(pan->text,"1")){if(watch_set(0)||motor_stop()){fault(fd,"Action","Stop failed");return;}}
  result(fd,name,"");return;
 }
 int continuous=!strcmp(name,"ContinuousMove"),absolute=!strcmp(name,"AbsoluteMove"),relative=!strcmp(name,"RelativeMove"),home=!strcmp(name,"GotoHomePosition");
 if(!continuous&&!absolute&&!relative&&!home){fault(fd,"ActionNotSupported","Operation not supported");return;}
 double vx=0,vy=0,sx=.5,sy=.5,seconds=1;
 if(continuous){if(!vector(t,op,"Velocity",VEL,&vx,&vy)){fault(fd,"InvalidArgVal","Unsupported velocity or space");return;}Node *d=child(t,op,PTZ,"Timeout");if(d&&!duration(d->text,&seconds)){fault(fd,"InvalidArgVal","Timeout must be PT0.1S through PT5S");return;}sx=fabs(vx);sy=fabs(vy);if(!vx&&!vy){if(watch_set(0)||motor_stop())fault(fd,"Action","Stop failed");else result(fd,name,"");return;}}
 else if(!speed(t,op,&sx,&sy)||(!home&&!vector(t,op,absolute?"Position":"Translation",absolute?POS:REL,&vx,&vy))){fault(fd,"InvalidArgVal","Unsupported position, speed or space");return;}
 int x,y,mx,my;if(!motor_status(&x,&y,&mx,&my)){fault(fd,"Action","Motor status unavailable");return;}
 int tx=0,ty=0;
 if(continuous){tx=vx>0?158:vx<0?-158:x;ty=vy>0?90:vy<0?-90:y;}
 else if(!home){tx=(int)lround(vx*158)+(relative?x:0);ty=(int)lround(vy*90)+(relative?y:0);if(relative){if(tx>158)tx=158;if(tx< -158)tx=-158;if(ty>90)ty=90;if(ty< -90)ty=-90;}}
 if((tx!=x&&sx<=0)||(ty!=y&&sy<=0)){fault(fd,"InvalidArgVal","Nonzero movement requires positive speed");return;}
 if(move_to(tx,ty,sx,sy,continuous?(int)lround(seconds*1000):15000)){fault(fd,"Action","Motor command failed");return;}
 fprintf(stderr,"PTZ_MOVE operation=%s target=%d,%d timeout_ms=%d\n",name,tx,ty,continuous?(int)lround(seconds*1000):15000);result(fd,name,"");
}

/* Retain trusted backend SOAP bytes except endpoint and PTZ capability edits. */
typedef struct{size_t pos,length;char *text;}Edit;
static int editcmp(const void *a,const void *b){const Edit *x=a,*y=b;return x->pos<y->pos?-1:x->pos>y->pos?1:0;}
static char *replace_literal(char *input,const char *old,const char *replacement){size_t count=0,n=strlen(old);for(const char *p=input;(p=strstr(p,old));p+=n)count++;if(!count)return input;char *out=alloc(strlen(input)+count*strlen(replacement)+1),*dest=out;const char *p=input,*q;while((q=strstr(p,old))){memcpy(dest,p,q-p);dest+=q-p;memcpy(dest,replacement,strlen(replacement));dest+=strlen(replacement);p=q+n;}strcpy(dest,p);free(input);return out;}
static char *rewrite(char *body,size_t size,const char *operation){
 Tree t;int ok=parse(&t,body,size);if(!ok){tree_free(&t);return NULL;}Edit e[80];int count=0;
 for(int i=0;i<t.count&&count<76;i++){
  Node *n=t.nodes+i;
  if(!strcmp(local(n->name),"XAddr")&&strstr(n->text,"http://")==n->text){e[count++]=(Edit){n->b,n->c-n->b,strdup(endpoint)};}
  if(!strcmp(operation,"GetCapabilities")&&named(n,DEVICE,"Capabilities")){
   char *c=device_ptz();size_t position=n->c;for(int j=i+1;j<t.count;j++)if(t.nodes[j].parent==i&&named(t.nodes+j,TT,"Extension")){position=t.nodes[j].a;break;}e[count++]=(Edit){position,0,c};
  }
  if(!strcmp(operation,"GetServices")&&named(n,DEVICE,"GetServicesResponse")){
   char *c=caps();char *b=format("<tds:Service><tds:Namespace>" PTZ "</tds:Namespace><tds:XAddr>%s</tds:XAddr><tds:Capabilities>%s</tds:Capabilities><tds:Version><tt:Major>2</tt:Major><tt:Minor>0</tt:Minor></tds:Version></tds:Service>",ptz_endpoint,c);free(c);e[count++]=(Edit){n->c,0,b};
  }
  if((!strcmp(operation,"GetProfiles")&&named(n,MEDIA,"Profiles"))||(!strcmp(operation,"GetProfile")&&named(n,MEDIA,"Profile"))){char *c=config();char *b=format("<tt:PTZConfiguration token=\"ptz_config_1\">%s</tt:PTZConfiguration>",c);free(c);e[count++]=(Edit){n->c,0,b};}
 }
 qsort(e,count,sizeof(Edit),editcmp);size_t capacity=size+20000,offset=0,used=0;char *out=alloc(capacity);
 for(int i=0;i<count;i++){size_t add=strlen(e[i].text);if(e[i].pos<offset||e[i].pos>size||e[i].length>size-e[i].pos||used+(e[i].pos-offset)+add+(size-e[i].pos-e[i].length)+1>capacity){free(out);out=NULL;break;}memcpy(out+used,body+offset,e[i].pos-offset);used+=e[i].pos-offset;memcpy(out+used,e[i].text,add);used+=add;offset=e[i].pos+e[i].length;}
 if(out){memcpy(out+used,body+offset,size-offset);out[used+size-offset]=0;}
 for(int i=0;i<count;i++)free(e[i].text);
 tree_free(&t);if(out){out=replace_literal(out,"HttpDigest=\"false\"","HttpDigest=\"true\"");out=replace_literal(out,"UsernameToken=\"true\"","UsernameToken=\"false\"");}return out;
}

static int connect_backend(void){int s=socket(AF_INET,SOCK_STREAM|SOCK_CLOEXEC,0);if(s<0)return -1;struct timeval tv={3,0};setsockopt(s,SOL_SOCKET,SO_RCVTIMEO,&tv,sizeof(tv));setsockopt(s,SOL_SOCKET,SO_SNDTIMEO,&tv,sizeof(tv));struct sockaddr_in a={.sin_family=AF_INET,.sin_port=htons(backend_port)};inet_pton(AF_INET,backend,&a.sin_addr);if(connect(s,(struct sockaddr*)&a,sizeof(a))){close(s);return -1;}return s;}
static void proxy(int fd,const char *body,const char *operation){
 int s=connect_backend();if(s<0){fault(fd,"Action","Device service unavailable");return;}
 char *request=format("POST /onvif/service HTTP/1.0\r\nHost: %s:%d\r\nContent-Type: application/soap+xml; charset=utf-8\r\nContent-Length: %zu\r\nConnection: close\r\n\r\n%s",backend,backend_port,strlen(body),body);
 if(sendall(s,request,strlen(request))){free(request);close(s);fault(fd,"Action","Backend transport failed");return;}free(request);
 char *response=alloc(MAXREPLY+1);size_t n=0;ssize_t z;while(n<MAXREPLY&&(z=recv(s,response+n,MAXREPLY-n,0))>0)n+=(size_t)z;close(s);response[n]=0;
 char *data=strstr(response,"\r\n\r\n");if(!data||n==MAXREPLY){free(response);fault(fd,"Action","Invalid backend reply");return;}data+=4;char *updated=rewrite(data,n-(size_t)(data-response),operation);if(!updated){free(response);fault(fd,"Action","Invalid backend XML");return;}
 int status=500;sscanf(response,"HTTP/%*s %d",&status);respond(fd,status,updated,NULL);free(updated);free(response);
}

static int header_value(const char *headers,const char *name,char *out,size_t cap){
 size_t k=strlen(name);int found=0;const char *p=strstr(headers,"\r\n");if(!p)return 0;p+=2;
 while(*p){const char *end=strstr(p,"\r\n");if(!end)break;if(end==p)break;if(!strncasecmp(p,name,k)&&p[k]==':'){if(found)return -1;const char *a=p+k+1;while(a<end&&(*a==' '||*a=='\t'))a++;size_t n=(size_t)(end-a);if(n>=cap)return -1;memcpy(out,a,n);out[n]=0;found=1;}p=end+2;}return found;
}
static void client(int fd,uint32_t peer){
 soap_ns=SOAP;message_id[0]=addressing[0]=reply_action[0]=0;
 struct timeval tv={2,0};setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&tv,sizeof(tv));setsockopt(fd,SOL_SOCKET,SO_SNDTIMEO,&tv,sizeof(tv));
 char *request=alloc(MAXBODY+8193);size_t n=0,head=0,length=0;double until=mono()+3;
 while(n<MAXBODY+8192&&mono()<until){ssize_t z=recv(fd,request+n,MAXBODY+8192-n,0);if(z<=0)break;n+=(size_t)z;request[n]=0;if(!head){char *p=strstr(request,"\r\n\r\n");if(p){head=(size_t)(p+4-request);if(head>8192)break;char save=request[head];request[head]=0;char len[32],te[80];if(header_value(request,"Transfer-Encoding",te,sizeof(te))!=0||header_value(request,"Content-Length",len,sizeof(len))!=1){request[head]=save;break;}char *e;unsigned long v=strtoul(len,&e,10);request[head]=save;if(!*len||*e||v>MAXBODY||!v)break;length=v;}}
  if(head&&n>=head+length)break;
 }
 if(!head||!length||n!=head+length){respond(fd,400,"",NULL);free(request);return;}
 char method[12],path[256],version[20];if(sscanf(request,"%11s %255s %19s",method,path,version)!=3||strcmp(method,"POST")||strncmp(path,"/onvif/",7)){respond(fd,400,"",NULL);free(request);return;}
 request[head+length]=0;Tree t;int valid=parse(&t,request+head,length);soap_ns=SOAP;
 if(valid){if(named(t.nodes,SOAP11,"Envelope"))soap_ns=SOAP11;else if(!named(t.nodes,SOAP,"Envelope"))valid=0;}
 Node *body=valid?child(&t,t.nodes,soap_ns,"Body"):NULL,*op=NULL;
 if(body)for(int i=1;i<t.count;i++)if(t.nodes[i].parent==(int)(body-t.nodes)){if(op){valid=0;break;}op=t.nodes+i;}
 if(!valid||!op){fault(fd,"InvalidArgVal","Invalid SOAP envelope");tree_free(&t);free(request);return;}
 Node *headnode=child(&t,t.nodes,soap_ns,"Header");
 if(headnode){const char *ns[2]={"http://schemas.xmlsoap.org/ws/2004/08/addressing","http://www.w3.org/2005/08/addressing"};for(int i=0;i<2;i++){Node *id=child(&t,headnode,ns[i],"MessageID");if(id){copy(message_id,sizeof(message_id),id->text);copy(addressing,sizeof(addressing),ns[i]);break;}}}
 if(strlen(local(op->name))>200){fault(fd,"InvalidArgVal","Operation name too long");tree_free(&t);free(request);return;}
 snprintf(reply_action,sizeof(reply_action),PTZ "/%sResponse",local(op->name));
 int isptz=!strncmp(op->name,PTZ "|",strlen(PTZ)+1);
 if(isptz){char authheader[2048];char save=request[head];request[head]=0;int got=header_value(request,"Authorization",authheader,sizeof(authheader));request[head]=save;if(got!=1||!auth(authheader,path,peer))unauthorized(fd,peer);else ptz(fd,&t,op);}
 else if(named(op,DEVICE,"GetCapabilities")){
  Node *category=child(&t,op,DEVICE,"Category");if(category&&!strcmp(category->text,"PTZ")){char *p=device_ptz();char *b=format("<tds:GetCapabilitiesResponse><tds:Capabilities>%s</tds:Capabilities></tds:GetCapabilitiesResponse>",p);char *e=envelope(b);respond(fd,200,e,NULL);free(p);free(b);free(e);}else proxy(fd,request+head,local(op->name));
 }
 else if(!strncmp(local(op->name),"Get",3)&&(!strncmp(op->name,DEVICE "|",strlen(DEVICE)+1)||!strncmp(op->name,MEDIA "|",strlen(MEDIA)+1)||!strncmp(op->name,"http://www.onvif.org/",strlen("http://www.onvif.org/"))))proxy(fd,request+head,local(op->name));
 else fault(fd,"ActionNotSupported","Only device/media reads and authenticated PTZ are enabled");
 tree_free(&t);free(request);
}

static int discovery_socket(void){int s=socket(AF_INET,SOCK_DGRAM|SOCK_CLOEXEC,0),one=1;if(s<0)return -1;setsockopt(s,SOL_SOCKET,SO_REUSEADDR,&one,sizeof(one));struct sockaddr_in a={.sin_family=AF_INET,.sin_port=htons(3702),.sin_addr.s_addr=INADDR_ANY};if(bind(s,(struct sockaddr*)&a,sizeof(a))){close(s);return -1;}struct ip_mreq m={0};inet_pton(AF_INET,"239.255.255.250",&m.imr_multiaddr);inet_pton(AF_INET,address,&m.imr_interface);if(setsockopt(s,IPPROTO_IP,IP_ADD_MEMBERSHIP,&m,sizeof(m))){close(s);return -1;}return s;}
static void discovery(int fd){
 char raw[8193];struct sockaddr_in peer;socklen_t size=sizeof(peer);ssize_t n=recvfrom(fd,raw,8192,0,(struct sockaddr*)&peer,&size);if(n<=0)return;raw[n]=0;Tree t;if(!parse(&t,raw,(size_t)n)){tree_free(&t);return;}
 const char *id=NULL;int probe=0;for(int i=0;i<t.count;i++){Node *p=t.nodes+i;if(!strcmp(local(p->name),"MessageID"))id=p->text;if(!strcmp(local(p->name),"Probe"))probe=1;}
 if(probe&&id&&strlen(id)<160&&!strpbrk(id,"<>&\"'")){
  char random[33],message[37];random_hex(random);snprintf(message,sizeof(message),"%.8s-%.4s-%.4s-%.4s-%.12s",random,random+8,random+12,random+16,random+20);char *response=format("<s:Envelope xmlns:s=\"" SOAP "\" xmlns:a=\"http://schemas.xmlsoap.org/ws/2004/08/addressing\" xmlns:d=\"http://schemas.xmlsoap.org/ws/2005/04/discovery\" xmlns:dn=\"http://www.onvif.org/ver10/network/wsdl\"><s:Header><a:MessageID>urn:uuid:%s</a:MessageID><a:RelatesTo>%s</a:RelatesTo><a:To>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:To><a:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/ProbeMatches</a:Action><d:AppSequence InstanceId=\"1\" MessageNumber=\"1\"/></s:Header><s:Body><d:ProbeMatches><d:ProbeMatch><a:EndpointReference><a:Address>%s</a:Address></a:EndpointReference><d:Types>dn:NetworkVideoTransmitter</d:Types><d:Scopes>onvif://www.onvif.org/type/video_encoder onvif://www.onvif.org/type/ptz onvif://www.onvif.org/name/LocalCamera</d:Scopes><d:XAddrs>%s</d:XAddrs><d:MetadataVersion>2</d:MetadataVersion></d:ProbeMatch></d:ProbeMatches></s:Body></s:Envelope>",message,id,uuid,endpoint);sendto(fd,response,strlen(response),0,(struct sockaddr*)&peer,size);free(response);
 }
 tree_free(&t);
}

int main(int argc,char **argv){
 const char *authfile=NULL;int discover=0;
 for(int i=1;i<argc;i++){if(!strcmp(argv[i],"--discover")){discover=1;continue;}if(i+1==argc)return 2;const char *key=argv[i++],*value=argv[i];if(!strcmp(key,"--listen"))copy(address,sizeof(address),value);else if(!strcmp(key,"--backend"))copy(backend,sizeof(backend),value);else if(!strcmp(key,"--port"))port=atoi(value);else if(!strcmp(key,"--backend-port"))backend_port=atoi(value);else if(!strcmp(key,"--auth"))authfile=value;else if(!strcmp(key,"--uuid"))copy(uuid,sizeof(uuid),value);else if(!strcmp(key,"--ubus")&&*value=='/')ubus_path=value;else return 2;}
 struct in_addr check;if(!authfile||port<1||port>65535||backend_port<1||backend_port>65535||inet_pton(AF_INET,address,&check)!=1||inet_pton(AF_INET,backend,&check)!=1||strpbrk(uuid,"<>&\"'"))return 2;
 FILE *f=fopen(authfile,"r");if(!f){perror("auth file");return 2;}if(fscanf(f,"%64s %32s",username,ha1)!=2){fclose(f);return 2;}fclose(f);if(strlen(ha1)!=32)return 2;for(int i=0;i<32;i++)if(!isxdigit((unsigned char)ha1[i]))return 2;
 for(const char *p=username;*p;p++)if(!isalnum((unsigned char)*p)&&*p!='_'&&*p!='-')return 2;
 snprintf(endpoint,sizeof(endpoint),"http://%s:%d/onvif/service",address,port);snprintf(ptz_endpoint,sizeof(ptz_endpoint),"http://%s:%d/onvif/ptz_service",address,port);
 struct rlimit core={0,0};setrlimit(RLIMIT_CORE,&core);signal(SIGPIPE,SIG_IGN);signal(SIGTERM,signal_exit);signal(SIGINT,signal_exit);
 int s=socket(AF_INET,SOCK_STREAM|SOCK_CLOEXEC,0),one=1;if(s<0)return 1;setsockopt(s,SOL_SOCKET,SO_REUSEADDR,&one,sizeof(one));struct sockaddr_in a={.sin_family=AF_INET,.sin_port=htons(port)};inet_pton(AF_INET,address,&a.sin_addr);if(bind(s,(struct sockaddr*)&a,sizeof(a))||listen(s,8)){perror("listen");return 1;}
 int udp=discover?discovery_socket():-1;if(discover&&udp<0){perror("discovery");close(s);return 1;}
 int command[2],ack[2];if(pipe2(command,O_CLOEXEC)||pipe2(ack,O_CLOEXEC))return 1;pid_t watcher=fork();if(watcher<0)return 1;
 if(!watcher){close(command[1]);close(ack[0]);close(s);if(udp>=0)close(udp);supervisor(command[0],ack[1]);return 0;}
 close(command[0]);close(ack[1]);watch_write=command[1];watch_ack=ack[0];
 fprintf(stderr,"ONVIF_PTZ_READY endpoint=%s backend=%s:%d watchdog=%d\n",endpoint,backend,backend_port,(int)watcher);
 while(!quitting){struct pollfd p[2]={{s,POLLIN,0},{udp,POLLIN,0}};int n=poll(p,udp<0?1:2,200);if(n<0&&errno!=EINTR)break;if(udp>=0&&(p[1].revents&POLLIN))discovery(udp);if(p[0].revents&POLLIN){struct sockaddr_in peer;socklen_t k=sizeof(peer);int c=accept4(s,(struct sockaddr*)&peer,&k,SOCK_CLOEXEC);if(c>=0){client(c,peer.sin_addr.s_addr);close(c);}}}
 close(s);if(udp>=0)close(udp);close(watch_write);close(watch_ack);waitpid(watcher,NULL,0);fprintf(stderr,"ONVIF_PTZ_EXIT\n");return 0;
}

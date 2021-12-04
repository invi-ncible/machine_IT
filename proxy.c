/*
 * proxy.c - CS:APP Web proxy
 *
 * TEAM MEMBERS:
 *     2016430024 - Yoon HeeSeung
 *     2017430031 - Lee JuneHee
 * 
 * IMPORTANT: Give a high level description of your code here. You
 * must also provide a header comment at the beginning of each
 * function that describes what that function does.
 */ 

#include "csapp.h"

FILE *log_file;                                                         //proxy.log
pthread_mutex_t mutex_lock;                                             //critical section을 가진 thread들의 running time이 겹치지 않게 실행
                                                                    
typedef struct _Connec{                                                 //peer thread에 소켓 정보를 전달하기 위한 구조체 선언
    int connectfd;
    struct sockaddr_in addr;
}Connec;

void *thread(void *vargp);
void proxy(int connfd, struct sockaddr_in *sockaddr);
void read_request_headers(rio_t *rp);
int parse_uri(char *uri, char *target_addr, char *path, int *port);
void format_log_entry(char *logstring, struct sockaddr_in *sockaddr, char *uri, int size);

void sigpipe_handler(int signal){                                       //연결이 끊어진 소켓에 쓰기를 하게 되면 프로그램을 종료시키는 SIGPIPE 시그널을 핸들링하기 위함 함수
    printf("SIGPIPE HANDLED\n");                                        
    return;                                                         
}

int main(int argc, char **argv){                            
    if (argc != 2) {                                                    //프록시 실행시 portnumber 입력, 입력하지 않을시 종료
	fprintf(stderr, "Usage: %s <port number>\n", argv[0]);
	exit(0);
    }

    int listenfd;
    Connec *connec;
    socklen_t clientlen;
    struct sockaddr_in clientaddr;                                      //client 의 socket address
    pthread_t tid;

    signal(SIGPIPE, sigpipe_handler);      
    pthread_mutex_init(&mutex_lock, NULL);                              //mutex 초기화

    int portnum = atoi(argv[1]); 
    listenfd = open_listenfd(portnum);                                  //client와의 연결을 기다림
    log_file = fopen("proxy.log","a");                                  //proxy.log 파일 생성, 맨 뒤에서부터 편집

    while(1){
        clientlen = sizeof(struct sockaddr_in);                         //proxy와 client의 connection fd가 동적으로 할당됨
        connec = malloc(sizeof(Connect));                               //main thread 와 pear thread 가 동히세 connfd에 접근하는 것을 막음 
        connec->connectfd= accept(listenfd, (SA *)&clientaddr, &clientlen);        
        connec->addr=clientaddr;                                        //client와의 connfd와 sockaddr를 connec 구조체에 전달
        pthread_create(&tid, NULL, thread, (void *)connec);             //thread 생성, connec를 thread에 인자로 전달
    }
    close(listenfd);                                                    //thread 생성 후 main thread에서 listenfd 종료
}

void *thread(void *vargp){
    Connec *connec = ((Connec *)vargp);
    int connfd = connec->connectfd;
    struct sockaddr_in sockaddr = connec->addr;
    pthread_detach(pthread_self());                                     //peer thread가 죽을 때 회수를 자동으로 해줌
    free(vargp);                                                        //동적 메모리는 peer thread에서 free
    signal(SIGPIPE, sigpipe_handler);                                   //연결이 되지 않은 상태에서 통신 시 sigpie_handler 동작
    proxy(connfd, &sockaddr);                                           //proxy 실행. 인자는 connfd랑 &sockaddr, sockaddr 는 로그파일 작성시 사용됨. 로그 파일 작성 전후로 pthread_mutex_lock, unlock 실행                                          
    close(connfd);                                                      //peer thread에서 connfd close
    return NULL;
}

void proxy(int connfd, struct sockaddr_in *sockaddr){

    //서버에 write 할 user 정보
    char *user_headers = "User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:88.0) Gecko/20100101 Firefox/88.0\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nAccept-Encoding: gzip, deflate\r\nConnection: close\r\nProxy-Connection: close\r\n\r\n";
    size_t len; 
    size_t sum = 0;
    rio_t rio, rio_client;

    int clientfd;
    int portnum;
    char host[MAXLINE], uri[MAXLINE], buf1[MAXLINE], buf2[MAXLINE], payload[MAXLINE];
    char method[MAXLINE], version[MAXLINE], path[MAXLINE];
    char log[MAXLINE];
                                                                        
    rio_readinitb(&rio, connfd);                                        //rio 구조체에 fd 정보를 저장
    rio_readlineb(&rio, buf1, MAXLINE);                                 //fd를 읽어 버퍼에 저장
    printf("Request Headers:\n");
    printf("%s\n", buf1);                                               //요청한 헤더 정보를 출력

    if (strcmp(buf1, "") == 0)                                          //버퍼에 내용이 들어있는지 확인
        return; 
    
    sscanf(buf1,"%s %s %s", method, uri, version);                      //HTTP request line을 method, uri, version으로 구분
    read_request_headers(&rio);                                         //함수 정의 부분에 설명 첨부

    parse_uri(uri, host, path, &portnum);                               //uri로부터 uri, host, path, portnum을 parsing

    printf("----------* Information *-----------\n");
    printf("uri = \"%s\"\n", uri);
    printf("host = \"%s\", ", host);
    printf("port = \"%d\", ", portnum);                                 //Default port number : 80
    printf("path = \"%s\"\n", path);
    printf("---------* Information end *---------\n");
                                                                        
    clientfd = open_clientfd(host, portnum);                            //proxy가 web server에 host와 port number를 이용하여 연결을 요청
    rio_readinitb(&rio_client, clientfd);                               //rio_client 구조체에 clientfd 정보 저장
 
    sprintf(buf2, "GET %s HTTP/1.0\r\n", path);                         //buf2에 path, version, method 정보 저장
    rio_writen(clientfd, buf2, strlen(buf2));                           //clientfd에 연결된 파일에 buf2의 데이터를 입력
    sprintf(buf2, "Host: %s\r\n", host);                                //buf2에 host 정보 저장
    rio_writen(clientfd, buf2, strlen(buf2));                           //clientfd에 연결된 파일에 buf2의 데이터를 입력
    rio_writen(clientfd, user_headers, strlen(user_headers));           //clientfd에 연결된 파일에 헤더의 HTTP 정보 입력

    strcpy(payload, "");                                                //payload 초기화
    while ((len = rio_readlineb(&rio_client, buf2, MAXLINE)) != 0) {    //clientfd를 읽어 buf2에 저장
        sum += len;
        if (sum <= MAXLINE)             
            strcat(payload, buf2);                                      //payload에 buf2를 복사
	    rio_writen(connfd, buf2, len);                                  //client와의 connfd에 연결된 파일에 buf2 데이터를 입력
	}

    format_log_entry(log, sockaddr, uri, sum);                          //log 저장 함수

    pthread_mutex_lock(&mutex_lock);                                    //다른 thread의 접근 제한

    fprintf(log_file, "%s %lu\n", log, sum);                            //log 파일에 로그 기록과 받은 파일의 크기 작성
    fflush(log_file);                                                   //log 파일의 출력 버퍼 비우기

    pthread_mutex_unlock(&mutex_lock);                                  //thread 접근 제한 해제

    close(clientfd);                                                    //메모리 누수 방지
}                                                                       

/*
 * read_request_headers - Read the header and ignore the connection request.
 *  
 * 'buf' 안의 문자열을 읽어들어 "\r\n" 기준으로 분할
 * 표준 HTTP는 각각의 text line을 carriage return과 line feed("\r\n")로 끝내야한다.
 */
void read_request_headers(rio_t *rp)
{
    char buf[MAXLINE];

    rio_readlineb(rp, buf, MAXLINE);                                    //버퍼에 헤더를 저장
    while (strcmp(buf, "\r\n"))                                         //"\r\n"을 기준으로 분할하여 출력
    {
        rio_readlineb(rp, buf, MAXLINE);
        printf("%s", buf);
    }
    return;
}

/*
 * parse_uri - URI parser
 * 
 * Given a URI from an HTTP proxy GET request (i.e., a URL), extract
 * the host name, path name, and port.  The memory for hostname and
 * pathname must already be allocated and should be at least MAXLINE
 * bytes. Return -1 if there are any problems.
 */
int parse_uri(char *uri, char *hostname, char *pathname, int *port)
{
    char *hostbegin;
    char *hostend;
    char *pathbegin;
    int len;

    if (strncasecmp(uri, "http://", 7) != 0) {
	hostname[0] = '\0';
	return -1;
    }
       
    /* Extract the host name */
    hostbegin = uri + 7;
    hostend = strpbrk(hostbegin, " :/\r\n\0");
    len = hostend - hostbegin;
    strncpy(hostname, hostbegin, len);
    hostname[len] = '\0';
    
    /* Extract the port number */
    *port = 80; /* default */
    if (*hostend == ':')   
	*port = atoi(hostend + 1);
    
    /* Extract the path */
    pathbegin = strchr(hostbegin, '/');
    if (pathbegin == NULL) {
	pathname[0] = '\0';
    }
    else {	
	strcpy(pathname, pathbegin);
    }

    return 0;
}

/*
 * format_log_entry - Create a formatted log entry in logstring. 
 * 
 * The inputs are the socket address of the requesting client
 * (sockaddr), the URI from the request (uri), and the size in bytes
 * of the response from the server (size).
 */
void format_log_entry(char *logstring, struct sockaddr_in *sockaddr, 
		      char *uri, int size)
{
    time_t now;
    char time_str[MAXLINE];
    unsigned long host;
    unsigned char a, b, c, d;

    /* Get a formatted time string */
    now = time(NULL);
    strftime(time_str, MAXLINE, "%a %d %b %Y %H:%M:%S %Z", localtime(&now));

    /* 
     * Convert the IP address in network byte order to dotted decimal
     * form. Note that we could have used inet_ntoa, but chose not to
     * because inet_ntoa is a Class 3 thread unsafe function that
     * returns a pointer to a static variable (Ch 13, CS:APP).
     */
    host = ntohl(sockaddr->sin_addr.s_addr);
    a = host >> 24;
    b = (host >> 16) & 0xff;
    c = (host >> 8) & 0xff;
    d = host & 0xff;


    /* Return the formatted log entry string */
    sprintf(logstring, "%s: %d.%d.%d.%d %s", time_str, a, b, c, d, uri);
}



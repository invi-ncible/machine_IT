#include "csapp.h"

pthread_mutex_t mutex_lock;

typedef struct _Connec{
    int connectfd;
    struct sockaddr_in addr;
}Connec;

void *thread(void *vargp){
    Connec *connec = ((Connec *)vargp);
    int connfd = connec->connectfd;
    struct sockaddr_in sockaddr = connec->addr;
    Pthread_detach(pthread_self());
    Free(vargp);
    // proxy 실행
    // 인자는 connfd랑 &sockaddr, sockaddr 는 로그파일 작성시 사용됨
    // 로그 파일 작성 전후로 pthread_mutex_lock, unlock 실행
    Close(connfd);
    return NULL;
}

int main(int argc, char **argv){
    if (argc != 2) {
	fprintf(stderr, "Usage: %s <port number>\n", argv[0]);
	exit(0);
    }

    int listenfd;
    Connec *connec;
    socklen_t clientlen;
    struct sockaddr_in clientaddr;
    pthread_t tid;

    pthread_mutex_init(&mutex_lock, NULL); // mutex 초기화
    
    int portnum = atoi(argv[1]); 
    listenfd = Open_listenfd(portnum);
    while(1){
        clientlen = sizeof(struct sockaddr_in);
        connec = Malloc(sizeof(Connect));
        connec->connectfd= Accept(listenfd, (SA *)&clientaddr, &clientlen);        
        connec->addr=clientaddr;
        Pthread_create(&tid, NULL, thread, (void *)connec);
    }
    close(listenfd);
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
	pathbegin++;	
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


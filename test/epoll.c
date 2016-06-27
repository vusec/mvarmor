#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <arpa/inet.h>

pid_t cfork(void)
{
    pid_t pid = fork();
    if (pid < 0)
    {
        perror("cfork");
        exit(1);
    }
    return pid;
}

void run_server(void)
{
    struct epoll_event ev, events[10];
    int listen_sock, conn_sock, nfds, epollfd;
    int n;
    socklen_t addrlen;
    struct sockaddr_in addr;

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(1234);
    listen_sock = socket(AF_INET, SOCK_STREAM, 0);
    n = 1;
    setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, &n, sizeof(n));
    if (bind(listen_sock, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    {
        perror("bind");
        exit(1);
    }
    listen(listen_sock, 10);

    epollfd = epoll_create(10);
    if (epollfd == -1)
    {
        perror("epoll_create");
        exit(1);
    }

    ev.events = EPOLLIN;
    ev.data.fd = listen_sock;
    if (epoll_ctl(epollfd, EPOLL_CTL_ADD, listen_sock, &ev) == -1)
    {
        perror("epoll_ctl: listen_sock:");
        exit(1);
    }
    printf("Registered fd %d as listen_sock\n", listen_sock);

    while (1)
    {
        nfds = epoll_wait(epollfd, events, 10, -1);
        if (nfds == -1)
        {
            perror("epoll_wait");
            exit(1);
        }
        for (n = 0; n < nfds; n++)
        {
            int fd = events[n].data.fd;
            printf("Got fd %d\n", fd);
            if (fd == listen_sock)
            {
                addrlen = sizeof(struct sockaddr_in);
                conn_sock = accept(listen_sock, (struct sockaddr *)&addr, &addrlen);
                if (conn_sock == -1)
                {
                    perror("accept");
                    exit(1);
                }
                ev.events = EPOLLIN;
                ev.data.fd = conn_sock;
                if (epoll_ctl(epollfd, EPOLL_CTL_ADD, conn_sock, &ev) == -1)
                {
                    perror("epoll_ctl: conn_sock");
                    exit(1);
                }
                printf("Registered fd %d as conn_sock\n", conn_sock);
            }
            else
            {
                char *resp = "HTTP/1.1 200 OK\r\nServer: test\r\nConnection: close\r\n\r\nHoi!\r\n\r\n";
                char buf[128];
                recvfrom(fd, buf, 128, 0, NULL, NULL);
                buf[127] = '\0';
                printf("R: %s\n", buf);
                write(fd, resp, strlen(resp));
                close(fd);
            }
        }
    }
}

int main(void)
{
    run_server();

    return 0;
}

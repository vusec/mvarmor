#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>



int main(void)
{
    int fd, n, err, i;
    char buffer[548];
    struct sockaddr_storage src_addr;
    struct iovec iov[1];
    struct msghdr message;
    char control[72];
    const char *hostname = 0; /* wildcard */
    const char *portname = "1234";
    struct addrinfo hints;
    struct addrinfo *res = 0;

    iov[0].iov_base = buffer;
    iov[0].iov_len = sizeof(buffer);

    message.msg_name = &src_addr;
    message.msg_namelen = sizeof(src_addr);
    message.msg_iov = iov;
    message.msg_iovlen = 1;
    message.msg_control = control;
    message.msg_controllen = sizeof(control);

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = 0;
    hints.ai_flags = AI_PASSIVE|AI_ADDRCONFIG;
    err = getaddrinfo(hostname, portname, &hints, &res);
    if (err != 0)
    {
        perror("Could not resolve addr");
        exit(1);
    }
    fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);

    n = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &n, sizeof(n));


    if (bind(fd, res->ai_addr, res->ai_addrlen) < 0)
    {
        perror("bind");
        exit(1);
    }

    ssize_t recv_count;
    recv_count = recvmsg(fd, &message, 0);
    if (recv_count < 0)
        perror("recving failed");
    printf("got msg: %zd  flags %d\n", recv_count, message.msg_flags);
    printf("control: %zu\n", message.msg_controllen);
    /*printf("name: %u, %p\n", message.msg_namelen, &src_addr);*/
    /*printf("buffer: %s\n", buffer);*/

    for (i = 0; i < message.msg_namelen; i++)
        printf("%x ", ((char *)message.msg_name)[i]);
    printf("\n");
    for (i = 0; i < message.msg_iovlen; i++)
        printf("{%zu, %s}, ", iov[i].iov_len, (char*)iov[i].iov_base);
    close(fd);

    return 0;
}

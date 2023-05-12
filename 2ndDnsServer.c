#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>     

#define BUF_SIZE 4096
#define MAX_NAME_LEN 256
struct DNS_Header{
	unsigned short id: 16;
	unsigned short tag: 16;
	unsigned short queryNum: 16;
	unsigned short answerNum: 16;
	unsigned short authorNum: 16;
	unsigned short addNum: 16;
};

struct DNS_Query{
	unsigned short qtype: 16;
	unsigned short qclass: 16;
};


struct TCP_Query{
	int tcp_qtype: 16;
	char *tcp_url;
};

int my_receive(){
	int socket_tcp;
	char buffer_receive[BUF_SIZE];
	memset(buffer_receive, 0, sizeof(buffer_receive));
	char* buffer_send;
	memset(buffer_send, 0, sizeof(*buffer_send));
	
	if((socket_tcp = socket(AF_INET, SOCK_STREAM, 0)) == -1){
		perror("socket() failed\n");
		exit(EXIT_FAILURE);
	}

	struct hostent *server;
	struct sockaddr_in serv_addr;
	memset(&serv_addr, 0, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = htons(53);
	serv_addr.sin_addr.s_addr = inet_addr("127.2.2.1"); 
	if (bind(socket_tcp, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) {
		perror("ERROR on binding");
	}
	listen(socket_tcp, 5);
	struct sockaddr_in cli_addr;
	socklen_t clilen = sizeof(cli_addr);
	while (1) {
		int newsockfd = accept(socket_tcp, (struct sockaddr *) &cli_addr, &clilen);
		if (newsockfd < 0) {
		    perror("ERROR on accept");
		}
		
		memset(buffer_receive, 0, sizeof(serv_addr));
		int n = read(newsockfd, buffer_receive, BUF_SIZE);
		buffer_receive[n] = '\0'; // C语言中，字符串是以空字符结尾的字符序列
					  //
		struct TCP_Query *tcpheader = (struct TCP_Query *)buffer_receive;
		printf("%d\n",ntohs(tcpheader->tcp_qtype));

		int qtype=ntohs(tcpheader->tcp_qtype);
		char *name_start = buffer_receive+2;
		char *name_end;
		name_end = strchr(&buffer_receive[2], '\0');
		int name_len = name_end - name_start;
		printf("Name_len: %d\n", name_len);
		char* name_str[name_len];
		for (int i=0; i<name_len; i++) {
			name_str[i] = name_start+i;
		}
		printf("url: %s\n", *name_str);
		if (n < 0) {
		    perror("ERROR reading from socket");
		}
		
		printf("Message received: %s\n", buffer_send);

		n = write(newsockfd, "I got your message", 18);
		if (n < 0) {
		    perror("ERROR writing to socket");
		}

		close(newsockfd);
	}

	close(socket_tcp);
	return 0;
}

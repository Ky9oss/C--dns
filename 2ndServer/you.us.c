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
#include "../packet_head.h"


char buffer_receive[BUF_SIZE];

int main() {
    int listening_socket, client_socket;
    struct sockaddr_in server_address, client_address;
    char buffer[1024] = {0};
    int opt = 1;
    int addrlen = sizeof(server_address);

    // 创建TCP套接字
    if ((listening_socket = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    // 设置套接字选项，允许重用地址
    if (setsockopt(listening_socket, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt))) {
        perror("Setsockopt failed");
        exit(EXIT_FAILURE);
    }

    // 配置服务器地址
    server_address.sin_family = AF_INET;
    server_address.sin_addr.s_addr = inet_addr("127.4.4.4");
    server_address.sin_port = htons(53);

    // 绑定套接字到指定的地址和端口
    if (bind(listening_socket, (struct sockaddr *)&server_address, sizeof(server_address)) < 0) {
        perror("Bind failed");
        exit(EXIT_FAILURE);
    }

    // 开始监听连接请求
    if (listen(listening_socket, 5) < 0) {
        perror("Listen failed");
        exit(EXIT_FAILURE);
    }

    printf("Listening on port %d...\n", 53);

    while (1) {
        // 接受新的客户端连接请求
        if ((client_socket = accept(listening_socket, (struct sockaddr *)&client_address, (socklen_t*)&addrlen)) < 0) {
            perror("Accept failed");
            exit(EXIT_FAILURE);
        }

        printf("New client connected.\n");

        // 读取客户端发送的数据
        int bytes_received = recv(client_socket, buffer_receive, sizeof(buffer_receive), 0);
	printf("\n\n\n\nReceived from %s:%d\n", inet_ntoa(client_address.sin_addr), ntohs(client_address.sin_port)); //inet_ntoa：地址转成xxx.xxx.xxx.xxx格式 //ntohs：转小端序
        printf("Received %d bytes: %s\n", bytes_received, buffer);
	struct DNS_Header *dnsheader = (struct DNS_Header *)&buffer_receive[2];
	unsigned short id = ntohs(dnsheader->id);
	printf("Transacation ID: %x\n", id);
	unsigned short tag = ntohs(dnsheader->tag);
	printf("Flags: %x\n", tag);
	unsigned short queryNum = ntohs(dnsheader->queryNum);
	printf("Questions: %x\n", queryNum);
	unsigned short answerNum = ntohs(dnsheader->answerNum);
	printf("Answer RRs: %x\n", answerNum);
	unsigned short authorNum = ntohs(dnsheader->authorNum);
	printf("Authority RRs: %x\n", authorNum);
	unsigned short addNum = ntohs(dnsheader->addNum);
	printf("Additional RRs: %x\n", addNum);
	
	char *name_start = buffer_receive+14;
	char *name_end;
	name_end = strchr(&buffer_receive[14], '\0');
	int name_len = name_end - name_start;
	printf("Name_len: %d\n", name_len);
	char* name_str[name_len+1];
	for (int i=0; i<name_len; i++) {
		name_str[i] = name_start+i;
	}
	printf("Name: %s\n", *name_str);

	struct DNS_Query *dnsquery = (struct DNS_Query *)(buffer_receive+14+name_len);
	unsigned short qtype = ntohs(dnsquery->qtype);
	printf("Type: %x\n", qtype);
	unsigned short qclass = ntohs(dnsquery->qclass);
	printf("Class: %x\n", qclass);




	//----------------数据库

	
	char address_answers[] = "127.4.4.1";
	unsigned short length = sizeof(address_answers);

	char buffer_send[sizeof(address_answers)+2];
	memset(buffer_send, 0, sizeof(*buffer_send));
	memcpy(buffer_send, &length, 2);
	memcpy(&buffer_send[2], &address_answers, sizeof(address_answers)); // 拷贝头部
        send(client_socket, buffer_send, sizeof(buffer_send), 0);

        // 关闭连接
        close(client_socket);
        printf("Client disconnected.\n");
    }

    return 0;
}

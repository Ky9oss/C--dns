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
    server_address.sin_addr.s_addr = inet_addr("127.3.3.1");
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
	// 接受新的客户端连接请求
	if ((client_socket = accept(listening_socket, (struct sockaddr *)&client_address, (socklen_t*)&addrlen)) < 0) {
	    perror("Accept failed");
	    exit(EXIT_FAILURE);
	}

    while (1) {


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
	int name_len = name_end - name_start+1;
	printf("Name_len: %d\n", name_len);
	char* name_str[name_len];
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

		
	
	//构造头部--dns header
	printf("Create DNS Header...\n");
	struct DNS_Header dns_header;
	memset(&dns_header, 0, sizeof(dns_header));
	//------------下面的数据待更改
	dns_header.id = htons(0x0001); // 设置标识符
	dns_header.tag = htons(0x8180); // 设置标志位，表示这是一个标准查询
	dns_header.queryNum = htons(1); // 问题数为1
	dns_header.answerNum = htons(1);
	dns_header.addNum = htons(0);
	dns_header.authorNum = htons(0);
	int A_data_length = 12; //-------注意A_data_length，用来计算包的长度


	//构造Queries--name
	char* url = *name_str;
	url[name_len] = '\0';
	A_data_length += name_len;

	//构造头部--dns query
	//printf("Create DNS query...\n");
	struct DNS_Query dns_query;
	dns_query.qtype = htons(qtype);
	dns_query.qclass = htons(0x0001);
	A_data_length += 4;

	//Answers--构造name
	unsigned short name_answers = htons(0xc00c);
	A_data_length += 2;

	  
	//Answers--构造address
	char ip_str[] = "127.4.4.1";//-------------------------------------------------------------
	struct in_addr addr;
	uint32_t ip_int;
	if (inet_aton(ip_str, &addr) == 0) {
	perror("inet_aton");
	exit(EXIT_FAILURE);
	}
	ip_int = ntohl(addr.s_addr);
	uint32_t address_answers = htonl(ip_int);
	int address_answers_len = 4;
	A_data_length += address_answers_len;

	//Answers身体
	struct DNS_RR dns_rr_answers1;
	memset(&dns_rr_answers1, 0, sizeof(dns_rr_answers1));
	dns_rr_answers1.type = htons(0x0001); // 设置标识符
	dns_rr_answers1._class = htons(0x0001); // 设置标识符
	dns_rr_answers1.ttl = htonl(0x00000064); // 设置标识符
	//注意data length，是后面的address数据的length
	dns_rr_answers1.data_len = htons(0x0004); // 设置标识符

	A_data_length += 10;

	unsigned short packet_length = htons(A_data_length);

	A_data_length += 2;


	char buffer_send[A_data_length];


	//开始将数据存入buffer
	//memcpy参数：参数1为你要拷贝到的缓冲区地址，参数2为你要拷贝数据的地址，参数3为数据的长度
	memset(buffer_send, 0, sizeof(*buffer_send));

	memcpy(&buffer_send, &packet_length, 2); // 拷贝头部
	int position = 2;

	memcpy(&buffer_send[position], &dns_header, 12); // 拷贝头部
	position += 12;

	memcpy(&buffer_send[position], url, name_len);
	position += name_len;

	memcpy(&buffer_send[position], &dns_query, 4);
	position += 4;

	memcpy(&buffer_send[position], &name_answers, 2); // 拷贝头部
	position += 2;

	memcpy(&buffer_send[position], &dns_rr_answers1, 10); // 拷贝头部
	position += 10;

	memcpy(&buffer_send[position], &address_answers, address_answers_len); // 拷贝头部
	position += address_answers_len;

        send(client_socket, buffer_send, sizeof(buffer_send), 0);

    }

    return 0;
}

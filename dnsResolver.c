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
#include "packet_head.h"



char buffer_receive[BUF_SIZE];
int my_send_and_receive(char url[MAX_NAME_LEN], int c_qtype);
void convert_to_big_endian(char* data, size_t size);
int count = 0;
int socket_udp;
struct sockaddr_in recv_addr;
struct sockaddr_in send_addr;
socklen_t addrlen = sizeof(recv_addr);




int main(int argc, char *argv[]){

	printf("------------------------------------------\n");
	printf("------------------------------------------\n");
	printf("||    Welcome to HKX&CZN dns client !   ||\n");
	printf("------------------------------------------\n");
	printf("------------------------------------------\n\n\n\n");


	while(1){

	printf("Input the query type (A, MX, PTR, CNAME): \n");
	char input1[MAX_NAME_LEN];
	fgets(input1, MAX_NAME_LEN, stdin);
	if (strcmp(input1, "PTR\n") == 0) {
		printf("GET PTR!\n");
		int c_qtype=0x000c;

		printf("Input the IP address: \n");
		char url[MAX_NAME_LEN];
		fgets(url, MAX_NAME_LEN, stdin);
		//去除换行符号
		url[strcspn(url, "\n")] = '\0';
		my_send_and_receive(url, c_qtype);



	} else if (strcmp(input1, "A\n") == 0) {
		printf("GET A!\n");
		int c_qtype=0x0001;

		printf("Input the url: \n");
		char url[MAX_NAME_LEN];
		fgets(url, MAX_NAME_LEN, stdin);

		url[strcspn(url, "\n")] = '\0';
		my_send_and_receive(url, c_qtype);

	} else if (strcmp(input1, "CNAME\n") == 0) {
		printf("GET CNMAE!\n");
		int c_qtype=0x0005;

		printf("Input the url: \n");
		char url[MAX_NAME_LEN];
		fgets(url, MAX_NAME_LEN, stdin);

		url[strcspn(url, "\n")] = '\0';
		my_send_and_receive(url, c_qtype);

	} else if (strcmp(input1, "MX\n") == 0) {
		printf("GET MX!\n");
		int c_qtype=0x000f;

		printf("Input the url: \n");
		char url[MAX_NAME_LEN];
		fgets(url, MAX_NAME_LEN, stdin);

		url[strcspn(url, "\n")] = '\0';
		my_send_and_receive(url, c_qtype);

	} else {
		printf("WRONG INPUT! You must input A or MX or PTR or CNMAE\n");
		exit(1);
	    // 输入不是有效的记录类型
	}

	}

}

int my_send_and_receive(char url[MAX_NAME_LEN], int c_qtype){
	 
	//构造udp socket
	if(count==0){
		socket_udp = socket(AF_INET, SOCK_DGRAM, 0);
		memset(&recv_addr, 0, sizeof(recv_addr));//初始化结构体中的数据
		recv_addr.sin_family = AF_INET; 
		recv_addr.sin_port = htons(12345); //htons 转换为网络字节序（大端序）
		recv_addr.sin_addr.s_addr = inet_addr("127.0.0.1"); 

		if (bind(socket_udp, (struct sockaddr*)&recv_addr, sizeof(recv_addr)) == -1) {
			perror("bind() failed\n");
			exit(EXIT_FAILURE);
		}


		printf("Create (sockaddr_in)send_addr...\n");
		memset(&send_addr, 0, sizeof(send_addr));//初始化结构体中的数据
		send_addr.sin_family = AF_INET; 
		send_addr.sin_port = htons(53); 
		send_addr.sin_addr.s_addr = inet_addr("127.1.1.1"); 
		count++;
	}
	 
	//构造name
	int url_len = strlen(url);
	char domain_name[url_len+2];
	int e = 0;
	for (int i = 0; i < url_len+1; i++) {
	    if (url[i] == '.') {
		domain_name[i-e] = '\x0'+e;
		e=0;
	    } else {
		domain_name[i+1] = url[i];
		e++;
	    }
	}
	domain_name[url_len-e+1] = '\x0'+(e-1);
	domain_name[url_len+1] = '\x00';
	int name_len = strlen(domain_name)+1;

	int dns_length = 16+name_len;
	char buffer_send[dns_length];


	//构造头部--dns header
	printf("Create DNS Header...\n");
	struct DNS_Header dns_header;
	memset(&dns_header, 0, sizeof(dns_header));
	dns_header.id = htons(0x0001); // 设置标识符
	dns_header.tag = htons(0x0100); // 设置标志位，表示这是一个标准查询
	dns_header.queryNum = htons(1); // 问题数为1
	dns_header.addNum = htons(0);
	dns_header.answerNum = htons(0);
	dns_header.authorNum = htons(0);
	memset(buffer_send, 0, sizeof(*buffer_send));
	memcpy(buffer_send, &dns_header, sizeof(dns_header)); // 拷贝头部
	int position = sizeof(dns_header);


	//构造头部--dns query
	printf("Create DNS query...\n");
	struct DNS_Query dns_query;


	dns_query.qtype = htons(c_qtype);
	dns_query.qclass = htons(0x0001);
	if (name_len >= MAX_NAME_LEN) {
		return -1;
	}
	size_t query_len = position + name_len + 2 + 2;
	if (query_len > BUF_SIZE) {
		return -1;
	}

	//开始将数据存入buffer
	//memcpy参数：参数1为你要拷贝到的缓冲区地址，参数2为你要拷贝数据的地址，参数3为数据的长度
	memcpy(&buffer_send[position], domain_name, name_len);
	position += name_len;

	unsigned short qtype = dns_query.qtype;
	memcpy(&buffer_send[position], &qtype, 2); // 拷贝头部
	position += 2;

	unsigned short qclass = dns_query.qclass;
	memcpy(&buffer_send[position], &qclass, 2); // 拷贝头部
	position += 2;


	printf("Start Send...\n");
	sendto(socket_udp, buffer_send, sizeof(buffer_send), 0, (struct sockaddr*)&send_addr, sizeof(send_addr));




	//接收数据！
	printf("------------------------------\n");
	printf("Receiving from Local DNS Server...\n");
	printf("------------------------------\n\n");

	memset(buffer_receive, 0, sizeof(buffer_receive));
	int received_bytes = recvfrom(socket_udp, buffer_receive, BUF_SIZE, 0, (struct sockaddr*)&recv_addr, &addrlen);
	buffer_receive[received_bytes] = '\0'; // C语言中，字符串是以空字符结尾的字符序列

	printf("[^_^] Received from Local DNS Server\n"); //inet_ntoa：地址转成xxx.xxx.xxx.xxx格式 //ntohs：转小端序

	return 1;

}


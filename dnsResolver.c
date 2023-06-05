#include <stddef.h>
#include <time.h>
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
clock_t start_time, end_time;
double cpu_time_used;




int main(int argc, char *argv[]){

	printf("------------------------------------------\n");
	printf("------------------------------------------\n");
	printf("||    Welcome to HKX&CZN dns client !   ||\n");
	printf("------------------------------------------\n");
	printf("------------------------------------------\n");


	while(1){

	printf("\n\n\nInput the query type (A, MX, PTR, CNAME): \n");
	char input1[MAX_NAME_LEN];
	fgets(input1, MAX_NAME_LEN, stdin);
	if (strcmp(input1, "PTR\n") == 0) {
		int c_qtype=0x000c;

		printf("Input the IP address: \n");
		char url[MAX_NAME_LEN];
		fgets(url, MAX_NAME_LEN, stdin);
		//去除换行符号
		url[strcspn(url, "\n")] = '\0';
		my_send_and_receive(url, c_qtype);



	} else if (strcmp(input1, "A\n") == 0) {
		int c_qtype=0x0001;

		printf("Input the url: \n");
		char url[MAX_NAME_LEN];
		fgets(url, MAX_NAME_LEN, stdin);

		url[strcspn(url, "\n")] = '\0';
		my_send_and_receive(url, c_qtype);

	} else if (strcmp(input1, "CNAME\n") == 0) {
		int c_qtype=0x0005;

		printf("Input the url: \n");
		char url[MAX_NAME_LEN];
		fgets(url, MAX_NAME_LEN, stdin);

		url[strcspn(url, "\n")] = '\0';
		my_send_and_receive(url, c_qtype);

	} else if (strcmp(input1, "MX\n") == 0) {
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

	// 记录开始时间
	start_time = clock();
	 
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


	sendto(socket_udp, buffer_send, sizeof(buffer_send), 0, (struct sockaddr*)&send_addr, sizeof(send_addr));





	//接收数据！
	printf("\n\n------------------------------\n");
	printf("Receiving from Local DNS Server...\n");
	printf("------------------------------\n");

	memset(buffer_receive, 0, sizeof(buffer_receive));
	int received_bytes = recvfrom(socket_udp, buffer_receive, BUF_SIZE, 0, (struct sockaddr*)&recv_addr, &addrlen);
	// 记录结束时间
	end_time = clock();

	// 计算执行时间
	cpu_time_used = ((double) (end_time - start_time)) / CLOCKS_PER_SEC;

	// 输出执行时间
	//printf("Took %f seconds to receive from local dns server.\n", cpu_time_used);
	buffer_receive[received_bytes] = '\0'; // C语言中，字符串是以空字符结尾的字符序列
	struct DNS_Header *dnsheader2 = (struct DNS_Header *)&buffer_receive;
	unsigned short id2 = ntohs(dnsheader2->id);
	printf("Transacation ID: %04x\n", id2);
	unsigned short tag2 = ntohs(dnsheader2->tag);
	printf("Flags: %04x\n", tag2);
	unsigned short queryNum2 = ntohs(dnsheader2->queryNum);
	printf("Questions: %04x\n", queryNum2);
	unsigned short answerNum2 = ntohs(dnsheader2->answerNum);
	printf("Answer RRs: %04x\n", answerNum2);
	unsigned short authorNum2 = ntohs(dnsheader2->authorNum);
	printf("Authority RRs: %04x\n", authorNum2);
	unsigned short addNum2 = ntohs(dnsheader2->addNum);
	printf("Additional RRs: %04x\n", addNum2);
	

	char *name_start2 = buffer_receive + 12;
	char *name_end2 = strchr(&buffer_receive[12], '\0');
	size_t name_len2 = name_end2 - name_start2+1;
	printf("Name_len: %zu\n", name_len2);
	char* name_str2 = malloc(name_len2);
	if (name_str2 == NULL) {
	    fprintf(stderr, "Failed to allocate memory for name_str.\n");
	    exit(EXIT_FAILURE);
	}
	memcpy(name_str2, name_start2, name_len2);
	name_str2[name_len2] = '\0';
	printf("Name: %s\n", name_str2);

	struct DNS_Query *dnsquery2 = (struct DNS_Query *)(buffer_receive+12+name_len2);
	unsigned short qtype2 = ntohs(dnsquery2->qtype);
	printf("Type: %04x\n", qtype2);
	unsigned short qclass2 = ntohs(dnsquery2->qclass);
	printf("Class: %04x\n", qclass2);
	

	int position2 = 18+name_len2;
	//假装两字节
	//position2 += 2;

	struct in_addr addr;
	struct DNS_RR *dns_rr2 = (struct DNS_RR *)(buffer_receive+position2);
	unsigned short type2 = ntohs(dns_rr2->type);
	printf("Answer Type: %04x\n", type2);
	unsigned short class2 = ntohs(dns_rr2->_class);
	printf("Answer Class: %04x\n", class2);
	uint32_t ttl2 = ntohl(dns_rr2->ttl);
	printf("TTL: %08x\n", ttl2);
	unsigned short data_len2 = ntohs(dns_rr2->data_len);
	printf("Data Len: %04x\n", data_len2);

	position2 -= 2;

	if(type2==0x0001){
		struct DNS_RR *dns_rr22 = (struct DNS_RR *)(buffer_receive+position2);
		uint32_t answer = ntohl(dns_rr22->address);
		printf("Answer in hex: %08x\n", answer);
		addr.s_addr = htonl(answer);
		char* str_ip = inet_ntoa(addr);
		printf("Answer: %s\n", str_ip);
	}




	printf("[^_^] Received from Local DNS Server\n\n\n"); //inet_ntoa：地址转成xxx.xxx.xxx.xxx格式 //ntohs：转小端序

	return 1;

}


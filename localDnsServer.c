#include <stdio.h>
#include <ctype.h>
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
char buffer_receive1[BUF_SIZE];
char buffer_receive2[BUF_SIZE];
char buffer_receive3[BUF_SIZE];
char buffer_tcp_receive[BUF_SIZE];
int my_receiveUDP();




int main(int argc, char *argv[]){

	//在这里检查cache，如果cache文件里有，则直接返回
	//否则，执行下面的函数
	my_receiveUDP();

}


int my_receiveUDP(){

	int socket_udp;

	if((socket_udp = socket(AF_INET, SOCK_DGRAM, 0)) == -1){
		perror("socket() failed\n");
		exit(EXIT_FAILURE);
	};

	struct sockaddr_in *recv_addr = malloc(sizeof(struct sockaddr_in));
	memset(recv_addr, 0, sizeof(*recv_addr));//初始化结构体中的数据
	recv_addr->sin_family = AF_INET; 
	recv_addr->sin_port = htons(53); //htons 转换为网络字节序（大端序）
	recv_addr->sin_addr.s_addr = inet_addr("127.1.1.1"); 
	socklen_t addrlen = sizeof(*recv_addr);

	if (bind(socket_udp, (struct sockaddr*)recv_addr, sizeof(*recv_addr)) == -1) {
		perror("bind() failed\n");
		exit(EXIT_FAILURE);
	};
	printf("Create (sockaddr_in)send_addr...\n");
	struct sockaddr_in send_addr;
	memset(&send_addr, 0, sizeof(send_addr));//初始化结构体中的数据
	send_addr.sin_family = AF_INET; 
	send_addr.sin_port = htons(12345); 
	send_addr.sin_addr.s_addr = inet_addr("127.0.0.1"); 

	while (1) {
	
	//接收数据！
	printf("------------------------------\n");
	printf("Receiving from DNS Clinet...\n");
	printf("------------------------------\n\n");
	int received_bytes = recvfrom(socket_udp, buffer_receive, BUF_SIZE, 0, (struct sockaddr*)recv_addr, &addrlen);
	buffer_receive[received_bytes] = '\0'; // C语言中，字符串是以空字符结尾的字符序列

	printf("received from %s:%d\n", inet_ntoa(recv_addr->sin_addr), ntohs(recv_addr->sin_port)); //inet_ntoa：地址转成xxx.xxx.xxx.xxx格式 //ntohs：转小端序

	struct DNS_Header *dnsheader = (struct DNS_Header *)buffer_receive;
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
	
	char *name_start = buffer_receive+12;
	char *name_end;
	name_end = strchr(&buffer_receive[12], '\0');
	int name_len = name_end - name_start+1;
	printf("Name_len: %x\n", name_len);
	char* name_str[name_len+1];
	for (int i=0; i<name_len; i++) {
		name_str[i] = name_start+i;
	}
	printf("Name: %s\n", *name_str);

	struct DNS_Query *dnsquery = (struct DNS_Query *)(buffer_receive+12+name_len);
	unsigned short qtype = ntohs(dnsquery->qtype);
	printf("Type: %x\n", qtype);
	unsigned short qclass = ntohs(dnsquery->qclass);
	printf("Class: %x\n", qclass);

	


	printf("------------------------------\n");
	printf("Send to Root DNS Server...\n");
	printf("------------------------------\n\n");


	//构造16进制包长
	unsigned short value = 18+name_len;  // 填充一个整型数字

	
	//构造name
	int dns_length = 2+16+name_len;
	char buffer_send[dns_length];


	//构造头部--dns header
	printf("Create DNS Header...\n");
	struct DNS_Header dns_header;
	memset(buffer_send, 0, sizeof(*buffer_send));
	dns_header.id = htons(id); // 设置标识符
	dns_header.tag = htons(tag); // 设置标志位，表示这是一个标准查询
	dns_header.queryNum = htons(queryNum); // 问题数为1
	dns_header.answerNum = htons(answerNum); dns_header.authorNum = htons(authorNum);
	dns_header.addNum = htons(addNum);


	//构造头部--dns query
	printf("Create DNS query...\n");
	struct DNS_Query dns_query;
	dns_query.qtype = htons(qtype);
	dns_query.qclass = htons(qclass);
	if (name_len >= MAX_NAME_LEN) {
		return -1;
	}
	size_t query_len = 12 + name_len + 2 + 2;
	if (query_len > BUF_SIZE) {
		return -1;
	}

	//开始将数据存入buffer
	//memcpy参数：参数1为你要拷贝到的缓冲区地址，参数2为你要拷贝数据的地址，参数3为数据的长度
	buffer_send[0] = (unsigned char)(value >> 8);   // 高位字节
	buffer_send[1] = (unsigned char)value;          // 低位字节
							//
	memcpy(&buffer_send[2], &dns_header, sizeof(dns_header)); // 拷贝头部
	int position = 2+sizeof(dns_header);

	memcpy(&buffer_send[position], name_str, name_len);
	position += name_len;

	memcpy(&buffer_send[position], &qtype, 2); // 拷贝头部
	position += 2;

	memcpy(&buffer_send[position], &qclass, 2); // 拷贝头部
	position += 2;


	//构造tcp socket
	int socket_tcp;
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
	if (connect(socket_tcp, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) {
		perror("ERROR connecting\n");
	}
	printf("Connected to server.\n");
	printf("Start Send to Root...\n");
	send(socket_tcp, buffer_send, sizeof(buffer_send), 0);


	// 读取服务器发送的响应
	int bytes_received = recv(socket_tcp, buffer_receive1, sizeof(buffer_receive1), 0);
	printf("Received %d bytes: %s\n", bytes_received, buffer_receive1);
	// 关闭连接
	close(socket_tcp);
	printf("Disconnected from server.\n");


	printf("\n\n\n\n------------------------------\n");
	printf("Send to tid DNS Server...\n");
	printf("------------------------------\n");

	//构造tcp socket
	int socket_tcp2;
	if((socket_tcp2 = socket(AF_INET, SOCK_STREAM, 0)) == -1){
		perror("socket() failed\n");
		exit(EXIT_FAILURE);
	}

	struct hostent *server2;
	struct sockaddr_in serv_addr2;
	memset(&serv_addr2, 0, sizeof(serv_addr2));
	serv_addr2.sin_family = AF_INET;
	serv_addr2.sin_port = htons(53);
	serv_addr2.sin_addr.s_addr = inet_addr("127.3.3.1"); 
	if (connect(socket_tcp2, (struct sockaddr *) &serv_addr2, sizeof(serv_addr2)) < 0) {
		perror("ERROR connecting\n");
	}
	printf("Connected to server.\n");
	send(socket_tcp2, buffer_send, sizeof(buffer_send), 0);

	// 读取服务器发送的响应
	int bytes_received2 = recv(socket_tcp2, buffer_receive2, sizeof(buffer_receive2), 0);
	printf("Received %d bytes: %s\n", bytes_received2, buffer_receive2);
	// 关闭连接
	close(socket_tcp2);
	printf("Disconnected from server.\n");




	printf("------------------------------\n");
	printf("Send to 2nd DNS Server...\n");
	printf("------------------------------\n\n");
	//构造tcp socket
	int socket_tcp3;
	if((socket_tcp3 = socket(AF_INET, SOCK_STREAM, 0)) == -1){
		perror("socket() failed\n");
		exit(EXIT_FAILURE);
	}

	struct hostent *server3;
	struct sockaddr_in serv_addr3;
	memset(&serv_addr3, 0, sizeof(serv_addr3));
	serv_addr3.sin_family = AF_INET;
	serv_addr3.sin_port = htons(53);
	serv_addr3.sin_addr.s_addr = inet_addr("127.4.4.1"); 
	if (connect(socket_tcp3, (struct sockaddr *) &serv_addr3, sizeof(serv_addr3)) < 0) {
		perror("ERROR connecting\n");
	}
	printf("Connected to server.\n");
	printf("Start Send to Root...\n");
	send(socket_tcp3, buffer_send, sizeof(buffer_send), 0);


	// 读取服务器发送的响应
	int bytes_received3 = recv(socket_tcp3, buffer_receive3, sizeof(buffer_receive3), 0);
	printf("Received %d bytes: %s\n", bytes_received3, buffer_receive3);
	// 关闭连接
	close(socket_tcp3);



	//A
	if(qtype==0x0001){

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
		char *url = *name_str;
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
		char *p = &domain_name[1];
		strcpy(domain_name, p);
		int name_len = strlen(domain_name)+1;
		A_data_length += name_len;

		//构造头部--dns query
		//printf("Create DNS query...\n");
		struct DNS_Query dns_query;
		dns_query.qtype = htons(qtype);
		dns_query.qclass = htons(0x0001);
		if (name_len >= MAX_NAME_LEN) {
			return -1;
		}
		size_t query_len = position + name_len + 2 + 2;
		if (query_len > BUF_SIZE) {
			return -1;
		}
		A_data_length += 4;

		//Answers--构造name
		unsigned short name_answers = htons(0xc00c);
		A_data_length += 2;

		  
		//Answers--构造address
		//char address_answers[] = "110.12.130.22";
		//char hex_str[32] = "";
		//char* p = strtok(address_answers, ".");
		//while (p != NULL) {
	//		int num = atoi(p);
	//		sprintf(hex_str + strlen(hex_str), "%02X", num);
	//		p = strtok(NULL, ".");
	//	}
		int address_answers = htonl(0xda1e676f);
		int address_answers_len = 4;
		A_data_length += address_answers_len;

		//Answers身体
		struct DNS_RR dns_rr_answers1;
		memset(&dns_rr_answers1, 0, sizeof(dns_rr_answers1));
		dns_rr_answers1.type = htons(0x0001); // 设置标识符
		dns_rr_answers1._class = htons(0x0001); // 设置标识符
		dns_rr_answers1.ttl = htonl(0x0064); // 设置标识符
		//注意data length，是后面的address数据的length
		dns_rr_answers1.data_len = htons(0x0004); // 设置标识符

		A_data_length += 10;


		char buffer_send[A_data_length];


		//开始将数据存入buffer
		//memcpy参数：参数1为你要拷贝到的缓冲区地址，参数2为你要拷贝数据的地址，参数3为数据的长度
		memset(buffer_send, 0, sizeof(*buffer_send));
		memcpy(buffer_send, &dns_header, 12); // 拷贝头部
		int position = 12;

		memcpy(&buffer_send[position], &domain_name, name_len);
		position += name_len;

		memcpy(&buffer_send[position], &dns_query, 4);
		position += 4;

		memcpy(&buffer_send[position], &name_answers, 2); // 拷贝头部
		position += 2;

		memcpy(&buffer_send[position], &dns_rr_answers1, 10); // 拷贝头部
		position += 10;

		memcpy(&buffer_send[position], &address_answers, address_answers_len); // 拷贝头部
		position += address_answers_len;

		sendto(socket_udp, buffer_send, sizeof(buffer_send), 0, (struct sockaddr*)&send_addr, sizeof(send_addr));
	}
	if(qtype==0x000c){
		//PTR
	}
	if(qtype==0x0005){
		//CNMAE
	}
	if(qtype==0x000f){
		//MX
	}

}
}



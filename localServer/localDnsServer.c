#include <stdio.h>
#include <time.h>
#include <ctype.h>
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
char buffer_receive1[BUF_SIZE];
char buffer_receive2[BUF_SIZE];
char buffer_receive3[BUF_SIZE];
char buffer_tcp_receive[BUF_SIZE];
int my_receiveUDP();
struct in_addr addr;
char ip_str[64];
clock_t start_time, end_time;
double cpu_time_used;




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
	struct sockaddr_in send_addr;
	memset(&send_addr, 0, sizeof(send_addr));//初始化结构体中的数据
	send_addr.sin_family = AF_INET; 
	send_addr.sin_port = htons(12345); 
	send_addr.sin_addr.s_addr = inet_addr("127.0.0.1"); 

	while (1) {
	
	//接收数据！
	printf("\n\n\n------------------------------\n");
	printf("Receiving from DNS Clinet...\n");
	printf("------------------------------\n\n");
	int received_bytes = recvfrom(socket_udp, buffer_receive, BUF_SIZE, 0, (struct sockaddr*)recv_addr, &addrlen);
	buffer_receive[received_bytes] = '\0'; // C语言中，字符串是以空字符结尾的字符序列

	printf("received from %s:%d\n", inet_ntoa(recv_addr->sin_addr), ntohs(recv_addr->sin_port)); //inet_ntoa：地址转成xxx.xxx.xxx.xxx格式 //ntohs：转小端序

	struct DNS_Header *dnsheader = (struct DNS_Header *)buffer_receive;
	unsigned short id = ntohs(dnsheader->id);
	printf("Transacation ID: %04x\n", id);
	unsigned short tag = ntohs(dnsheader->tag);
	printf("Flags: %04x\n", tag);
	unsigned short queryNum = ntohs(dnsheader->queryNum);
	printf("Questions: %04x\n", queryNum);
	unsigned short answerNum = ntohs(dnsheader->answerNum);
	printf("Answer RRs: %04x\n", answerNum);
	unsigned short authorNum = ntohs(dnsheader->authorNum);
	printf("Authority RRs: %04x\n", authorNum);
	unsigned short addNum = ntohs(dnsheader->addNum);
	printf("Additional RRs: %04x\n", addNum);
	

	char *name_start = buffer_receive + 12;
	char *name_end = strchr(&buffer_receive[12], '\0');
	size_t name_len = name_end - name_start+1;
	printf("Name_len: %zu\n", name_len);
	char* name_str = malloc(name_len+1);
	if (name_str == NULL) {
	    fprintf(stderr, "Failed to allocate memory for name_str.\n");
	    exit(EXIT_FAILURE);
	}
	memcpy(name_str, name_start, name_len);
	name_str[name_len] = '\0';
	printf("Name: %s\n", name_str);

	struct DNS_Query *dnsquery = (struct DNS_Query *)(buffer_receive+12+name_len);
	unsigned short qtype = ntohs(dnsquery->qtype);
	printf("Type: %04x\n", qtype);
	unsigned short qclass = ntohs(dnsquery->qclass);
	printf("Class: %04x\n", qclass);

	


	printf("\n\n\n------------------------------\n");
	printf("Send to Root DNS Server...\n");
	printf("------------------------------\n\n");


	//开始记时
	start_time = clock();

	//构造16进制包长
	int value = 16+name_len;  // 填充一个整型数字

	
	//构造name
	int dns_length = 2+16+name_len;
	char buffer_send[dns_length];
	name_len += 1;


	//构造头部--dns header
	struct DNS_Header dns_header;
	memset(buffer_send, 0, sizeof(*buffer_send));
	dns_header.id = htons(id); // 设置标识符
	dns_header.tag = htons(tag); // 设置标志位，表示这是一个标准查询
	dns_header.queryNum = htons(queryNum); // 问题数为1
	dns_header.answerNum = htons(answerNum); dns_header.authorNum = htons(authorNum);
	dns_header.addNum = htons(addNum);


	//构造头部--dns query
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
	
	memset(buffer_send, 0, sizeof(*buffer_send));
	//memcpy(buffer_send, &value, 2); // 拷贝头部
							//
	memcpy(&buffer_send[2], &dns_header, sizeof(dns_header)); // 拷贝头部
	int position = 2+sizeof(dns_header);

	//*name_str[name_len+1] = '\0';
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

	recv_addr->sin_family = AF_INET; 
	recv_addr->sin_port = htons(12345); //htons 转换为网络字节序（大端序）
	recv_addr->sin_addr.s_addr = inet_addr("127.1.1.1"); 
	socklen_t addrlen = sizeof(*recv_addr);
	if (bind(socket_tcp, (struct sockaddr*)recv_addr, sizeof(*recv_addr)) == -1) {
		perror("bind() failed\n");
		exit(EXIT_FAILURE);
	};

	struct hostent *server;
	struct sockaddr_in serv_addr;
	memset(&serv_addr, 0, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = htons(53);
	serv_addr.sin_addr.s_addr = inet_addr("127.2.2.1"); 
	if (connect(socket_tcp, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) {
		perror("ERROR connecting\n");
	}
	send(socket_tcp, buffer_send, sizeof(buffer_send), 0);


	// 读取服务器发送的响应
	//接收数据！
	printf("\n\n\n------------------------------\n");
	printf("Receiving from Root Server...\n");
	printf("------------------------------\n\n");

	int received_bytes1 = recv(socket_tcp, buffer_receive1, sizeof(buffer_receive1), 0);

	unsigned short data_length1 = *((unsigned short*) buffer_receive1);

	buffer_receive1[received_bytes1] = '\0'; // C语言中，字符串是以空字符结尾的字符序列
						 //
	// 记录结束时间
	end_time = clock();

	// 计算执行时间
	cpu_time_used = ((double) (end_time - start_time)) / CLOCKS_PER_SEC;
	
	// 输出执行时间
	printf("Took %f seconds to receive data.\n", cpu_time_used);

	printf("Received from %s:%d\n", inet_ntoa(serv_addr.sin_addr), ntohs(serv_addr.sin_port)); //inet_ntoa：地址转成xxx.xxx.xxx.xxx格式 //ntohs：转小端序

	struct DNS_Header *dnsheader1 = (struct DNS_Header *)&buffer_receive1[2];
	unsigned short id1 = ntohs(dnsheader1->id);
	printf("Transacation ID: %04x\n", id1);
	unsigned short tag1 = ntohs(dnsheader1->tag);
	printf("Flags: %04x\n", tag1);
	unsigned short queryNum1 = ntohs(dnsheader1->queryNum);
	printf("Questions: %04x\n", queryNum1);
	unsigned short answerNum1 = ntohs(dnsheader1->answerNum);
	printf("Answer RRs: %04x\n", answerNum1);
	unsigned short authorNum1 = ntohs(dnsheader1->authorNum);
	printf("Authority RRs: %04x\n", authorNum1);
	unsigned short addNum1 = ntohs(dnsheader1->addNum);
	printf("Additional RRs: %04x\n", addNum1);
	

	char *name_start1 = buffer_receive1 + 14;
	char *name_end1 = strchr(&buffer_receive1[14], '\0');
	size_t name_len1 = name_end1 - name_start1+1;
	printf("Name_len: %zu\n", name_len1);
	char* name_str1 = malloc(name_len1);
	if (name_str1 == NULL) {
	    fprintf(stderr, "Failed to allocate memory for name_str.\n");
	    exit(EXIT_FAILURE);
	}
	memcpy(name_str1, name_start1, name_len1);
	name_str1[name_len1] = '\0';
	printf("Name: %s\n", name_str1);

	struct DNS_Query *dnsquery1 = (struct DNS_Query *)(buffer_receive1+14+name_len1);
	unsigned short qtype1 = ntohs(dnsquery1->qtype);
	printf("Type: %04x\n", qtype1);
	unsigned short qclass1 = ntohs(dnsquery1->qclass);
	printf("Class: %04x\n", qclass1);
	

	int position1 = 18+name_len1;
	//假装两字节
	//position1 += 2;

	struct DNS_RR *dns_rr1 = (struct DNS_RR *)(buffer_receive1+position1);
	unsigned short type1 = ntohs(dns_rr1->type);
	unsigned short class1 = ntohs(dns_rr1->_class);
	uint32_t ttl1 = ntohl(dns_rr1->ttl);
	unsigned short data_len1 = ntohs(dns_rr1->data_len);
	uint32_t answer1 = ntohl(dns_rr1->address);
	printf("Answer: %08x\n", answer1);

	//position2 += 10;

	addr.s_addr = htonl(answer1);
	char* str_ip1 = inet_ntoa(addr);
	printf("Answer: %s\n", str_ip1);


	position1 += 2;
	struct DNS_RR *dns_rr11 = (struct DNS_RR *)(buffer_receive1+position1);
	type1 = ntohs(dns_rr11->type);
	printf("Answer Type: %04x\n", type1);
	class1 = ntohs(dns_rr11->_class);
	printf("Answer Class: %04x\n", class1);
	ttl1 = ntohl(dns_rr11->ttl);
	printf("TTL: %08x\n", ttl1);
	data_len1 = ntohs(dns_rr11->data_len);
	printf("Data Len: %04x\n", data_len1);

	// 关闭连接
	close(socket_tcp);


	printf("\n\n\n\n------------------------------\n");
	printf("Send to tid DNS Server...\n");
	printf("------------------------------\n");


	//构造tcp socket
	int socket_tcp2;
	if((socket_tcp2 = socket(AF_INET, SOCK_STREAM, 0)) == -1){
		perror("socket() failed\n");
		exit(EXIT_FAILURE);
	}
	recv_addr->sin_family = AF_INET; 
	recv_addr->sin_port = htons(12345); //htons 转换为网络字节序（大端序）
	recv_addr->sin_addr.s_addr = inet_addr("127.1.1.1"); 
	addrlen = sizeof(*recv_addr);
	if (bind(socket_tcp, (struct sockaddr*)recv_addr, sizeof(*recv_addr)) == -1) {
		perror("bind() failed\n");
		exit(EXIT_FAILURE);
	};

	struct hostent *server2;
	struct sockaddr_in serv_addr2;
	memset(&serv_addr2, 0, sizeof(serv_addr2));
	serv_addr2.sin_family = AF_INET;
	serv_addr2.sin_port = htons(53);
	serv_addr2.sin_addr.s_addr = inet_addr(str_ip1); 
	if (connect(socket_tcp2, (struct sockaddr *) &serv_addr2, sizeof(serv_addr2)) < 0) {
		perror("ERROR connecting\n");
	}

	// 记录开始时间
	start_time = clock();

	send(socket_tcp2, buffer_send, sizeof(buffer_send), 0);

	// 读取服务器发送的响应
	//接收数据！
	printf("\n\n\n------------------------------\n");
	printf("Receiving from tid Server...\n");
	printf("------------------------------\n\n");

	int received_bytes2 = recv(socket_tcp2, buffer_receive2, sizeof(buffer_receive2), 0);
	unsigned short data_length2 = *((unsigned short*) buffer_receive2);

	buffer_receive2[received_bytes2] = '\0'; // C语言中，字符串是以空字符结尾的字符序列

	// 记录结束时间
	end_time = clock();

	// 计算执行时间
	cpu_time_used = ((double) (end_time - start_time)) / CLOCKS_PER_SEC;
	
	// 输出执行时间
	printf("Took %f seconds to receive data.\n", cpu_time_used);

	printf("Received from %s:%d\n", inet_ntoa(serv_addr2.sin_addr), ntohs(serv_addr2.sin_port)); //inet_ntoa：地址转成xxx.xxx.xxx.xxx格式 //ntohs：转小端序

	struct DNS_Header *dnsheader2 = (struct DNS_Header *)&buffer_receive2[2];
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
	

	char *name_start2 = buffer_receive2 + 14;
	char *name_end2 = strchr(&buffer_receive2[14], '\0');
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

	struct DNS_Query *dnsquery2 = (struct DNS_Query *)(buffer_receive2+14+name_len2);
	unsigned short qtype2 = ntohs(dnsquery2->qtype);
	printf("Type: %04x\n", qtype2);
	unsigned short qclass2 = ntohs(dnsquery2->qclass);
	printf("Class: %04x\n", qclass2);
	

	//有问题的解包
	int position2 = 18+name_len2;
	//假装两字节
	//position2 += 2;

	struct DNS_RR *dns_rr2 = (struct DNS_RR *)(buffer_receive2+position2);
	unsigned short type2 = ntohs(dns_rr2->type);
	unsigned short class2 = ntohs(dns_rr2->_class);
	uint32_t ttl2 = ntohl(dns_rr2->ttl);
	unsigned short data_len2 = ntohs(dns_rr2->data_len);
	uint32_t answer = ntohl(dns_rr2->address);
	printf("Answer: %08x\n", answer);

	//position2 += 10;

	addr.s_addr = htonl(answer);
	char* str_ip = inet_ntoa(addr);
	printf("Answer: %s\n", str_ip);

	position2 += 2;
	struct DNS_RR *dns_rr22 = (struct DNS_RR *)(buffer_receive2+position2);
	type2 = ntohs(dns_rr22->type);
	printf("Answer Type: %04x\n", type2);
	class2 = ntohs(dns_rr22->_class);
	printf("Answer Class: %04x\n", class2);
	ttl2 = ntohl(dns_rr2->ttl);
	printf("TTL: %08x\n", ttl2);
	data_len2 = ntohs(dns_rr22->data_len);
	printf("Data Len: %04x\n", data_len2);

	// 关闭连接
	close(socket_tcp2);




	printf("\n\n\n------------------------------\n");
	printf("Send to 2nd DNS Server...\n");
	printf("------------------------------\n\n");
	//构造tcp socket
	int socket_tcp3;
	if((socket_tcp3 = socket(AF_INET, SOCK_STREAM, 0)) == -1){
		perror("socket() failed\n");
		exit(EXIT_FAILURE);
	}
	recv_addr->sin_family = AF_INET; 
	recv_addr->sin_port = htons(12345); //htons 转换为网络字节序（大端序）
	recv_addr->sin_addr.s_addr = inet_addr("127.1.1.1"); 
	addrlen = sizeof(*recv_addr);
	if (bind(socket_tcp, (struct sockaddr*)recv_addr, sizeof(*recv_addr)) == -1) {
		perror("bind() failed\n");
		exit(EXIT_FAILURE);
	};

	struct hostent *server3;
	struct sockaddr_in serv_addr3;
	memset(&serv_addr3, 0, sizeof(serv_addr3));
	serv_addr3.sin_family = AF_INET;
	serv_addr3.sin_port = htons(53);
	serv_addr3.sin_addr.s_addr = inet_addr(str_ip); 
	if (connect(socket_tcp3, (struct sockaddr *) &serv_addr3, sizeof(serv_addr3)) < 0) {
		perror("ERROR connecting\n");
	}
	send(socket_tcp3, buffer_send, sizeof(buffer_send), 0);


	// 读取服务器发送的响应
	recv(socket_tcp3, buffer_receive3, sizeof(buffer_receive3), 0);
	unsigned short data_length3 = *((unsigned short*) buffer_receive3);
	char address_received3[data_length3];
	memcpy(address_received3, &buffer_receive3[2], data_length3);
	printf("Received %d bytes: %s\n", data_length3, address_received3);
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
		char *url = name_str2;
		A_data_length += name_len2;

		//构造头部--dns query
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


		//Authoritative--构造name
		unsigned short name_authoritative = htons(0xc00c);
		A_data_length += 2;

		  
		//Authoritative--构造address
		int address_authoritative = htonl(0xda1e676f);
		int address_authoritative_len = 4;
		A_data_length += address_authoritative_len;

		//Authoritative身体
		struct DNS_RR dns_rr_authoritative1;
		memset(&dns_rr_authoritative1, 0, sizeof(dns_rr_authoritative1));
		dns_rr_authoritative1.type = htons(0x0002); // 设置标识符
		dns_rr_authoritative1._class = htons(0x0001); // 设置标识符
		dns_rr_authoritative1.ttl = htonl(0x0064); // 设置标识符
		//注意data length，是后面的address数据的length
		dns_rr_authoritative1.data_len = htons(0x0004); // 设置标识符

		A_data_length += 10;


		//Additional--构造name
		unsigned short name_additional = htons(0xc00c);
		A_data_length += 2;

		  
		//Additional--构造address
		int address_additional = htonl(0xda1e676f);
		int address_additional_len = 4;
		A_data_length += address_additional_len;

		//Additional身体
		struct DNS_RR dns_rr_additional1;
		memset(&dns_rr_additional1, 0, sizeof(dns_rr_additional1));
		dns_rr_additional1.type = htons(0x0001); // 设置标识符
		dns_rr_additional1._class = htons(0x0001); // 设置标识符
		dns_rr_additional1.ttl = htonl(0x0064); // 设置标识符
		//注意data length，是后面的address数据的length
		dns_rr_additional1.data_len = htons(0x0004); // 设置标识符

		A_data_length += 10;
		char buffer_send[A_data_length];


		//开始将数据存入buffer
		//memcpy参数：参数1为你要拷贝到的缓冲区地址，参数2为你要拷贝数据的地址，参数3为数据的长度
		memset(buffer_send, 0, sizeof(*buffer_send));
		memcpy(buffer_send, &dns_header, 12); // 拷贝头部
		int position = 12;

		memcpy(&buffer_send[position], url, name_len2);
		position += name_len2;

		memcpy(&buffer_send[position], &dns_query, 4);
		position += 4;

		memcpy(&buffer_send[position], &name_answers, 2); // 拷贝头部
		position += 2;

		memcpy(&buffer_send[position], &dns_rr_answers1, 10); // 拷贝头部
		position += 10;

		memcpy(&buffer_send[position], &address_answers, address_answers_len); // 拷贝头部
		position += address_answers_len;

		memcpy(&buffer_send[position], &name_authoritative, 2); // 拷贝头部
		position += 2;

		memcpy(&buffer_send[position], &dns_rr_authoritative1, 10); // 拷贝头部
		position += 10;

		memcpy(&buffer_send[position], &address_authoritative, address_authoritative_len); // 拷贝头部
		position += address_authoritative_len;

		memcpy(&buffer_send[position], &name_additional, 2); // 拷贝头部
		position += 2;

		memcpy(&buffer_send[position], &dns_rr_additional1, 10); // 拷贝头部
		position += 10;

		memcpy(&buffer_send[position], &address_additional, address_additional_len); // 拷贝头部
		position += address_additional_len;

		sendto(socket_udp, buffer_send, sizeof(buffer_send), 0, (struct sockaddr*)&send_addr, sizeof(send_addr));
	}


	if(qtype==0x000c){
		//PTR
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
		char *url = name_str2;
		A_data_length += name_len2;

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

		memcpy(&buffer_send[position], url, name_len2);
		position += name_len2;

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


	if(qtype==0x0005){
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
		char *url = name_str2;
		A_data_length += name_len2;

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

		memcpy(&buffer_send[position], url, name_len2);
		position += name_len2;

		memcpy(&buffer_send[position], &dns_query, 4);
		position += 4;

		memcpy(&buffer_send[position], &name_answers, 2); // 拷贝头部
		position += 2;

		memcpy(&buffer_send[position], &dns_rr_answers1, 10); // 拷贝头部
		position += 10;

		memcpy(&buffer_send[position], &address_answers, address_answers_len); // 拷贝头部
		position += address_answers_len;

		sendto(socket_udp, buffer_send, sizeof(buffer_send), 0, (struct sockaddr*)&send_addr, sizeof(send_addr));
		//CNMAE
	}


	if(qtype==0x000f){
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
		char *url = name_str2;
		A_data_length += name_len2;

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

		memcpy(&buffer_send[position], url, name_len2);
		position += name_len2;

		memcpy(&buffer_send[position], &dns_query, 4);
		position += 4;

		memcpy(&buffer_send[position], &name_answers, 2); // 拷贝头部
		position += 2;

		memcpy(&buffer_send[position], &dns_rr_answers1, 10); // 拷贝头部
		position += 10;

		memcpy(&buffer_send[position], &address_answers, address_answers_len); // 拷贝头部
		position += address_answers_len;

		sendto(socket_udp, buffer_send, sizeof(buffer_send), 0, (struct sockaddr*)&send_addr, sizeof(send_addr));
		//MX
	}

}
}



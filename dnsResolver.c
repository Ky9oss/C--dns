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


char buffer_receive[BUF_SIZE];
char buffer_send[BUF_SIZE];
int my_send(int socket);
int my_receive(int socket);
void convert_to_big_endian(unsigned char* data, size_t size);


struct DNS_Header{
	unsigned short id: 16;
	unsigned short tag: 16;
	unsigned short queryNum: 16;
	unsigned short answerNum: 16;
	unsigned short authorNum: 16;
	unsigned short addNum: 16;
};

struct DNS_Query{
	unsigned char *name;
	unsigned short qtype: 16;
	unsigned short qclass: 16;
};


int main(int argc, char *argv[]){

	printf("Start main...\n");
	int socket_udp;
	int socket_tcp;

	if((socket_udp = socket(AF_INET, SOCK_DGRAM, 0)) == -1){
		perror("socket() failed");
		exit(EXIT_FAILURE);
	}
	
	if((socket_tcp = socket(AF_INET, SOCK_STREAM, 0)) == -1){
		perror("socket() failed");
		exit(EXIT_FAILURE);
	}


	printf("Start While...\n");
	my_send(socket_udp);


}

int my_receive(int socket){

	struct sockaddr_in recv_addr;
	memset(&recv_addr, 0, sizeof(recv_addr));//初始化结构体中的数据
	recv_addr.sin_family = AF_INET; 
	recv_addr.sin_port = htons(12345); //htons 转换为网络字节序（大端序）
	recv_addr.sin_addr.s_addr = inet_addr("127.0.0.1"); 

	if (bind(socket, (struct sockaddr*)&recv_addr, sizeof(recv_addr)) == -1) {
		perror("bind() failed");
		exit(EXIT_FAILURE);
	}
	socklen_t addrlen = sizeof(recv_addr);

	int received_bytes = recvfrom(socket, buffer_receive, BUF_SIZE, 0, (struct sockaddr*)&recv_addr, &addrlen);
	buffer_receive[received_bytes] = '\0'; // C语言中，字符串是以空字符结尾的字符序列

	printf("received from %s:%d: %s\n", inet_ntoa(recv_addr.sin_addr), ntohs(recv_addr.sin_port), buffer_receive); //inet_ntoa：地址转成xxx.xxx.xxx.xxx格式 //ntohs：转小端序

	return 1;
}

int my_send(int socket){

	printf("Create DNS Header...\n");
	struct DNS_Header dns_header;
	memset(&dns_header, 0, sizeof(dns_header));
	dns_header.id = htons(5555); // 设置标识符
	dns_header.tag = htons(0x0100); // 设置标志位，表示这是一个标准查询
	dns_header.queryNum = htons(1); // 问题数为1
	dns_header.addNum = htons(1);
	dns_header.answerNum = htons(2);
	dns_header.authorNum = htons(2);
	memset(buffer_send, 0, sizeof(buffer_send));
	memcpy(buffer_send, &dns_header, sizeof(dns_header)); // 拷贝头部
	int position = sizeof(dns_header);


	printf("Create DNS query...\n");
	struct DNS_Query *dns_query;
	unsigned char url[] = "bupt.edu.cn";
	size_t url_len = strlen((char*)url);
	unsigned char domain_name[url_len+2];
	int e = 0;
	for (int i = 0; i < url_len; i++) {
	    if (url[i] == '.') {
		domain_name[i-e] = e;
		e=0;
	    } else {
		domain_name[i+1] = url[i];
		e++;
	    }
	}
	domain_name[url_len+1-e] = e;
	domain_name[url_len+2] = '\0';
	convert_to_big_endian(domain_name, sizeof(domain_name));

	//uint16_t num;
	//memcpy(&num, &url, sizeof(num));
	//num = htons(num);
	//memcpy(&url, &num, sizeof(url));

	dns_query->name = (unsigned char*)malloc(sizeof(domain_name));
	dns_query->qtype = htons(0x0010);
	uint16_t qtype = dns_query->qtype;
	dns_query->qclass = htons(0x0010);
	uint16_t qclass = dns_query->qclass;
	size_t name_len = strlen((char*)dns_query->name)+1;
	if (name_len >= MAX_NAME_LEN) {
		return -1;
	}
	size_t query_len = name_len + 2 + 2;
	if (query_len > BUF_SIZE) {
		return -1;
	}
	//memcpy参数：参数1为你要拷贝到的缓冲区地址，参数2为你要拷贝数据的地址，参数3为数据的长度
	memcpy(&buffer_send[position], &dns_query->name, name_len);
	position += name_len;
	memcpy(&buffer_send[position], &qtype, 2);
	position += 2;
	memcpy(&buffer_send[position], &qclass, 2);
	position += 2;
	buffer_send[position] = htons(0x00);



	// 打印生成的 DNS 报文
	//for(int i = 0; i < position; i++){
	//    printf("%02x", buffer_send[i]);
	//}


	printf("Create (sockaddr_in)send_addr...\n");
	struct sockaddr_in send_addr;
	memset(&send_addr, 0, sizeof(send_addr));//初始化结构体中的数据
	send_addr.sin_family = AF_INET; 
	send_addr.sin_port = htons(53); 
	send_addr.sin_addr.s_addr = inet_addr("127.1.1.1"); 

	printf("Start Send...\n");
	sendto(socket, buffer_send, sizeof(buffer_send), 0, (struct sockaddr*)&send_addr, sizeof(send_addr));

	return 1;

}

//当char x[]作为参数传递时，会自动转换char* x类型，作为指针传递
void convert_to_big_endian(unsigned char* data, size_t size) {
    for (size_t i = 0; i < size / 2; i++) {
        unsigned char tmp = data[i];
        data[i] = data[size - i - 1];
        data[size - i - 1] = tmp;
    }
}

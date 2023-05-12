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


char buffer_receive[BUF_SIZE];
int my_send();
int my_receive();
void convert_to_big_endian(char* data, size_t size);


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


int main(int argc, char *argv[]){

	printf("Start While...\n");
	while(1){
		my_send();
		my_receive();
	}

}

int my_receive(){
	int socket_udp;

	if((socket_udp = socket(AF_INET, SOCK_DGRAM, 0)) == -1){
		perror("socket() failed");
		exit(EXIT_FAILURE);
	};


}

int my_send(){
	char url[] = "bupt.edu.cn";
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


	printf("Start create name...\n");
	int dns_length = 16+name_len;
	char buffer_send[dns_length];
	int socket_udp;
	socket_udp = socket(AF_INET, SOCK_DGRAM, 0);
	struct sockaddr_in recv_addr;
	memset(&recv_addr, 0, sizeof(recv_addr));//初始化结构体中的数据
	recv_addr.sin_family = AF_INET; 
	recv_addr.sin_port = htons(12345); //htons 转换为网络字节序（大端序）
	recv_addr.sin_addr.s_addr = inet_addr("127.0.0.1"); 

	if (bind(socket_udp, (struct sockaddr*)&recv_addr, sizeof(recv_addr)) == -1) {
		perror("bind() failed\n");
		exit(EXIT_FAILURE);
	}
	socklen_t addrlen = sizeof(recv_addr);


	printf("Create DNS Header...\n");
	struct DNS_Header dns_header;
	memset(&dns_header, 0, sizeof(dns_header));
	dns_header.id = htons(0xa82e); // 设置标识符
	dns_header.tag = htons(0x0100); // 设置标志位，表示这是一个标准查询
	dns_header.queryNum = htons(1); // 问题数为1
	dns_header.addNum = htons(0);
	dns_header.answerNum = htons(0);
	dns_header.authorNum = htons(0);
	memset(buffer_send, 0, sizeof(*buffer_send));
	memcpy(buffer_send, &dns_header, sizeof(dns_header)); // 拷贝头部
	int position = sizeof(dns_header);


	printf("Create DNS query...\n");
	struct DNS_Query dns_query;
	//dns_query->name = domain_name;
	dns_query.qtype = htons(0x0001);
	dns_query.qclass = htons(0x0001);
	if (name_len >= MAX_NAME_LEN) {
		return -1;
	}
	size_t query_len = position + name_len + 2 + 2;
	if (query_len > BUF_SIZE) {
		return -1;
	}
	//memcpy参数：参数1为你要拷贝到的缓冲区地址，参数2为你要拷贝数据的地址，参数3为数据的长度
	printf("Start memcpy...\n");
	memcpy(&buffer_send[position], &domain_name, name_len);
	position += name_len;
	memcpy(&buffer_send[position], &dns_query, sizeof(dns_query)); // 拷贝头部


	printf("Create (sockaddr_in)send_addr...\n");
	struct sockaddr_in send_addr;
	memset(&send_addr, 0, sizeof(send_addr));//初始化结构体中的数据
	send_addr.sin_family = AF_INET; 
	send_addr.sin_port = htons(53); 
	send_addr.sin_addr.s_addr = inet_addr("127.1.1.1"); 


	while(1){
		printf("Start Send...\n");
		sendto(socket_udp, buffer_send, sizeof(buffer_send), 0, (struct sockaddr*)&send_addr, sizeof(send_addr));


		printf("Start receiving...\n");
		int received_bytes = recvfrom(socket_udp, buffer_receive, BUF_SIZE, 0, (struct sockaddr*)&recv_addr, &addrlen);
		buffer_receive[received_bytes] = '\0'; // C语言中，字符串是以空字符结尾的字符序列

		printf("received from %s:%d\n", inet_ntoa(recv_addr.sin_addr), ntohs(recv_addr.sin_port)); //inet_ntoa：地址转成xxx.xxx.xxx.xxx格式 //ntohs：转小端序
	
		struct DNS_Header *dnsheader = (struct DNS_Header *)buffer_receive;
		printf("%d\n",ntohs(dnsheader->id));
		char *name_start = buffer_receive+sizeof(*dnsheader);
		char *name_end;
		name_end = strchr(&buffer_receive[sizeof(*dnsheader)], '\0');
		int name_len = name_end - name_start;
		char name_str[name_len];
		for (int i=0; i<name_len; i++) {
			name_str[i] = *(name_start+i);
		}
		printf("%s\n", name_str);
		
	};
	
	close(socket_udp);

	return 1;

}


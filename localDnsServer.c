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


#define BUF_SIZE 4096


char buffer_receive[BUF_SIZE];
char buffer_tcp_receive[BUF_SIZE];


struct TCP_Query my_receive(int* socket_udp, struct sockaddr_in* recv_addr);
char* my_send(struct TCP_Query tcp_value);


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

struct DNS_RR {
	unsigned char *name;
	unsigned short type;
	unsigned short _class;
	unsigned int ttl;
	unsigned short data_len;
	unsigned char *rdata;
};

struct TCP_Query{
	unsigned short tcp_qtype: 16;
	char *tcp_url;
};



int main(int argc, char *argv[]){

	printf("Start main...\n");

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

	printf("Start bind...\n");
	if (bind(socket_udp, (struct sockaddr*)recv_addr, sizeof(*recv_addr)) == -1) {
		perror("bind() failed\n");
		exit(EXIT_FAILURE);
	};

	while(1){
		struct TCP_Query tcp_value = my_receive(&socket_udp, recv_addr);
		char* received_root = my_send(tcp_value);
		if(received_root[0]=='s'){

		}
		else{
			printf("Received TCP Packet from Root DNS server: The answer is %s", received_root);
		}
		char* received_tid = my_send(tcp_value);
		if(received_tid[0]=='s'){

		}
		else{
			printf("Received TCP Packet from Tid DNS server: The answer is %s", received_tid);
		}
		char* received_2nd = my_send(tcp_value);
		if(received_2nd[0]=='s'){

		}
		else{
			printf("Received TCP Packet from 2nd DNS server: The answer is %s", received_2nd);
		}
	}


}


struct TCP_Query my_receive(int *socket_udp, struct sockaddr_in* recv_addr){

	socklen_t addrlen = sizeof(*recv_addr);
	printf("Start receiving...\n");
	int received_bytes = recvfrom(*socket_udp, buffer_receive, BUF_SIZE, 0, (struct sockaddr*)recv_addr, &addrlen);
	buffer_receive[received_bytes] = '\0'; // C语言中，字符串是以空字符结尾的字符序列

	printf("received from %s:%d\n", inet_ntoa(recv_addr->sin_addr), ntohs(recv_addr->sin_port)); //inet_ntoa：地址转成xxx.xxx.xxx.xxx格式 //ntohs：转小端序

	struct DNS_Header *dnsheader = (struct DNS_Header *)buffer_receive;
	printf("%d\n",ntohs(dnsheader->id));
	char *name_start = buffer_receive+sizeof(*dnsheader);
	char *name_end;
	name_end = strchr(&buffer_receive[sizeof(*dnsheader)], '\0');
	int name_len = name_end - name_start;
	printf("Name_len: %d\n", name_len);
	char* name_str[name_len];
	for (int i=0; i<name_len; i++) {
		name_str[i] = name_start+i;
		//if(isalpha(*name_str[i])!=0){
		//	printf("%c\n", *name_str[i]);
		//}
	}
	printf("url: %s\n", *name_str);
	struct DNS_Query *dnsquery = (struct DNS_Query *)(buffer_receive+sizeof(*dnsheader)+name_len+1);
	struct TCP_Query tcp_value;
	tcp_value.tcp_url = *name_str;
	tcp_value.tcp_qtype = ntohs(dnsquery->qtype);
	

	return tcp_value;
}


char* my_send(struct TCP_Query tcp_value){
	int socket_tcp;
	char buffer_send[sizeof(tcp_value)];
	memset(buffer_send, 0, sizeof(buffer_send));
	
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
	printf("Start memcpy...\n");
	memcpy(buffer_send, &tcp_value, 2); 
	memcpy(&buffer_send[2], tcp_value.tcp_url, sizeof(*tcp_value.tcp_url)); 
	int n = write(socket_tcp, buffer_send, strlen(buffer_send));
	if (n < 0) {
		perror("ERROR writing to socket\n");
	}

	memset(buffer_tcp_receive, 0, sizeof(buffer_tcp_receive));
	n = read(socket_tcp, buffer_tcp_receive, BUF_SIZE);
	if (n < 0) {
		perror("ERROR reading from socket\n");
	}
	printf("Send to %s:%d\n", inet_ntoa(serv_addr.sin_addr), ntohs(serv_addr.sin_port)); 
	printf("Send Data: %s\n", buffer_send);
	char* returned = buffer_tcp_receive;
	close(socket_tcp);
	return returned;

}

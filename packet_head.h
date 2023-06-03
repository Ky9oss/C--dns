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
	//char *DQ_name;
	unsigned short qtype: 16;
	unsigned short qclass: 16;
};

struct DNS_RR {
	//unsigned short _name: 16;
	unsigned short type: 16;
	unsigned short _class: 16;
	uint32_t ttl: 32;
	unsigned short data_len: 16;
	uint32_t address: 32;
};


struct DNS_Header_TCP{
	unsigned short length: 16;
	unsigned short id: 16;
	unsigned short tag: 16;
	unsigned short queryNum: 16;
	unsigned short answerNum: 16;
	unsigned short authorNum: 16;
	unsigned short addNum: 16;
};

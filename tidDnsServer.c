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

    while (1) {
        // 接受新的客户端连接请求
        if ((client_socket = accept(listening_socket, (struct sockaddr *)&client_address, (socklen_t*)&addrlen)) < 0) {
            perror("Accept failed");
            exit(EXIT_FAILURE);
        }

        printf("New client connected.\n");

        // 读取客户端发送的数据
        int bytes_received = recv(client_socket, buffer, sizeof(buffer), 0);
        printf("Received %d bytes: %s\n", bytes_received, buffer);

        // 发送响应给客户端
        char *response = "Hello from server!";
        send(client_socket, response, strlen(response), 0);

        // 关闭连接
        close(client_socket);
        printf("Client disconnected.\n");
    }

    return 0;
}

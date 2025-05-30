#include <iostream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>
#include <sys/utsname.h>
#include <thread>

#define MULTICAST_GROUP "239.255.255.250"
#define PORT 5555
#define RESPONSE_PORT 5556
#define BUFFER_SIZE 1024

void listen_multicast(int sock) {
    char buffer[BUFFER_SIZE];
    sockaddr_in sender_addr{};
    socklen_t addr_len = sizeof(sender_addr);

    while (true) {
        memset(buffer, 0, BUFFER_SIZE);
        recvfrom(sock, buffer, BUFFER_SIZE, 0, 
                (sockaddr*)&sender_addr, &addr_len);

        if (strcmp(buffer, "HEARTBEAT") == 0) {
            char client_ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &sender_addr.sin_addr, 
                     client_ip, INET_ADDRSTRLEN);
            std::cout << "Received a multicast" << std::endl;
            sockaddr_in response_addr{};
            response_addr.sin_family = AF_INET;
            response_addr.sin_port = htons(RESPONSE_PORT);
            inet_pton(AF_INET, client_ip, &response_addr.sin_addr);

            char hostname[256];
            gethostname(hostname, sizeof(hostname));
            std::string msg = "HEARTBEAT_RESPONSE " + std::string(hostname);
            sendto(sock, msg.c_str(), msg.size(), 0, 
                  (sockaddr*)&response_addr, sizeof(response_addr));
            std::cout << "Sent a response to the server" << std::endl;
        }
    }
}

void process_requests(int sock) {
    char buffer[BUFFER_SIZE];
    sockaddr_in sender_addr{};
    socklen_t addr_len = sizeof(sender_addr);

    while (true) {
        memset(buffer, 0, BUFFER_SIZE);
        recvfrom(sock, buffer, BUFFER_SIZE, 0, 
                (sockaddr*)&sender_addr, &addr_len);

        if (strcmp(buffer, "SYSINFO_REQUEST") == 0) {
            char client_ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &sender_addr.sin_addr, 
                     client_ip, INET_ADDRSTRLEN);
            std::cout << "Received a sysinfo request" << std::endl;
            utsname sys_info{};
            uname(&sys_info);
            std::string info = std::string(sys_info.sysname) + " " +
                              std::string(sys_info.release) + " " +
                              std::string(sys_info.machine);

            char hostname[256];
            gethostname(hostname, sizeof(hostname));
            std::string msg = "SYSINFO_RESPONSE " + 
                             std::string(hostname) + " " + info;
            
            sockaddr_in response_addr{};
            response_addr.sin_family = AF_INET;
            response_addr.sin_port = htons(RESPONSE_PORT);
            inet_pton(AF_INET, client_ip, &response_addr.sin_addr);

            sendto(sock, msg.c_str(), msg.size(), 0, 
                  (sockaddr*)&response_addr, sizeof(response_addr));
            std::cout << "Sent a sysinfo response" << std::endl;
        }
    }
}

int main() {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("socket");
        return 1;
    }

    // Настройка multicast
    ip_mreq mreq{};
    inet_pton(AF_INET, MULTICAST_GROUP, &mreq.imr_multiaddr);
    mreq.imr_interface.s_addr = htonl(INADDR_ANY);
    setsockopt(sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, 
              &mreq, sizeof(mreq));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    
    if (bind(sock, (sockaddr*)&addr, sizeof(addr))){
        perror("bind");
        return 1;
    }

    // Второй сокет для обработки запросов
    int cmd_sock = socket(AF_INET, SOCK_DGRAM, 0);
    sockaddr_in cmd_addr{};
    cmd_addr.sin_family = AF_INET;
    cmd_addr.sin_port = htons(RESPONSE_PORT);
    cmd_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    
    if (bind(cmd_sock, (sockaddr*)&cmd_addr, sizeof(cmd_addr))) {
        perror("bind cmd");
        return 1;
    }

    std::thread multicast_thread(listen_multicast, sock);
    std::thread request_thread(process_requests, cmd_sock);

    multicast_thread.join();
    request_thread.join();

    close(sock);
    close(cmd_sock);
    return 0;
}
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
        ssize_t recv_len = recvfrom(sock, buffer, BUFFER_SIZE, 0, 
                                   (sockaddr*)&sender_addr, &addr_len);
        
        if (recv_len <= 0) continue;

        if (strcmp(buffer, "SYSINFO_REQUEST") == 0) {
            std::cout << "Received request from server" << std::endl;
            char server_ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &sender_addr.sin_addr, server_ip, INET_ADDRSTRLEN);
            
            utsname sys_info{};
            if (uname(&sys_info)) {
                std::cerr << "Failed to get system info" << std::endl;
                continue;
            }

            char hostname[256];
            gethostname(hostname, sizeof(hostname));
            std::string info = std::string(sys_info.sysname) + " " +
                              std::string(sys_info.release) + " " +
                              std::string(sys_info.machine);

            std::string msg = "SYSINFO_RESPONSE " + 
                             std::string(hostname) + " " + info;

            sockaddr_in response_addr{};
            response_addr.sin_family = AF_INET;
            response_addr.sin_port = htons(RESPONSE_PORT);
            inet_pton(AF_INET, server_ip, &response_addr.sin_addr);

            if (sendto(sock, msg.c_str(), msg.size(), 0, 
                      (sockaddr*)&response_addr, sizeof(response_addr)) < 0) {
                std::cerr << "Failed to send sysinfo" << std::endl;
            } else {
                std::cout << "Sent system info to server" << std::endl;
            }
        }
    }
}

int main() {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("socket");
        return 1;
    }

    ip_mreq mreq{};
    inet_pton(AF_INET, MULTICAST_GROUP, &mreq.imr_multiaddr);
    mreq.imr_interface.s_addr = htonl(INADDR_ANY);
    
    if (setsockopt(sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq))) {
        perror("multicast join");
        close(sock);
        return 1;
    }

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    
    if (bind(sock, (sockaddr*)&addr, sizeof(addr))) {
        perror("bind");
        close(sock);
        return 1;
    }

    std::thread multicast_thread(listen_multicast, sock);

    char hostname[256];
    gethostname(hostname, sizeof(hostname));
    std::cout << "Client started. Hostname: " << hostname << std::endl;
    std::cout << "Press Enter to exit..." << std::endl;
    
    std::cin.get();
    
    close(sock);
    return 0;
}
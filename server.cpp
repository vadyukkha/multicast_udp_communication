#include <iostream>
#include <vector>
#include <map>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>
#include <ctime>
#include <sys/utsname.h>
#include <thread>
#include <mutex>
#include <chrono>

#define MULTICAST_GROUP "239.255.255.250"
#define PORT 5555
#define RESPONSE_PORT 5556
#define BUFFER_SIZE 1024
#define TIME_INTERVAL 5
#define CLIENT_TIMEOUT 15

struct ClientInfo {
    std::string id;
    std::string ip;
    time_t last_seen;
    std::string sysinfo;
    bool marked_offline = false;
};

std::map<std::string, ClientInfo> clients;
std::mutex clients_mutex;

void send_multicast(int sock) {
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
    inet_pton(AF_INET, MULTICAST_GROUP, &addr.sin_addr);

    const char* msg = "SYSINFO_REQUEST";
    while (true) {
        sendto(sock, msg, strlen(msg), 0, 
              (sockaddr*)&addr, sizeof(addr));
        std::cout << "Sent a multicast sysinfo request" << std::endl;
        std::this_thread::sleep_for(
            std::chrono::seconds(TIME_INTERVAL));
    }
}

void process_responses(int sock) {
    char buffer[BUFFER_SIZE];
    sockaddr_in sender_addr{};
    socklen_t addr_len = sizeof(sender_addr);

    while (true) {
        memset(buffer, 0, BUFFER_SIZE);
        ssize_t recv_len = recvfrom(sock, buffer, BUFFER_SIZE, 0, 
                                   (sockaddr*)&sender_addr, &addr_len);
        if (recv_len <= 0) continue;

        char client_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &sender_addr.sin_addr, client_ip, INET_ADDRSTRLEN);

        std::lock_guard<std::mutex> lock(clients_mutex);
        time_t current_time = time(nullptr);

        if (strncmp(buffer, "SYSINFO_RESPONSE", 16) == 0) {
            char* data_start = buffer + 17;
            char* space_pos = strchr(data_start, ' ');
            
            if (space_pos) {
                *space_pos = '\0';
                std::string client_id(data_start);
                std::string sysinfo(space_pos + 1);
                
                auto it = clients.find(client_id);
                if (it != clients.end()) {
                    if (it->second.marked_offline) {
                        it->second.marked_offline = false;
                        std::cout << "Client is back online: " << client_id << std::endl;
                    }
                    it->second.last_seen = current_time;
                    it->second.sysinfo = sysinfo;
                    
                    std::cout << "\n=== System Information from " << client_id << " ===" << std::endl;
                    std::cout << "IP Address: " << client_ip << std::endl;
                    std::cout << "System Info: " << sysinfo << std::endl;
                    std::cout << "Last Seen: " << ctime(&current_time);
                    std::cout << "=================================\n" << std::endl;
                } else {
                    ClientInfo new_client{
                        client_id,
                        client_ip,
                        current_time,
                        sysinfo,
                        false
                    };
                    clients[client_id] = new_client;
                    std::cout << "New client registered: " << client_id << " (" << client_ip << ")" << std::endl;
                    
                    std::cout << "\n=== System Information from " << client_id << " ===" << std::endl;
                    std::cout << "IP Address: " << client_ip << std::endl;
                    std::cout << "System Info: " << sysinfo << std::endl;
                    std::cout << "Last Seen: " << ctime(&current_time);
                    std::cout << "=================================\n" << std::endl;
                }
            }
        }
    }
}

void check_clients(int sock) {
    while (true) {
        std::this_thread::sleep_for(std::chrono::seconds(3));
        time_t current_time = time(nullptr);
        
        std::lock_guard<std::mutex> lock(clients_mutex);
        std::vector<std::string> to_remove;
        
        for (auto& [id, client] : clients) {
            if (current_time - client.last_seen > CLIENT_TIMEOUT) {
                if (!client.marked_offline) {
                    client.marked_offline = true;
                    std::cout << "Client is offline: " << id << std::endl;
                }
                
                if (current_time - client.last_seen > CLIENT_TIMEOUT * 2) {
                    to_remove.push_back(id);
                }
            }
        }
        
        for (const auto& id : to_remove) {
            std::cout << "Removing inactive client: " << id << std::endl;
            clients.erase(id);
        }
    }
}

int main() {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("socket");
        return 1;
    }

    int reuse = 1;
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse))) {
        perror("setsockopt");
    }

    sockaddr_in server_addr{};
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(RESPONSE_PORT);
    server_addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(sock, (sockaddr*)&server_addr, sizeof(server_addr))) {
        perror("bind");
        close(sock);
        return 1;
    }

    std::thread multicast_thread(send_multicast, sock);
    std::thread recv_thread(process_responses, sock);
    std::thread check_thread(check_clients, sock);

    multicast_thread.join();
    recv_thread.join();
    check_thread.join();

    close(sock);
    return 0;
}
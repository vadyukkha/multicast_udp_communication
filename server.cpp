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
};

std::map<std::string, ClientInfo> clients;
std::mutex clients_mutex;

void send_heartbeat(int sock) {
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
    inet_pton(AF_INET, MULTICAST_GROUP, &addr.sin_addr);

    const char* msg = "HEARTBEAT";
    while (true) {
        sendto(sock, msg, strlen(msg), 0, 
              (sockaddr*)&addr, sizeof(addr));
        std::cout << "Sent a multicast" << std::endl;
        std::this_thread::sleep_for(
            std::chrono::seconds(TIME_INTERVAL));
    }
}

void request_sysinfo(int sock, const ClientInfo& client) {
    sockaddr_in client_addr{};
    client_addr.sin_family = AF_INET;
    client_addr.sin_port = htons(RESPONSE_PORT);
    inet_pton(AF_INET, client.ip.c_str(), &client_addr.sin_addr);
    const char* msg = "SYSINFO_REQUEST";
    sendto(sock, msg, strlen(msg), 0, 
          (sockaddr*)&client_addr, sizeof(client_addr));
    std::cout << "Sent a sysinfo request" << std::endl;
}

void process_responses(int sock) {
    char buffer[BUFFER_SIZE];
    sockaddr_in sender_addr{};
    socklen_t addr_len = sizeof(sender_addr);

    while (true) {
        memset(buffer, 0, BUFFER_SIZE);
        recvfrom(sock, buffer, BUFFER_SIZE, 0, 
                (sockaddr*)&sender_addr, &addr_len);

        char client_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &sender_addr.sin_addr, 
                 client_ip, INET_ADDRSTRLEN);

        std::lock_guard<std::mutex> lock(clients_mutex);
        time_t current_time = time(nullptr);

        if (strncmp(buffer, "HEARTBEAT_RESPONSE", 18) == 0) {
            std::cout << "Received a multicast response" << std::endl;
            std::string client_id = buffer + 19;
            auto it = clients.find(client_id);
            if (it != clients.end()) {
                it->second.last_seen = current_time;
            } else {
                ClientInfo new_client{
                    client_id,
                    client_ip,
                    current_time,
                    ""
                };
                clients[client_id] = new_client;
                request_sysinfo(sock, new_client);
            }
        } else if (strncmp(buffer, "SYSINFO_RESPONSE", 16) == 0) {
            std::cout << "Received a sysinfo response" << std::endl;
            std::string client_id = buffer + 17;
            auto it = clients.find(client_id);
            if (it != clients.end()) {
                it->second.sysinfo = buffer + 17 + client_id.size() + 1;
            }
        }
    }
}

void check_clients(int sock) {
    while (true) {
        std::this_thread::sleep_for(std::chrono::seconds(3));
        time_t current_time = time(nullptr);
        
        std::lock_guard<std::mutex> lock(clients_mutex);
        for (auto& [id, client] : clients) {
            if (current_time - client.last_seen > CLIENT_TIMEOUT) {
                std::cout << "[!] Client offline: " << id << std::endl;
            } else if (client.sysinfo.empty()) {
                request_sysinfo(sock, client);
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

    sockaddr_in server_addr{};
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(RESPONSE_PORT);
    server_addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(sock, (sockaddr*)&server_addr, sizeof(server_addr))){
        perror("bind");
        return 1;
    }

    std::thread hb_thread(send_heartbeat, sock);
    std::thread recv_thread(process_responses, sock);
    std::thread check_thread(check_clients, sock);

    hb_thread.join();
    recv_thread.join();
    check_thread.join();

    close(sock);
    return 0;
}
#include "seed.hpp"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>
#include <iostream>
#include <fstream>
#include <thread>
#include <sstream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

SeedNode::SeedNode(const std::string& ip, int port) 
    : ip(ip), port(port), serverSocket(-1), running(false) {
    // Create output filename based on port
    outputFileName = "seed_" + std::to_string(port) + "_output.txt";
}

SeedNode::~SeedNode() {
    stop();
}

bool SeedNode::start() {
    // Create socket
    serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSocket < 0) {
        std::cerr << "Error creating socket" << std::endl;
        return false;
    }

    // Set socket options for reuse
    int opt = 1;
    if (setsockopt(serverSocket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        std::cerr << "Error setting socket options" << std::endl;
        return false;
    }

    // Configure server address
    struct sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(port);
    serverAddr.sin_addr.s_addr = INADDR_ANY;

    // Bind socket
    if (bind(serverSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) < 0) {
        std::cerr << "Error binding socket" << std::endl;
        return false;
    }

    // Listen for connections
    if (listen(serverSocket, 10) < 0) {
        std::cerr << "Error listening on socket" << std::endl;
        return false;
    }

    running = true;
    std::string startMsg = "Seed node started on port " + std::to_string(port);
    std::cout << startMsg << std::endl;
    logToFile(startMsg);

    // Accept connections in a loop
    while (running) {
        struct sockaddr_in clientAddr;
        socklen_t clientLen = sizeof(clientAddr);
        int clientSocket = accept(serverSocket, (struct sockaddr*)&clientAddr, &clientLen);

        if (clientSocket < 0) {
            if (running) {
                std::cerr << "Error accepting connection" << std::endl;
            }
            continue;
        }

        // Create new thread for each client
        std::thread clientThread(&SeedNode::handleClient, this, clientSocket);
        clientThread.detach();
    }

    return true;
}

void SeedNode::stop() {
    running = false;
    if (serverSocket != -1) {
        close(serverSocket);
        serverSocket = -1;
    }
}

void SeedNode::handleClient(int clientSocket) {
    char buffer[4096];
    std::string msg = "New client connection accepted";
    std::cout << msg << std::endl;
    logToFile(msg);

    while (running) {
        memset(buffer, 0, sizeof(buffer));
        ssize_t bytesRead = recv(clientSocket, buffer, sizeof(buffer) - 1, 0);

        if (bytesRead <= 0) {
            break;
        }

        try {
            json request = json::parse(buffer);
            
            if (request["type"] == "register") {
                // Handle peer registration
                PeerInfo newPeer{
                    request["ip"],
                    request["port"],
                    std::chrono::system_clock::now()
                };
                
                addPeer(newPeer);
                
                // Send peer list back to client
                json response;
                response["type"] = "peer_list";
                response["peers"] = getPeerList();
                std::string responseStr = response.dump();
                
                send(clientSocket, responseStr.c_str(), responseStr.length(), 0);
                
                std::string logMsg = "Registered new peer: " + newPeer.ip + ":" + std::to_string(newPeer.port);
                logToFile(logMsg);
            }
            else if (request["type"] == "dead_node") {
                // Handle dead node notification
                handleDeadNode(request["dead_ip"], request["dead_port"]);
                
                std::string logMsg = "Received dead node notification for: " + 
                                   std::string(request["dead_ip"]) + ":" + 
                                   std::to_string(static_cast<int>(request["dead_port"]));
                logToFile(logMsg);
            }
        }
        catch (const json::parse_error& e) {
            std::cerr << "JSON parsing error: " << e.what() << std::endl;
            logToFile("Error parsing client message: " + std::string(e.what()));
        }
        catch (const std::exception& e) {
            std::cerr << "Error handling client message: " << e.what() << std::endl;
            logToFile("Error handling client message: " + std::string(e.what()));
        }
    }

    close(clientSocket);
}

void SeedNode::addPeer(const PeerInfo& peer) {
    std::lock_guard<std::mutex> lock(peerListMutex);
    peerList[peer] = std::chrono::system_clock::now();
}

void SeedNode::handleDeadNode(const std::string& deadIP, int deadPort) {
    std::lock_guard<std::mutex> lock(peerListMutex);
    PeerInfo deadPeer{deadIP, deadPort, std::chrono::system_clock::now()};
    
    if (peerList.erase(deadPeer) > 0) {
        std::string msg = "Removed dead peer: " + deadIP + ":" + std::to_string(deadPort);
        std::cout << msg << std::endl;
        logToFile(msg);
    }
}

std::vector<PeerInfo> SeedNode::getPeerList() {
    std::lock_guard<std::mutex> lock(peerListMutex);
    std::vector<PeerInfo> peers;
    
    for (const auto& [peer, timestamp] : peerList) {
        peers.push_back(peer);
    }
    
    return peers;
}

void SeedNode::logToFile(const std::string& message) {
    std::ofstream outFile(outputFileName, std::ios::app);
    if (outFile.is_open()) {
        auto now = std::chrono::system_clock::now();
        auto now_c = std::chrono::system_clock::to_time_t(now);
        outFile << std::ctime(&now_c) << message << std::endl;
        outFile.close();
    }
}

std::string SeedNode::serializePeerList() {
    std::lock_guard<std::mutex> lock(peerListMutex);
    json j;
    std::vector<json> peerJsonList;
    
    for (const auto& [peer, timestamp] : peerList) {
        json peerJson;
        peerJson["ip"] = peer.ip;
        peerJson["port"] = peer.port;
        peerJsonList.push_back(peerJson);
    }
    
    j["peers"] = peerJsonList;
    return j.dump();
}
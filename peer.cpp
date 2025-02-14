#include "peer.hpp"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>
#include <iostream>
#include <fstream>
#include <sstream>
#include <random>
#include <algorithm>
#include <nlohmann/json.hpp>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <iomanip>

using json = nlohmann::json;

PeerNode::PeerNode(const std::string& ip, int port, const std::vector<PeerInfo>& seeds)
    : ip(ip), port(port), seedNodes(seeds), serverSocket(-1), running(false), messageCounter(0) {
    outputFileName = "peer_" + std::to_string(port) + "_output.txt";
}

PeerNode::~PeerNode() {
    stop();
}

bool PeerNode::start() {
    // Create server socket
    serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSocket < 0) {
        std::cerr << "Error creating socket" << std::endl;
        return false;
    }

    // Set socket options
    int opt = 1;
    if (setsockopt(serverSocket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        std::cerr << "Error setting socket options" << std::endl;
        return false;
    }

    // Bind socket
    struct sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(port);
    serverAddr.sin_addr.s_addr = INADDR_ANY;

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
    logToFile("Peer node started on port " + std::to_string(port));

    // Connect to seeds and get initial peer list
    int minSeeds = (seedNodes.size() / 2) + 1;
    int connectedSeeds = 0;

    for (const auto& seed : seedNodes) {
        if (connectToSeed(seed)) {
            connectedSeeds++;
            if (connectedSeeds >= minSeeds) break;
        }
    }

    if (connectedSeeds < minSeeds) {
        std::cerr << "Failed to connect to minimum required seeds" << std::endl;
        stop();
        return false;
    }

    // Start background threads
    std::thread pingThread(&PeerNode::pingLoop, this);
    std::thread messageThread(&PeerNode::messageGenerationLoop, this);
    pingThread.detach();
    messageThread.detach();

    // Accept incoming connections
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

        std::thread clientThread(&PeerNode::handleClient, this, clientSocket);
        clientThread.detach();
    }

    return true;
}

void PeerNode::stop() {
    running = false;
    
    // Close all peer connections
    {
        std::lock_guard<std::mutex> lock(peersMutex);
        for (const auto& [peer, socket] : connectedPeers) {
            close(socket);
        }
        connectedPeers.clear();
    }

    // Close server socket
    if (serverSocket != -1) {
        close(serverSocket);
        serverSocket = -1;
    }
}

void PeerNode::logToFile(const std::string& message) {
    std::lock_guard<std::mutex> lock(messageMutex);
    std::ofstream outFile(outputFileName, std::ios::app);
    if (outFile.is_open()) {
        auto now = std::chrono::system_clock::now();
        auto timestamp = std::chrono::system_clock::to_time_t(now);
        outFile << std::ctime(&timestamp) << ": " << message << std::endl;
    }
}

std::string PeerNode::calculateMessageHash(const Message& msg) {
    EVP_MD_CTX *mdctx;
    const EVP_MD *md;
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len;

    md = EVP_sha256();
    mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, md, nullptr);

    std::stringstream ms;
    ms << msg.content << msg.timestamp << msg.sourceIP;

    std::string str = ms.str();
    EVP_DigestUpdate(mdctx, str.c_str(), str.size());
    EVP_DigestFinal(mdctx, hash, &hash_len);
    EVP_MD_CTX_free(mdctx);

    std::stringstream ss;
    for(unsigned int i = 0; i < hash_len; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
    }

    return ss.str();
}

bool PeerNode::connectToSeed(const PeerInfo& seed) {
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) return false;

    struct sockaddr_in seedAddr;
    seedAddr.sin_family = AF_INET;
    seedAddr.sin_port = htons(seed.port);
    inet_pton(AF_INET, seed.ip.c_str(), &seedAddr.sin_addr);

    if (connect(sockfd, (struct sockaddr*)&seedAddr, sizeof(seedAddr)) < 0) {
        close(sockfd);
        return false;
    }

    // Register with seed
    json registration;
    registration["type"] = "register";
    registration["ip"] = ip;
    registration["port"] = port;
    std::string msg = registration.dump();
    
    if (send(sockfd, msg.c_str(), msg.length(), 0) < 0) {
        close(sockfd);
        return false;
    }

    // Get peer list from seed
    char buffer[4096];
    memset(buffer, 0, sizeof(buffer));
    ssize_t bytesRead = recv(sockfd, buffer, sizeof(buffer) - 1, 0);
    
    if (bytesRead > 0) {
        try {
            json response = json::parse(buffer);
            if (response["type"] == "peer_list") {
                std::vector<PeerInfo> peers;
                for (const auto& p : response["peers"]) {
                    peers.push_back({p["ip"], p["port"], std::chrono::system_clock::now()});
                }
                selectAndConnectPeers(peers);
            }
        }
        catch (const std::exception& e) {
            std::cerr << "Error parsing seed response: " << e.what() << std::endl;
            close(sockfd);
            return false;
        }
    }

    close(sockfd);
    return true;
}

void PeerNode::selectAndConnectPeers(const std::vector<PeerInfo>& peers) {
    std::random_device rd;
    std::mt19937 gen(rd());
    
    // Calculate number of peers to connect to using power law
    double alpha = 2.5; // Power law exponent
    std::uniform_real_distribution<> dis(0, 1);
    int numPeers = std::min(static_cast<int>(peers.size()), 
                           static_cast<int>(peers.size() * std::pow(dis(gen), 1/alpha)));

    std::vector<PeerInfo> shuffledPeers = peers;
    std::shuffle(shuffledPeers.begin(), shuffledPeers.end(), gen);

    for (size_t i = 0; i < static_cast<size_t>(numPeers) && i < shuffledPeers.size(); ++i) {
        const auto& peer = shuffledPeers[i];
        
        if (peer.ip == ip && peer.port == port) continue;

        int sockfd = socket(AF_INET, SOCK_STREAM, 0);
        if (sockfd < 0) continue;

        struct sockaddr_in peerAddr;
        peerAddr.sin_family = AF_INET;
        peerAddr.sin_port = htons(peer.port);
        inet_pton(AF_INET, peer.ip.c_str(), &peerAddr.sin_addr);

        if (connect(sockfd, (struct sockaddr*)&peerAddr, sizeof(peerAddr)) >= 0) {
            std::lock_guard<std::mutex> lock(peersMutex);
            connectedPeers[{peer.ip, peer.port}] = sockfd;
            
            // Initialize ping status for new peer
            std::lock_guard<std::mutex> pingLock(pingMutex);
            pingStatus[{peer.ip, peer.port}] = {0, std::chrono::system_clock::now()};
            
            logToFile("Connected to peer: " + peer.ip + ":" + std::to_string(peer.port));
        } else {
            close(sockfd);
        }
    }
}

void PeerNode::handleClient(int clientSocket) {
    char buffer[4096];
    
    while (running) {
        memset(buffer, 0, sizeof(buffer));
        ssize_t bytesRead = recv(clientSocket, buffer, sizeof(buffer) - 1, 0);

        if (bytesRead <= 0) break;

        try {
            json message = json::parse(buffer);
            
            if (message["type"] == "gossip") {
                Message msg {
                    message["content"],
                    message["timestamp"],
                    message["source_ip"],
                    message["source_port"],
                    message["msg_number"],
                    message["hash"]
                };

                std::string msgHash = calculateMessageHash(msg);
                
                {
                    std::lock_guard<std::mutex> lock(messageMutex);
                    if (messageList.find(msgHash) == messageList.end()) {
                        messageList[msgHash] = {msg, {}};
                        logToFile("Received new message: " + msg.content);
                        broadcastMessage(msg, clientSocket);
                    }
                }
            }
        }
        catch (const std::exception& e) {
            std::cerr << "Error handling client message: " << e.what() << std::endl;
        }
    }

    close(clientSocket);
}

void PeerNode::broadcastMessage(const Message& msg, int excludeSocket) {
    json message;
    message["type"] = "gossip";
    message["content"] = msg.content;
    message["timestamp"] = msg.timestamp;
    message["source_ip"] = msg.sourceIP;
    message["source_port"] = msg.sourcePort;
    message["msg_number"] = msg.msgNumber;
    message["hash"] = msg.hash;

    std::string messageStr = message.dump();

    std::lock_guard<std::mutex> lock(peersMutex);
    for (const auto& [peer, socket] : connectedPeers) {
        if (socket != excludeSocket) {
            if (send(socket, messageStr.c_str(), messageStr.length(), 0) > 0) {
                std::lock_guard<std::mutex> msgLock(messageMutex);
                messageList[msg.hash].sentTo.insert(peer);
            }
        }
    }
}

void PeerNode::pingLoop() {
    while (running) {
        std::vector<std::pair<std::string, int>> deadPeers;

        {
            std::lock_guard<std::mutex> lock(pingMutex);
            auto now = std::chrono::system_clock::now();
            
            for (auto& [peer, status] : pingStatus) {
                if (std::chrono::duration_cast<std::chrono::seconds>(
                    now - status.lastPing).count() >= 13) {
                    
                    std::string pingCmd = "ping -c 1 -W 1 " + peer.first + " > /dev/null 2>&1";
                    int result = system(pingCmd.c_str());

                    if (result != 0) {
                        status.failedAttempts++;
                        if (status.failedAttempts >= 3) {
                            deadPeers.push_back(peer);
                        }
                    } else {
                        status.failedAttempts = 0;
                    }
                    
                    status.lastPing = now;
                }
            }
        }

        for (const auto& peer : deadPeers) {
            handleDeadPeer(peer.first, peer.second);
        }

        std::this_thread::sleep_for(std::chrono::seconds(5));
    }
}

void PeerNode::messageGenerationLoop() {
    while (running && messageCounter < 10) {
        Message msg {
            "Message from " + ip + ":" + std::to_string(port),
            std::to_string(std::chrono::system_clock::now().time_since_epoch().count()),
            ip,
            port,
            messageCounter++,
            ""
        };
        msg.hash = calculateMessageHash(msg);

        {
            std::lock_guard<std::mutex> lock(messageMutex);
            messageList[msg.hash] = {msg, {}};
        }

        broadcastMessage(msg);
        logToFile("Generated message: " + msg.content);

        std::this_thread::sleep_for(std::chrono::seconds(5));
    }
}

void PeerNode::handleDeadPeer(const std::string& deadIP, int deadPort) {
    // Remove from connected peers
    {
        std::lock_guard<std::mutex> lock(peersMutex);
        auto it = connectedPeers.find({deadIP, deadPort});
        if (it != connectedPeers.end()) {
            close(it->second);
            connectedPeers.erase(it);
            logToFile("Peer disconnected: " + deadIP + ":" + std::to_string(deadPort));
        }
    }

    // Remove from ping status
    {
        std::lock_guard<std::mutex> lock(pingMutex);
        pingStatus.erase({deadIP, deadPort});
    }

    // Try to find new peers from remaining seeds
    for (const auto& seed : seedNodes) {
        if (seed.ip != deadIP || seed.port != deadPort) {
            connectToSeed(seed);
        }
    }
}
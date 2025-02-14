#pragma once
#include <string>
#include <vector>
#include <unordered_map>
#include <mutex>
#include <queue>
#include <set>
#include <thread>
#include <condition_variable>
#include <chrono>
#include <utility>
#include "seed.hpp"  // For PeerInfo struct

struct Message {
    std::string content;
    std::string timestamp;
    std::string sourceIP;
    int sourcePort;
    int msgNumber;
    std::string hash;
};

struct MessageTracker {
    Message msg;
    std::set<std::pair<std::string, int>> sentTo;  // IP, port pairs
};

struct PairHash {
    template <class T1, class T2>
    std::size_t operator()(const std::pair<T1, T2>& pair) const {
        // Combine the hashes of both elements
        return std::hash<T1>()(pair.first) ^ 
               (std::hash<T2>()(pair.second) << 1);
    }
};

class PeerNode {
private:
    // Basic info
    std::string ip;
    int port;
    std::vector<PeerInfo> seedNodes;
    int serverSocket;
    bool running;
    std::string outputFileName;

    // Connection management
    std::unordered_map<std::pair<std::string, int>, int, PairHash> connectedPeers;  // (IP, port) -> socket
    std::mutex peersMutex;
    
    // Message management
    std::unordered_map<std::string, MessageTracker> messageList;  // hash -> MessageTracker
    std::mutex messageMutex;
    int messageCounter;
    
    // Ping management
    struct PingStatus {
        int failedAttempts;
        std::chrono::system_clock::time_point lastPing;
    };
    std::unordered_map<std::pair<std::string, int>, PingStatus, PairHash> pingStatus;
    std::mutex pingMutex;

    // Private member functions
    void handleClient(int clientSocket);
    void logToFile(const std::string& message);
    bool connectToSeed(const PeerInfo& seed);
    void selectAndConnectPeers(const std::vector<PeerInfo>& peers);
    std::string calculateMessageHash(const Message& msg);
    void broadcastMessage(const Message& msg, int excludeSocket = -1);
    void pingLoop();
    void messageGenerationLoop();
    void handleDeadPeer(const std::string& ip, int port);

public:
    PeerNode(const std::string& ip, int port, const std::vector<PeerInfo>& seeds);
    ~PeerNode();

    bool start();
    void stop();
    bool isRunning() const { return running; }
};
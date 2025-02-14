#pragma once
#include "info.hpp"
#include<string>
#include<vector>
#include<unordered_map>
#include<mutex>
#include<chrono>

class SeedNode {
private:
    std::string ip;
    int port;
    int serverSocket;
    std::unordered_map<PeerInfo, std::chrono::system_clock::time_point, PeerInfoHash> peerList;
    std::mutex peerListMutex;
    bool running;
    std::string outputFileName;

    void handleClient(int clientSocket);
    void logToFile(const std::string& message);
    std::string serializePeerList();
    void removePeer(const PeerInfo& peer);

public:
    SeedNode(const std::string& ip, int port);
    ~SeedNode();

    bool start();
    void stop();

    void addPeer(const PeerInfo& peer);
    void handleDeadNode(const std::string& deadIP, int deadPort);
    std::vector<PeerInfo> getPeerList();
};

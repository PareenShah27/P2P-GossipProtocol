#pragma once
#include "peer.hpp"
#include "config.hpp"
#include <memory>
#include <string>

class Peer {
public:
    Peer(const std::string& configFile);
    ~Peer();

    void start();
    void stop();
    bool isRunning() const;

private:
    std::unique_ptr<PeerNode> node;
    NetworkConfig config;  
};
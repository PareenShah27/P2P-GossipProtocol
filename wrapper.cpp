#include "wrapper.hpp"

Peer::Peer(const std::string& configFile) : config(configFile) {
    // Create PeerNode with configuration
    std::vector<PeerInfo> seedPeers;
    for (const auto& peernode : config.getSeedNodes()) {
        seedPeers.push_back({peernode.ip, peernode.port});
    }
    
    node = std::make_unique<PeerNode>(
        config.getLocalIP(),
        config.getLocalPort(),
        seedPeers
    );
}

Peer::~Peer() {
    stop();
}

void Peer::start() {
    if (node) {
        node->start();
    }
}

void Peer::stop() {
    if (node) {
        node->stop();
    }
}

bool Peer::isRunning() const {
    return node && node->isRunning();
}
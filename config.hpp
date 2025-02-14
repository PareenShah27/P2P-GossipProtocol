#pragma once

#include <string>
#include <vector>
#include <stdexcept>

class NetworkConfig {
public:
    struct NodeInfo {
        std::string ip;
        int port;


        NodeInfo();
        NodeInfo(const std::string& ip, int port);
        bool operator==(const NodeInfo& other) const;
        std::string toString() const;
    };

    class ConfigException : public std::runtime_error {
    public:
        explicit ConfigException(const std::string& message);
    };

    NetworkConfig(const std::string& configPath);

    // Getters
    const std::vector<NodeInfo>& getSeedNodes() const;
    std::string getLocalIP() const;
    int getLocalPort() const;
    int getMinRequiredSeeds() const;
    int getPingInterval() const;
    int getMessageInterval() const;
    int getMaxMessages() const;
    int getMaxMissedPings() const;

    // Utility functions
    std::vector<NodeInfo> getRandomSeeds(int count) const;
    std::string toString() const;

private:
    std::string configFilePath;
    std::vector<NodeInfo> seedNodes;
    int minConnectionCount;
    int pingIntervalSecs;
    int messageIntervalSecs;
    int maxMessageCount;
    int maxMissedPings;
    std::string localIP;
    int localPort;

    void loadConfig();
    void parseLine(const std::string& line, int lineNumber);
    void validateConfig();
    static bool isValidIPAddress(const std::string& ip);
    static bool isValidPort(int port);
};


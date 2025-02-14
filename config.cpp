#include "config.hpp"
#include <fstream>
#include <sstream>
#include <algorithm>
#include <random>
#include <arpa/inet.h>

// Helper function to trim whitespace from strings
static inline std::string trim(const std::string& str) {
    const auto start = str.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) return "";
    const auto end = str.find_last_not_of(" \t\r\n");
    return str.substr(start, end - start + 1);
}

NetworkConfig::NodeInfo::NodeInfo(): ip(""), port(0) {}

NetworkConfig::NodeInfo::NodeInfo(const std::string& ip, int port) : ip(ip), port(port) {}

bool NetworkConfig::NodeInfo::operator==(const NodeInfo& other) const {
    return ip == other.ip && port == other.port;
}

std::string NetworkConfig::NodeInfo::toString() const {
    return ip + ":" + std::to_string(port);
}

NetworkConfig::ConfigException::ConfigException(const std::string& message)
    : std::runtime_error("Configuration Error: " + message) {}

NetworkConfig::NetworkConfig(const std::string& configPath)
    : configFilePath(configPath),
      minConnectionCount(0),
      pingIntervalSecs(13),
      messageIntervalSecs(5),
      maxMessageCount(10),
      maxMissedPings(3),
      localIP("192.168.99.96"),
      localPort(5000) {
    loadConfig();
    validateConfig();
}

const std::vector<NetworkConfig::NodeInfo>& NetworkConfig::getSeedNodes() const { return seedNodes; }
std::string NetworkConfig::getLocalIP() const { return localIP; }
int NetworkConfig::getLocalPort() const { return localPort; }
int NetworkConfig::getMinRequiredSeeds() const { return minConnectionCount; }
int NetworkConfig::getPingInterval() const { return pingIntervalSecs; }
int NetworkConfig::getMessageInterval() const { return messageIntervalSecs; }
int NetworkConfig::getMaxMessages() const { return maxMessageCount; }
int NetworkConfig::getMaxMissedPings() const { return maxMissedPings; }

void NetworkConfig::loadConfig() {
    std::ifstream file(configFilePath);
    if (!file.is_open()) {
        throw ConfigException("Unable to open config file: " + configFilePath);
    }

    std::string line;
    int lineNumber = 0;
    while (std::getline(file, line)) {
        lineNumber++;
        line = trim(line);
        if (line.empty() || line[0] == '#') continue;

        try {
            parseLine(line, lineNumber);
        } catch (const ConfigException& e) {
            throw ConfigException("Error at line " + std::to_string(lineNumber) + ": " + e.what());
        }
    }

    if (seedNodes.empty()) {
        throw ConfigException("No valid seed nodes found in configuration");
    }
    minConnectionCount = (seedNodes.size() / 2) + 1;
}

void NetworkConfig::parseLine(const std::string& line, int lineNumber) {
    std::istringstream iss(line);
    std::string key, value;
    
    if (line.find('=') != std::string::npos) {
        std::getline(iss, key, '=');
        std::getline(iss, value);
        key = trim(key);
        value = trim(value);
        
        if (key.empty() || value.empty()) {
            throw ConfigException("Invalid configuration format");
        }

        if (key == "ping_interval") pingIntervalSecs = std::stoi(value);
        else if (key == "message_interval") messageIntervalSecs = std::stoi(value);
        else if (key == "max_messages") maxMessageCount = std::stoi(value);
        else if (key == "max_missed_pings") maxMissedPings = std::stoi(value);
    } else {
        std::string ip, portStr;
        if (std::getline(iss, ip, ':') && std::getline(iss, portStr)) {
            ip = trim(ip);
            portStr = trim(portStr);
            
            if (!isValidIPAddress(ip)) {
                throw ConfigException("Invalid IP address: " + ip);
            }

            try {
                int port = std::stoi(portStr);
                if (!isValidPort(port)) {
                    throw ConfigException("Invalid port number: " + portStr);
                }
                seedNodes.emplace_back(ip, port);
            } catch (const std::exception& e) {
                throw ConfigException("Invalid port format: " + portStr);
            }
        } else {
            throw ConfigException("Invalid seed node format");
        }
    }
}

void NetworkConfig::validateConfig() {
    if (pingIntervalSecs <= 0) throw ConfigException("Ping interval must be positive");
    if (messageIntervalSecs <= 0) throw ConfigException("Message interval must be positive");
    if (maxMessageCount <= 0) throw ConfigException("Maximum message count must be positive");
    if (maxMissedPings <= 0) throw ConfigException("Maximum missed pings must be positive");

    for (const auto& node : seedNodes) {
        if (!isValidIPAddress(node.ip) || !isValidPort(node.port)) {
            throw ConfigException("Invalid seed node configuration: " + node.toString());
        }
    }

    std::vector<NodeInfo> sortedNodes = seedNodes;
    std::sort(sortedNodes.begin(), sortedNodes.end(),
        [](const NodeInfo& a, const NodeInfo& b) {
            return (a.ip < b.ip) || (a.ip == b.ip && a.port < b.port);
        });
    auto it = std::unique(sortedNodes.begin(), sortedNodes.end());
    if (it != sortedNodes.end()) {
        throw ConfigException("Duplicate seed nodes found in configuration");
    }
}

bool NetworkConfig::isValidIPAddress(const std::string& ip) {
    struct sockaddr_in sa;
    return inet_pton(AF_INET, ip.c_str(), &(sa.sin_addr)) == 1;
}

bool NetworkConfig::isValidPort(int port) {
    return port > 0 && port < 65536;
}

std::vector<NetworkConfig::NodeInfo> NetworkConfig::getRandomSeeds(int count) const {
    if (count > static_cast<int>(seedNodes.size())) {
        throw ConfigException("Requested more seeds than available");
    }

    std::vector<NodeInfo> result = seedNodes;
    std::random_device rd;
    std::mt19937 gen(rd());
    std::shuffle(result.begin(), result.end(), gen);
    result.resize(count);
    return result;
}

std::string NetworkConfig::toString() const {
    std::ostringstream oss;
    oss << "Network Configuration:\n";
    oss << "----------------------\n";
    oss << "Seed Nodes (" << seedNodes.size() << "):\n";
    for (const auto& node : seedNodes) {
        oss << " " << node.toString() << "\n";
    }
    oss << "Minimum Required Seeds: " << minConnectionCount << "\n";
    oss << "Network Parameters:\n";
    oss << " Ping Interval: " << pingIntervalSecs << " seconds\n";
    oss << " Message Interval: " << messageIntervalSecs << " seconds\n";
    oss << " Max Messages: " << maxMessageCount << "\n";
    oss << " Max Missed Pings: " << maxMissedPings << "\n";
    return oss.str();
}

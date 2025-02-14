#pragma once
#include <nlohmann/json.hpp>
#include <chrono>
#include <string>

struct PeerInfo {
    std::string ip;
    int port;
    std::chrono::system_clock::time_point lastSeen;

    bool operator==(const PeerInfo& other) const {
        return ip == other.ip && port == other.port;
    }
};

struct PeerInfoHash {
    size_t operator()(const PeerInfo& p) const {
        return std::hash<std::string>()(p.ip) ^ std::hash<int>()(p.port);
    }
};

// Add this to enable JSON serialization of PeerInfo
namespace nlohmann {
    template <>
    struct adl_serializer<PeerInfo> {
        static void to_json(json& j, const PeerInfo& p) {
            j = json{
                {"ip", p.ip},
                {"port", p.port},
                {"lastSeen", std::chrono::system_clock::to_time_t(p.lastSeen)}
            };
        }

        static void from_json(const json& j, PeerInfo& p) {
            p.ip = j.at("ip").get<std::string>();
            p.port = j.at("port").get<int>();
            p.lastSeen = std::chrono::system_clock::from_time_t(j.at("lastSeen").get<time_t>());
        }
    };
}
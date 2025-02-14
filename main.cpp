#include "peer.hpp"
#include "config.hpp"
#include "wrapper.hpp"
#include <iostream>
#include <csignal>
#include <cstdlib>
#include <ctime>
#include <string>
#include <memory>

std::unique_ptr<Peer> globalPeer;
bool shouldExit = false;

void signalHandler(int signum) {
    std::cout << "\nReceived signal " << signum << std::endl;
    std::cout << "Initiating graceful shutdown..." << std::endl;
    shouldExit = true;
    
    if (globalPeer) {
        globalPeer->stop();
    }
}

void printUsage(const char* programName) {
    std::cout << "Usage: " << programName << " <config_file>" << std::endl;
    std::cout << "Example: " << programName << " config.txt" << std::endl;
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Error: Invalid number of arguments" << std::endl;
        printUsage(argv[0]);
        return 1;
    }

    signal(SIGINT, signalHandler);
    signal(SIGTERM, signalHandler);

    try {
        srand(time(nullptr));

        std::cout << "Initializing peer node..." << std::endl;
        std::string configFile = argv[1];
        
        try {
            NetworkConfig config(configFile);
            std::cout << "Configuration loaded successfully:" << std::endl;
            std::cout << config.toString() << std::endl;
        } catch (const NetworkConfig::ConfigException& e) {
            std::cerr << "Configuration error: " << e.what() << std::endl;
            return 1;
        }

        globalPeer = std::make_unique<Peer>(configFile);
        
        std::cout << "Starting peer node..." << std::endl;
        globalPeer->start();

        while (!shouldExit) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }

        std::cout << "Shutting down peer node..." << std::endl;
        globalPeer->stop();
        globalPeer.reset();

        std::cout << "Peer node shutdown complete" << std::endl;
        return 0;

    } catch (const std::exception& e) {
        std::cerr << "Fatal error: " << e.what() << std::endl;
        if (globalPeer) {
            globalPeer->stop();
            globalPeer.reset();
        }
        return 1;
    }
}
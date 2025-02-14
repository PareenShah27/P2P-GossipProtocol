# Compiler and flags
CXX = g++
CXXFLAGS = -Wall -std=c++17 -pthread -I./headers -I/usr/include/openssl
LDFLAGS = -lssl -lcrypto

# Source files and object files
SRC_DIR = src
SOURCES = $(wildcard $(SRC_DIR)/*.cpp)
OBJECTS = $(SOURCES:$(SRC_DIR)/%.cpp=%.o)

# Output executable name
EXECUTABLE = peer_network

# Default target
all: $(EXECUTABLE)

# Rule to build the final executable
$(EXECUTABLE): $(OBJECTS)
	$(CXX) $(CXXFLAGS) $(OBJECTS) -o $@ $(LDFLAGS)

# Rule to compile source files into object files
%.o: $(SRC_DIR)/%.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

# Clean up build artifacts
clean:
	rm -f $(OBJECTS) $(EXECUTABLE)

# Phony targets
.PHONY: all clean

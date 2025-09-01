CXX = g++
CXXFLAGS = -std=c++17 -O3 -Wall -Wextra -pthread
LIBS = -lssl -lcrypto
TARGET = xillen_hash_cracker
SOURCE = hash_cracker.cpp

all: $(TARGET)

$(TARGET): $(SOURCE)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(SOURCE) $(LIBS)

debug: CXXFLAGS += -g -DDEBUG
debug: $(TARGET)

release: CXXFLAGS += -DNDEBUG
release: $(TARGET)

clean:
	rm -f $(TARGET)

install: $(TARGET)
	sudo cp $(TARGET) /usr/local/bin/

uninstall:
	sudo rm -f /usr/local/bin/$(TARGET)

.PHONY: all debug release clean install uninstall


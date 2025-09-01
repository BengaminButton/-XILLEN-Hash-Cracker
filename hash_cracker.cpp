#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <map>
#include <chrono>
#include <thread>
#include <mutex>
#include <algorithm>
#include <iomanip>
#include <sstream>
#include <cstring>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <openssl/evp.h>

class XillenHashCracker {
private:
    std::map<std::string, std::string> rainbow_table;
    std::vector<std::string> wordlist;
    std::mutex mtx;
    bool verbose;
    int threads;
    
public:
    XillenHashCracker() : verbose(false), threads(std::thread::hardware_concurrency()) {
        std::cout << "╔══════════════════════════════════════════════════════════════╗" << std::endl;
        std::cout << "║                    XILLEN Hash Cracker                     ║" << std::endl;
        std::cout << "║                        v2.0 by @Bengamin_Button            ║" << std::endl;
        std::cout << "╚══════════════════════════════════════════════════════════════╝" << std::endl;
        std::cout << std::endl;
    }
    
    void setVerbose(bool v) { verbose = v; }
    void setThreads(int t) { threads = t; }
    
    std::string calculateMD5(const std::string& input) {
        unsigned char digest[MD5_DIGEST_LENGTH];
        MD5_CTX ctx;
        MD5_Init(&ctx);
        MD5_Update(&ctx, input.c_str(), input.length());
        MD5_Final(digest, &ctx);
        
        std::stringstream ss;
        for(int i = 0; i < MD5_DIGEST_LENGTH; i++) {
            ss << std::hex << std::setw(2) << std::setfill('0') << (int)digest[i];
        }
        return ss.str();
    }
    
    std::string calculateSHA1(const std::string& input) {
        unsigned char digest[SHA_DIGEST_LENGTH];
        SHA_CTX ctx;
        SHA1_Init(&ctx);
        SHA1_Update(&ctx, input.c_str(), input.length());
        SHA1_Final(digest, &ctx);
        
        std::stringstream ss;
        for(int i = 0; i < SHA_DIGEST_LENGTH; i++) {
            ss << std::hex << std::setw(2) << std::setfill('0') << (int)digest[i];
        }
        return ss.str();
    }
    
    std::string calculateSHA256(const std::string& input) {
        unsigned char digest[SHA256_DIGEST_LENGTH];
        SHA256_CTX ctx;
        SHA256_Init(&ctx);
        SHA256_Update(&ctx, input.c_str(), input.length());
        SHA256_Final(digest, &ctx);
        
        std::stringstream ss;
        for(int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
            ss << std::hex << std::setw(2) << std::setfill('0') << (int)digest[i];
        }
        return ss.str();
    }
    
    std::string calculateHash(const std::string& input, const std::string& algorithm) {
        if (algorithm == "md5") return calculateMD5(input);
        if (algorithm == "sha1") return calculateSHA1(input);
        if (algorithm == "sha256") return calculateSHA256(input);
        return "";
    }
    
    bool loadWordlist(const std::string& filename) {
        std::ifstream file(filename);
        if (!file.is_open()) {
            std::cerr << "Error: Cannot open wordlist file: " << filename << std::endl;
            return false;
        }
        
        std::string line;
        while (std::getline(file, line)) {
            if (!line.empty()) {
                wordlist.push_back(line);
            }
        }
        file.close();
        
        std::cout << "Loaded " << wordlist.size() << " words from wordlist" << std::endl;
        return true;
    }
    
    void generateRainbowTable(const std::string& algorithm, int maxLength = 8) {
        std::cout << "Generating rainbow table for " << algorithm << "..." << std::endl;
        
        std::vector<std::string> charset = {"abcdefghijklmnopqrstuvwxyz0123456789"};
        std::string current;
        
        auto start = std::chrono::high_resolution_clock::now();
        int count = 0;
        
        for (int len = 1; len <= maxLength; len++) {
            generateCombinations(charset, current, len, algorithm, count);
        }
        
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::seconds>(end - start);
        
        std::cout << "Rainbow table generated: " << rainbow_table.size() << " entries in " 
                  << duration.count() << " seconds" << std::endl;
    }
    
    void generateCombinations(const std::vector<std::string>& charset, std::string& current, 
                            int length, const std::string& algorithm, int& count) {
        if (current.length() == length) {
            std::string hash = calculateHash(current, algorithm);
            rainbow_table[hash] = current;
            count++;
            
            if (count % 10000 == 0 && verbose) {
                std::cout << "Generated " << count << " hashes..." << std::endl;
            }
            return;
        }
        
        for (char c : charset[0]) {
            current += c;
            generateCombinations(charset, current, length, algorithm, count);
            current.pop_back();
        }
    }
    
    std::string crackHash(const std::string& targetHash, const std::string& algorithm) {
        std::cout << "Attempting to crack " << algorithm << " hash: " << targetHash << std::endl;
        
        auto start = std::chrono::high_resolution_clock::now();
        
        if (rainbow_table.find(targetHash) != rainbow_table.end()) {
            auto end = std::chrono::high_resolution_clock::now();
            auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
            std::cout << "Hash found in rainbow table in " << duration.count() << " ms" << std::endl;
            return rainbow_table[targetHash];
        }
        
        std::cout << "Hash not found in rainbow table, trying wordlist attack..." << std::endl;
        
        std::vector<std::thread> threadPool;
        std::string result = "";
        std::mutex resultMutex;
        
        int wordsPerThread = wordlist.size() / threads;
        
        for (int i = 0; i < threads; i++) {
            int startIdx = i * wordsPerThread;
            int endIdx = (i == threads - 1) ? wordlist.size() : (i + 1) * wordsPerThread;
            
            threadPool.emplace_back([this, &targetHash, &algorithm, &result, &resultMutex, startIdx, endIdx]() {
                for (int j = startIdx; j < endIdx && result.empty(); j++) {
                    std::string hash = calculateHash(wordlist[j], algorithm);
                    if (hash == targetHash) {
                        std::lock_guard<std::mutex> lock(resultMutex);
                        if (result.empty()) {
                            result = wordlist[j];
                        }
                        break;
                    }
                }
            });
        }
        
        for (auto& thread : threadPool) {
            thread.join();
        }
        
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
        
        if (!result.empty()) {
            std::cout << "Hash cracked in " << duration.count() << " ms" << std::endl;
            return result;
        } else {
            std::cout << "Hash not found after " << duration.count() << " ms" << std::endl;
            return "";
        }
    }
    
    void dictionaryAttack(const std::string& targetHash, const std::string& algorithm) {
        std::cout << "Starting dictionary attack..." << std::endl;
        
        auto start = std::chrono::high_resolution_clock::now();
        int count = 0;
        
        for (const auto& word : wordlist) {
            count++;
            if (count % 10000 == 0 && verbose) {
                std::cout << "Tried " << count << " words..." << std::endl;
            }
            
            std::string hash = calculateHash(word, algorithm);
            if (hash == targetHash) {
                auto end = std::chrono::high_resolution_clock::now();
                auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
                
                std::cout << "Hash cracked: " << word << " in " << duration.count() << " ms" << std::endl;
                return;
            }
        }
        
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
        std::cout << "Hash not found after trying " << count << " words in " << duration.count() << " ms" << std::endl;
    }
    
    void bruteforceAttack(const std::string& targetHash, const std::string& algorithm, int maxLength = 8) {
        std::cout << "Starting bruteforce attack (max length: " << maxLength << ")..." << std::endl;
        
        std::string charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()";
        std::string current;
        int count = 0;
        
        auto start = std::chrono::high_resolution_clock::now();
        
        for (int len = 1; len <= maxLength; len++) {
            if (bruteforceRecursive(charset, current, len, targetHash, algorithm, count, start)) {
                return;
            }
        }
        
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
        std::cout << "Hash not found after trying " << count << " combinations in " << duration.count() << " ms" << std::endl;
    }
    
    bool bruteforceRecursive(const std::string& charset, std::string& current, int length, 
                           const std::string& targetHash, const std::string& algorithm, 
                           int& count, const std::chrono::high_resolution_clock::time_point& start) {
        if (current.length() == length) {
            count++;
            if (count % 100000 == 0 && verbose) {
                auto now = std::chrono::high_resolution_clock::now();
                auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(now - start);
                std::cout << "Tried " << count << " combinations in " << duration.count() << " ms..." << std::endl;
            }
            
            std::string hash = calculateHash(current, algorithm);
            if (hash == targetHash) {
                auto end = std::chrono::high_resolution_clock::now();
                auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
                
                std::cout << "Hash cracked: " << current << " in " << duration.count() << " ms" << std::endl;
                return true;
            }
            return false;
        }
        
        for (char c : charset) {
            current += c;
            if (bruteforceRecursive(charset, current, length, targetHash, algorithm, count, start)) {
                return true;
            }
            current.pop_back();
        }
        return false;
    }
    
    void saveRainbowTable(const std::string& filename) {
        std::ofstream file(filename);
        if (!file.is_open()) {
            std::cerr << "Error: Cannot create file: " << filename << std::endl;
            return;
        }
        
        for (const auto& entry : rainbow_table) {
            file << entry.first << ":" << entry.second << std::endl;
        }
        file.close();
        
        std::cout << "Rainbow table saved to: " << filename << std::endl;
    }
    
    void loadRainbowTable(const std::string& filename) {
        std::ifstream file(filename);
        if (!file.is_open()) {
            std::cerr << "Error: Cannot open file: " << filename << std::endl;
            return;
        }
        
        rainbow_table.clear();
        std::string line;
        while (std::getline(file, line)) {
            size_t pos = line.find(':');
            if (pos != std::string::npos) {
                std::string hash = line.substr(0, pos);
                std::string plaintext = line.substr(pos + 1);
                rainbow_table[hash] = plaintext;
            }
        }
        file.close();
        
        std::cout << "Loaded " << rainbow_table.size() << " entries from rainbow table" << std::endl;
    }
    
    void showMenu() {
        std::cout << "\n=== XILLEN Hash Cracker Menu ===" << std::endl;
        std::cout << "1. Load wordlist" << std::endl;
        std::cout << "2. Generate rainbow table" << std::endl;
        std::cout << "3. Crack hash" << std::endl;
        std::cout << "4. Dictionary attack" << std::endl;
        std::cout << "5. Bruteforce attack" << std::endl;
        std::cout << "6. Save rainbow table" << std::endl;
        std::cout << "7. Load rainbow table" << std::endl;
        std::cout << "8. Set threads (" << threads << ")" << std::endl;
        std::cout << "9. Toggle verbose (" << (verbose ? "ON" : "OFF") << ")" << std::endl;
        std::cout << "0. Exit" << std::endl;
        std::cout << "Choice: ";
    }
    
    void run() {
        std::string choice;
        
        while (true) {
            showMenu();
            std::cin >> choice;
            
            if (choice == "1") {
                std::string filename;
                std::cout << "Enter wordlist filename: ";
                std::cin >> filename;
                loadWordlist(filename);
            }
            else if (choice == "2") {
                std::string algorithm;
                int maxLength;
                std::cout << "Enter algorithm (md5/sha1/sha256): ";
                std::cin >> algorithm;
                std::cout << "Enter max length for rainbow table: ";
                std::cin >> maxLength;
                generateRainbowTable(algorithm, maxLength);
            }
            else if (choice == "3") {
                std::string hash, algorithm;
                std::cout << "Enter hash to crack: ";
                std::cin >> hash;
                std::cout << "Enter algorithm (md5/sha1/sha256): ";
                std::cin >> algorithm;
                std::string result = crackHash(hash, algorithm);
                if (!result.empty()) {
                    std::cout << "Cracked: " << result << std::endl;
                }
            }
            else if (choice == "4") {
                std::string hash, algorithm;
                std::cout << "Enter hash to crack: ";
                std::cin >> hash;
                std::cout << "Enter algorithm (md5/sha1/sha256): ";
                std::cin >> algorithm;
                dictionaryAttack(hash, algorithm);
            }
            else if (choice == "5") {
                std::string hash, algorithm;
                int maxLength;
                std::cout << "Enter hash to crack: ";
                std::cin >> hash;
                std::cout << "Enter algorithm (md5/sha1/sha256): ";
                std::cin >> algorithm;
                std::cout << "Enter max length for bruteforce: ";
                std::cin >> maxLength;
                bruteforceAttack(hash, algorithm, maxLength);
            }
            else if (choice == "6") {
                std::string filename;
                std::cout << "Enter filename to save: ";
                std::cin >> filename;
                saveRainbowTable(filename);
            }
            else if (choice == "7") {
                std::string filename;
                std::cout << "Enter filename to load: ";
                std::cin >> filename;
                loadRainbowTable(filename);
            }
            else if (choice == "8") {
                std::cout << "Enter number of threads: ";
                std::cin >> threads;
                if (threads <= 0) threads = std::thread::hardware_concurrency();
                std::cout << "Threads set to: " << threads << std::endl;
            }
            else if (choice == "9") {
                verbose = !verbose;
                std::cout << "Verbose mode: " << (verbose ? "ON" : "OFF") << std::endl;
            }
            else if (choice == "0") {
                std::cout << "Goodbye!" << std::endl;
                break;
            }
            else {
                std::cout << "Invalid choice!" << std::endl;
            }
        }
    }
};

int main() {
    XillenHashCracker cracker;
    cracker.run();
    return 0;
}


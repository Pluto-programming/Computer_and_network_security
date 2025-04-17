#include <set>
#include <string>
#include <iostream>
#include "attack_detection.h"
#include <algorithm>

static std::set<std::string> used_nonces;

bool detect_replay_or_reuse(const std::string& nonce) {
    if (used_nonces.find(nonce) != used_nonces.end()) {
        std::cerr << "Attack Detected: Nonce replay/reuse attempt." << std::endl;
        return true;
    }
    used_nonces.insert(nonce);
    return false;
}

bool detect_attack(const std::string& msg) {
    // Very basic check: flag message if it contains "ATTACK" (case-insensitive)
    std::string lower_msg = msg;
    std::transform(lower_msg.begin(), lower_msg.end(), lower_msg.begin(), ::tolower);
    return lower_msg.find("attack") != std::string::npos;
}

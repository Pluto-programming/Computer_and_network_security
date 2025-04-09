#include <fstream>
#include <ctime>
#include <iostream>

void log_message(const std::string& msg) {
    std::ofstream log("chat_server.log", std::ios::app);
    std::time_t now = std::time(nullptr);
    log << std::ctime(&now) << ": " << msg << std::endl;
}

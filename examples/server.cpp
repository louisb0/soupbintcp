#include <soupbin/server.hpp>

#include <chrono>
#include <cstddef>
#include <cstdlib>
#include <expected>
#include <iostream>
#include <span>
#include <string_view>
#include <system_error>

bool handle_auth(std::string_view username, std::string_view password) {
    return username == "user" && password == "letmein";
}

void handle_data(std::span<const std::byte> data) {
    std::cout << "Received " << data.size() << " bytes of data\n";
}

void handle_debug(std::span<const std::byte> debug_data) {
    std::cout << "Debug: " << debug_data.size() << " bytes\n";
}

bool handle_tick() {
    return true;
}

int main() {
    auto server = soupbin::make_server({
        .hostname = "localhost",
        .port = "8888",
        .tick = std::chrono::milliseconds(1),
        .on_auth = handle_auth,
        .on_data = handle_data,
        .on_debug = handle_debug,
        .on_tick = handle_tick,
    });

    if (!server) {
        const auto &err = server.error();
        std::cout << "Could not create server - [" << err.category().name() << "]: " << err.message() << '\n';
        return EXIT_FAILURE;
    }

    auto result = server->run();
    if (result) {
        std::cout << "Server stopped with error - [" << result.category().name() << "]: " << result.message() << '\n';
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

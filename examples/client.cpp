#include <soupbin/client.hpp>

#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <expected>
#include <iostream>
#include <span>
#include <string>
#include <system_error>

#include <sys/types.h>

int main() {
    auto client = soupbin::connect({
        .hostname = "localhost",
        .port = "8888",
        .username = "user",
        .password = "letmein",
        // .session_id = "abc123",
        // .sequence_num = "1293874",
    });

    if (!client) {
        const auto &err = client.error();
        std::cout << "Could not connect to server [" << err.category().name() << "]: " << err.message() << '\n';
        return EXIT_FAILURE;
    }

    std::string msg = "hello!";
    auto data = std::as_bytes(std::span(msg));

    ssize_t sent = client->send_debug(data);
    if (sent == -1) {
        std::cout << "Could not message server: " << std::strerror(errno) << '\n';
        return EXIT_FAILURE;
    }

    std::cout << "Sent " << sent << " bytes: '" << msg << "'\n";
    std::cout << "Press Enter to exit...\n";

    std::cin.get();

    return EXIT_SUCCESS;
}

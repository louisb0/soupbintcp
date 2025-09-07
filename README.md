# soupbintcp
A C++ implementation of NASDAQ's SoupBinTCP protocol defined at [https://www.nasdaq.com/docs/SoupBinTCP%204.0.pdf](https://www.nasdaq.com/docs/SoupBinTCP%204.0.pdf).

## Examples

These are the current simple examples prone to change as the project evolves.

### Server

```cpp
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
        std::cout << "Could not create server [" << err.category().name() << "]: " << err.message() << '\n';
        return EXIT_FAILURE;
    }

    auto result = server->run();
    if (result) {
        std::cout << "Server stopped with error [" << result.category().name() << "]: " << result.message() << '\n';
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
```

### Client

```cpp
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
```


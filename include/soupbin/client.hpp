#pragma once

#include <cstddef>
#include <expected>
#include <memory>
#include <span>
#include <string>
#include <system_error>

#include <sys/types.h>

namespace soupbin {

static constexpr const char *NEW_SESSION = " ";
static constexpr const char *SEQ_START = "0";

struct connect_config {
    std::string hostname;
    std::string port;
    std::string username;
    std::string password;
    std::string session_id = NEW_SESSION;
    std::string sequence_num = SEQ_START;
};

class client {
public:
    client(client &&) noexcept;
    client &operator=(client &&) noexcept;
    client(const client &) = delete;
    client &operator=(const client &) = delete;
    ~client();

    [[nodiscard]] ssize_t send_unseq(std::span<const std::byte>) const noexcept;
    [[nodiscard]] ssize_t send_debug(std::span<const std::byte>) const noexcept;
    [[nodiscard]] ssize_t recv(std::span<std::byte>) const noexcept;

    [[nodiscard]] bool logout() const noexcept;
    [[nodiscard]] bool send_and_check_heartbeat() const noexcept;

private:
    class impl;
    std::unique_ptr<impl> impl_;

    explicit client(std::unique_ptr<impl> impl);
    friend std::expected<client, std::error_code> connect(const connect_config &);
};

[[nodiscard]] std::expected<client, std::error_code> connect(const connect_config &);

} // namespace soupbin

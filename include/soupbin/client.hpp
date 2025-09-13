#pragma once

#include <cstddef>
#include <cstdint>
#include <expected>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <system_error>

namespace soupbin {

#ifndef SOUPBIN_C_RECV_BYTES_PER_TICK
#define SOUPBIN_C_RECV_BYTES_PER_TICK 1024
#endif

#ifndef SOUPBIN_C_SEND_BYTES_PER_TICK
#define SOUPBIN_C_SEND_BYTES_PER_TICK 2048
#endif

#ifndef SOUPBIN_C_RECV_QUEUE_BYTES
#define SOUPBIN_C_RECV_QUEUE_BYTES 8192
#endif

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

struct server_message {
    enum class type : uint8_t {
        debug,
        unsequenced,
        sequenced
    } type;
    std::span<const std::byte> payload;
};

class client {
public:
    client(client &&) noexcept;
    client &operator=(client &&) noexcept;
    client(const client &) = delete;
    client &operator=(const client &) = delete;
    ~client();

    [[nodiscard]] const std::string &session_id() const noexcept;
    [[nodiscard]] size_t sequence_num() const noexcept;

    void queue_unseq_msg(std::span<const std::byte>) noexcept;
    void queue_debug_msg(std::span<const std::byte>) noexcept;
    [[nodiscard]] std::optional<server_message> try_recv_msg() noexcept;
    [[nodiscard]] std::error_code commit() noexcept;

    [[nodiscard]] std::error_code logout() noexcept;

private:
    class impl;
    std::unique_ptr<impl> impl_;

    explicit client(std::unique_ptr<impl> p);
    friend std::expected<client, std::error_code> connect(const connect_config &);
};

[[nodiscard]] std::expected<client, std::error_code> connect(const connect_config &);

} // namespace soupbin

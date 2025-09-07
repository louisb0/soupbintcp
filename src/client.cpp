#include "soupbin/client.hpp"

#include "soupbin/errors.hpp"

#include "detail/assert.hpp"
#include "detail/messages.hpp"

#include <algorithm>
#include <array>
#include <cstring>
#include <memory>
#include <utility>

#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/uio.h>

namespace soupbin {

// ---------------- declaration ----------------

class client::impl {
    int fd_;

public:
    impl(int fd) : fd_(fd) {
        ASSERT(fd_ >= 0);
    }

    ~impl() {
        ASSERT(fd_ >= 0);
        close(fd_);
    }

    impl(const impl &) = delete;
    impl &operator=(const impl &) = delete;
    impl(impl &&) = delete;
    impl &operator=(impl &&) = delete;

    [[nodiscard]] ssize_t send_unseq(std::span<const std::byte> from) const noexcept;
    [[nodiscard]] ssize_t send_debug(std::span<const std::byte> from) const noexcept;
    [[nodiscard]] ssize_t recv(std::span<std::byte> to) const noexcept;

    [[nodiscard]] bool logout() const noexcept;
    [[nodiscard]] bool send_and_check_heartbeat() const noexcept;
};

client::client(std::unique_ptr<impl> impl) : impl_(std::move(impl)) {}
client::client(client &&other) noexcept : impl_(std::move(other.impl_)) {}
client &client::operator=(client &&) noexcept = default;
client::~client() = default;

ssize_t client::send_unseq(std::span<const std::byte> from) const noexcept {
    return impl_->send_unseq(from);
}

ssize_t client::send_debug(std::span<const std::byte> from) const noexcept {
    return impl_->send_debug(from);
}

ssize_t client::recv(std::span<std::byte> to) const noexcept {
    return impl_->recv(to);
}

bool client::logout() const noexcept {
    return impl_->logout();
}

bool client::send_and_check_heartbeat() const noexcept {
    return impl_->send_and_check_heartbeat();
}

// ---------------- definition ----------------

ssize_t client::impl::send_unseq(std::span<const std::byte> from) const noexcept {
    return -1;
}

ssize_t client::impl::send_debug(std::span<const std::byte> from) const noexcept {
    return -1;
}

ssize_t client::impl::recv(std::span<std::byte> to) const noexcept {
    return -1;
}

bool client::impl::logout() const noexcept {
    return false;
}

bool client::impl::send_and_check_heartbeat() const noexcept {
    return false;
}

// ---------------- factory ----------------

std::expected<client, std::error_code> connect(const connect_config &cfg) {
    if (cfg.hostname.empty()) {
        return std::unexpected(make_soupbin_error(errc::bad_hostname));
    }

    if (cfg.port.empty()) {
        return std::unexpected(make_soupbin_error(errc::bad_port));
    }

    if (cfg.username.empty() || cfg.username.length() > detail::username_len) {
        return std::unexpected(make_soupbin_error(errc::bad_username));
    }

    if (cfg.password.empty() || cfg.password.length() > detail::password_len) {
        return std::unexpected(make_soupbin_error(errc::bad_password));
    }

    if (cfg.session_id.empty() || cfg.session_id.length() > detail::session_id_len) {
        return std::unexpected(make_soupbin_error(errc::bad_session_id));
    }

    if (cfg.sequence_num.empty() || cfg.sequence_num.length() > detail::sequence_num_len) {
        return std::unexpected(make_soupbin_error(errc::bad_sequence_number));
    }

    // Resolve address.
    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    addrinfo *res{};
    int gai_c = getaddrinfo(cfg.hostname.c_str(), cfg.port.c_str(), &hints, &res);
    if (gai_c != 0) {
        if (gai_c == EAI_SYSTEM) {
            return std::unexpected(std::error_code(errno, std::system_category()));
        }
        return std::unexpected(make_gai_error(gai_c));
    }

    // Find suitable connection.
    int cfd = -1;
    for (addrinfo *it = res; it != nullptr; it = it->ai_next) {
        int fd = socket(it->ai_family, it->ai_socktype, it->ai_protocol);
        if (fd == -1) {
            continue;
        }

        if (connect(fd, it->ai_addr, it->ai_addrlen) == -1) {
            close(fd);
            continue;
        }

        int flags = fcntl(fd, F_GETFL, 0);
        if (flags == -1 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1) {
            close(fd);
            continue;
        }

        cfd = fd;
        break;
    }

    freeaddrinfo(res);

    if (cfd == -1) {
        return std::unexpected(make_soupbin_error(errc::bad_host));
    }

    // Send login request, read reply.
    detail::msg_login_request req = detail::msg_login_request::build(cfg);
    if (send(cfd, &req, sizeof(req), 0) == -1) {
        close(cfd);
        return std::unexpected(std::error_code(errno, std::system_category()));
    }

    constexpr size_t buf_size = std::max(sizeof(detail::msg_login_accepted), sizeof(detail::msg_login_rejected));
    std::array<std::byte, buf_size> buf{};

    ssize_t n = recv(cfd, buf.data(), sizeof(detail::msg_header), MSG_WAITALL);
    if (n != sizeof(detail::msg_header)) {
        close(cfd);
        return std::unexpected(std::error_code(errno, std::system_category()));
    }

    auto *header = reinterpret_cast<detail::msg_header *>(buf.data());
    size_t remaining = ntohs(header->length);

    n = ::recv(cfd, header + 1, remaining, MSG_WAITALL);
    if (n != static_cast<ssize_t>(remaining)) {
        close(cfd);
        return std::unexpected(std::error_code(errno, std::system_category()));
    }

    // Handle authentication result.
    if (header->type == detail::mt_login_accepted) {
        return client(std::make_unique<client::impl>(cfd));
    }

    close(cfd);

    if (header->type == detail::mt_login_rejected) {
        auto *msg = reinterpret_cast<detail::msg_login_rejected *>(buf.data());

        if (msg->reason == detail::rej_not_authorized) {
            return std::unexpected(make_soupbin_error(errc::no_such_login));
        }

        if (msg->reason == detail::rej_no_session) {
            return std::unexpected(make_soupbin_error(errc::no_such_session));
        }

        return std::unexpected(make_soupbin_error(errc::protocol));
    }

    return std::unexpected(make_soupbin_error(errc::protocol));
}

} // namespace soupbin

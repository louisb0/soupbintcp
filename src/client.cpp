#include "soupbin/client.hpp"

#include "soupbin/errors.hpp"
#include "soupbin/server.hpp"

#include "detail/assert.hpp"
#include "detail/log.hpp"
#include "detail/messages.hpp"
#include "detail/util.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <memory>
#include <optional>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

namespace soupbin {

// ---------------- declaration ----------------

class client::impl {
    int fd_;
    bool logged_in_{ true };
    bool active_session_{ true };

    std::vector<std::byte> send_queue_;
    struct {
        std::vector<std::byte> buffer;
        uint32_t consumed{};
    } recv_queue_;

    std::chrono::steady_clock::time_point last_send_;
    std::chrono::steady_clock::time_point last_recv_{ std::chrono::steady_clock::now() };

    std::string session_id_;
    size_t sequence_num_;

public:
    impl(int fd, std::string_view session_num, size_t sequence_num) : fd_(fd), session_id_(session_num), sequence_num_(sequence_num) {
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

    [[nodiscard]] const std::string &session_id() const noexcept { return session_id_; }
    [[nodiscard]] size_t sequence_num() const noexcept { return sequence_num_; }

    void queue_unseq_msg(std::span<const std::byte> data) noexcept;
    void queue_debug_msg(std::span<const std::byte> data) noexcept;
    [[nodiscard]] std::optional<soupbin::server_message> try_recv_msg() noexcept;
    [[nodiscard]] std::error_code commit() noexcept;

    [[nodiscard]] std::error_code logout() noexcept;
};

client::client(std::unique_ptr<impl> p) : impl_(std::move(p)) {}
client::client(client &&other) noexcept : impl_(std::move(other.impl_)) {}
client &client::operator=(client &&) noexcept = default;
client::~client() = default;

const std::string &client::session_id() const noexcept {
    return impl_->session_id();
}

size_t client::sequence_num() const noexcept {
    return impl_->sequence_num();
}

void client::queue_unseq_msg(std::span<const std::byte> data) noexcept {
    impl_->queue_unseq_msg(data);
}

void client::queue_debug_msg(std::span<const std::byte> data) noexcept {
    impl_->queue_debug_msg(data);
}

std::optional<soupbin::server_message> client::try_recv_msg() noexcept {
    return impl_->try_recv_msg();
}

std::error_code client::commit() noexcept {
    return impl_->commit();
}

std::error_code client::logout() noexcept {
    return impl_->logout();
}

// ---------------- definition ----------------

std::error_code client::impl::commit() noexcept {
    if (!logged_in_) {
        return make_soupbin_error(errc::logged_out);
    }

    if (!active_session_) {
        return make_soupbin_error(errc::end_of_session);
    }

    const auto now = std::chrono::steady_clock::now();

    // Receive data.
    if (recv_queue_.consumed > 0) {
        recv_queue_.buffer.erase(recv_queue_.buffer.begin(), recv_queue_.buffer.begin() + recv_queue_.consumed);
        recv_queue_.consumed = 0;
    }

    const size_t space = SOUPBIN_C_RECV_QUEUE_BYTES - recv_queue_.buffer.size();
    if (space > 0) {
        std::array<std::byte, SOUPBIN_C_RECV_BYTES_PER_TICK> buffer{};

        // TODO: Compare throughput with loop.
        ssize_t bytes = recv(fd_, buffer.data(), std::min(buffer.size(), space), 0);

        if (bytes == -1) {
            if (errno == EWOULDBLOCK || errno == EAGAIN) {
                // NOTE: Continue normal flow if there is no data to receive.
                bytes = 0;
            } else {
                LOG_CRITICAL("failed to recv() from server.");
                return { errno, std::system_category() };
            }
        } else if (bytes == 0) {
            return make_soupbin_error(errc::server_disconnect);
        }

        if (bytes > 0) {
            recv_queue_.buffer.insert(recv_queue_.buffer.end(), buffer.begin(), buffer.begin() + bytes);
            last_recv_ = std::chrono::steady_clock::now();
        }
    }

    DEBUG_ASSERT(recv_queue_.buffer.size() <= SOUPBIN_C_RECV_QUEUE_BYTES);
    DEBUG_ASSERT(recv_queue_.consumed == 0);

    // Send data.
    if (!send_queue_.empty()) {
        const size_t to_send = std::min(send_queue_.size(), static_cast<size_t>(SOUPBIN_C_SEND_BYTES_PER_TICK));

        const ssize_t sent = send(fd_, send_queue_.data(), to_send, 0);
        if (sent == -1) {
            LOG_CRITICAL("failed to send() queued data to server.");
            return { errno, std::system_category() };
        }

        send_queue_.erase(send_queue_.begin(), send_queue_.begin() + sent);
        last_send_ = now;
    }

    // Manage heartbeats.
    if (now - last_recv_ > std::chrono::seconds(SOUPBIN_S_SERVER_HEARTBEAT_SEC)) {
        return make_soupbin_error(errc::server_heartbeat);
    }

    if (now - last_send_ > std::chrono::seconds(SOUPBIN_S_CLIENT_HEARTBEAT_SEC - 1)) {
        const detail::msg_client_heartbeat hb = detail::msg_client_heartbeat::build();

        const ssize_t sent = send(fd_, &hb, sizeof(hb), 0);
        if (sent == -1) {
            LOG_CRITICAL("failed to send() heartbeat to server.");
            return { errno, std::system_category() };
        }

        last_send_ = now;
    }

    return {};
}

void client::impl::queue_unseq_msg(std::span<const std::byte> data) noexcept {
    const detail::msg_header hdr{
        .length = htons(static_cast<uint16_t>(data.size())),
        .type = detail::mt_unsequenced,
    };

    const auto *hdr_bytes = reinterpret_cast<const std::byte *>(&hdr);
    send_queue_.insert(send_queue_.end(), hdr_bytes, hdr_bytes + sizeof(hdr));
    send_queue_.insert(send_queue_.end(), data.begin(), data.end());
}

void client::impl::queue_debug_msg(std::span<const std::byte> data) noexcept {
    const detail::msg_header hdr{
        .length = htons(static_cast<uint16_t>(data.size())),
        .type = detail::mt_debug,
    };

    const auto *hdr_bytes = reinterpret_cast<const std::byte *>(&hdr);
    send_queue_.insert(send_queue_.end(), hdr_bytes, hdr_bytes + sizeof(hdr));
    send_queue_.insert(send_queue_.end(), data.begin(), data.end());
}

std::optional<soupbin::server_message> client::impl::try_recv_msg() noexcept {
    bool processing = true;
    while (processing) {
        // Check that there is a message.
        const size_t available = recv_queue_.buffer.size() - recv_queue_.consumed;
        if (available < sizeof(detail::msg_header)) {
            break;
        }

        const auto *hdr = reinterpret_cast<const detail::msg_header *>(&recv_queue_.buffer[recv_queue_.consumed]);
        const size_t payload_size = ntohs(hdr->length);
        const size_t total_msg_size = sizeof(detail::msg_header) + payload_size;

        if (total_msg_size > available) {
            break;
        }

        // Pull the payload and advance the parse position.
        const std::span<const std::byte> payload{
            &recv_queue_.buffer[recv_queue_.consumed + sizeof(detail::msg_header)],
            payload_size
        };

        recv_queue_.consumed += total_msg_size;

        // Process message.
        switch (hdr->type) {
        case detail::mt_debug: {
            return soupbin::server_message{ .type = soupbin::server_message::type::debug, .payload = payload };
        }

        case detail::mt_unsequenced: {
            return soupbin::server_message{ .type = soupbin::server_message::type::unsequenced, .payload = payload };
        }

        case detail::mt_sequenced: {
            sequence_num_++;
            return soupbin::server_message{ .type = soupbin::server_message::type::sequenced, .payload = payload };
        }

        case detail::mt_end_of_session: {
            processing = false;
            active_session_ = false;
            break;
        }

        // NOTE: This is handled implicitly by setting last_recv_ on any data.
        case detail::mt_server_heartbeat: {
            break;
        }

        case detail::mt_login_accepted:
        case detail::mt_login_rejected:
        case detail::mt_login_request:
        case detail::mt_logout_request:
        case detail::mt_client_heartbeat: {
            LOG_WARN("received unexpected message type from server. (mt={})", static_cast<char>(hdr->type));
            break;
        }

        default: {
            LOG_WARN("received unknown message type from server (mt={}).", static_cast<char>(hdr->type));
            break;
        }
        }
    }

    return std::nullopt;
}

std::error_code client::impl::logout() noexcept {
    if (!logged_in_) {
        return make_soupbin_error(errc::logged_out);
    }

    detail::msg_logout_request msg = detail::msg_logout_request::build();
    if (send(fd_, &msg, sizeof(msg), 0) == -1) {
        LOG_CRITICAL("failed to send() logout to server.");
        return { errno, std::system_category() };
    }

    // NOTE: fd close is left to client destructor - not ideal.
    logged_in_ = false;

    return {};
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
        LOG_CRITICAL("failed to getaddrinfo() for the provided hostname and port.");

        if (gai_c == EAI_SYSTEM) {
            return std::unexpected(std::error_code(errno, std::system_category()));
        }

        return std::unexpected(make_gai_error(gai_c));
    }

    // Find suitable connecting address.
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

        cfd = fd;
        break;
    }

    freeaddrinfo(res);

    if (cfd == -1) {
        return std::unexpected(make_soupbin_error(errc::bad_host));
    }

    // Send login request.
    const detail::msg_login_request req = detail::msg_login_request::build(cfg);
    if (send(cfd, &req, sizeof(req), 0) == -1) {
        LOG_CRITICAL("failed to send() login request.");
        detail::preserving_close(cfd);

        return std::unexpected(std::error_code(errno, std::system_category()));
    }

    // Receive login response.
    constexpr size_t buffer_size = std::max(sizeof(detail::msg_login_accepted), sizeof(detail::msg_login_rejected));
    std::array<std::byte, buffer_size> buffer{};

    // Header.
    ssize_t bytes = recv(cfd, buffer.data(), sizeof(detail::msg_header), MSG_WAITALL);
    if (bytes != sizeof(detail::msg_header)) {
        LOG_CRITICAL("failed to recv() login response header.");
        detail::preserving_close(cfd);

        return std::unexpected(std::error_code(errno, std::system_category()));
    }

    // Payload.
    const auto *hdr = reinterpret_cast<const detail::msg_header *>(buffer.data());

    std::byte *payload_start = buffer.data() + sizeof(detail::msg_header);
    const size_t payload_size = ntohs(hdr->length);

    bytes = ::recv(cfd, payload_start, payload_size, MSG_WAITALL);
    if (bytes != static_cast<ssize_t>(payload_size)) {
        LOG_CRITICAL("failed to recv() login response payload.");
        detail::preserving_close(cfd);

        return std::unexpected(std::error_code(errno, std::system_category()));
    }

    // Set non-blocking.
    int flags = fcntl(cfd, F_GETFL, 0);
    if (flags == -1 || fcntl(cfd, F_SETFL, flags | O_NONBLOCK) == -1) {
        LOG_CRITICAL("failed to fcntl() set client as non-blocking.");
        detail::preserving_close(cfd);

        return std::unexpected(std::error_code(errno, std::system_category()));
    }

    // Handle authentication success.
    if (hdr->type == detail::mt_login_accepted) {
        const auto *msg = reinterpret_cast<const detail::msg_login_accepted *>(buffer.data());

        const auto session_id = detail::format_session_id(msg->session_id);
        const auto sequence_num = detail::format_sequence_num(msg->sequence_num);

        return client(std::make_unique<client::impl>(cfd, session_id, sequence_num));
    }

    // Handle authentication failure.
    close(cfd);

    if (hdr->type == detail::mt_login_rejected) {
        const auto *msg = reinterpret_cast<const detail::msg_login_rejected *>(buffer.data());

        if (msg->reason == detail::rej_not_authenticated) {
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

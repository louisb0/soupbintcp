#pragma once

#include "soupbin/client.hpp"

#include "detail/assert.hpp"
#include "detail/util.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string_view>

#include <netinet/in.h>

namespace soupbin::detail {

// -------------- types --------------

static constexpr uint8_t username_len = 6;
static constexpr uint8_t password_len = 10;
static constexpr uint8_t session_id_len = 10;
static constexpr uint8_t sequence_num_len = 20;

enum message_type : uint8_t {
    // server <-> client
    mt_debug = '+',
    mt_unsequenced = 'U',

    // server -> client
    mt_login_accepted = 'A',
    mt_login_rejected = 'J',
    mt_sequenced = 'S',
    mt_server_heartbeat = 'H',
    mt_end_of_session = 'Z',

    // client -> server
    mt_login_request = 'L',
    mt_logout_request = 'O',
    mt_client_heartbeat = 'R',
};

enum login_reject_code : uint8_t {
    rej_not_authenticated = 'A',
    rej_no_session = 'S',
};

// -------------- messages --------------
// NOLINTBEGIN(*-c-arrays)

struct __attribute__((packed)) msg_header {
    uint16_t length;
    message_type type;
};

struct __attribute__((packed)) msg_debug {
    msg_header hdr;
    std::byte data[];

    [[nodiscard]] static msg_debug build(size_t payload_size) {
        msg_debug msg{};
        msg.hdr.length = htons(payload_size);
        msg.hdr.type = mt_debug;

        return msg;
    }
};

struct __attribute__((packed)) msg_login_request {
    msg_header hdr;
    char username[username_len];
    char password[password_len];
    char session_id[session_id_len];
    char sequence_num[sequence_num_len];

    [[nodiscard]] static msg_login_request build(const connect_config &cfg) {
        ASSERT(!cfg.username.empty() && cfg.username.length() <= detail::username_len);
        ASSERT(!cfg.password.empty() && cfg.password.length() <= detail::password_len);
        ASSERT(!cfg.session_id.empty() && cfg.session_id.length() <= detail::session_id_len);
        ASSERT(!cfg.sequence_num.empty() && cfg.sequence_num.length() <= detail::sequence_num_len);

        msg_login_request msg{};
        msg.hdr.length = htons(sizeof(msg) - sizeof(msg.hdr));
        msg.hdr.type = detail::mt_login_request;
        detail::pad_field_right(msg.username, detail::username_len, cfg.username);
        detail::pad_field_right(msg.password, detail::password_len, cfg.password);
        detail::pad_field_left(msg.session_id, detail::session_id_len, cfg.session_id);
        detail::pad_field_left(msg.sequence_num, detail::sequence_num_len, cfg.sequence_num);

        return msg;
    }
};

struct __attribute__((packed)) msg_login_accepted {
    msg_header hdr;
    char session_id[session_id_len];
    char sequence_num[sequence_num_len];

    [[nodiscard]] static msg_login_accepted build(std::string_view session_id, std::string_view sequence_num) {
        ASSERT(session_id.length() == session_id_len);
        ASSERT(sequence_num.length() == sequence_num_len);

        msg_login_accepted msg{};
        msg.hdr.length = htons(sizeof(msg) - sizeof(msg.hdr));
        msg.hdr.type = detail::mt_login_accepted;
        std::memcpy(msg.session_id, session_id.data(), detail::session_id_len);
        std::memcpy(msg.sequence_num, sequence_num.data(), detail::sequence_num_len);

        return msg;
    }
};

struct __attribute__((packed)) msg_login_rejected {
    msg_header hdr;
    login_reject_code reason;

    [[nodiscard]] static msg_login_rejected build(login_reject_code reason) {
        msg_login_rejected msg{};
        msg.hdr.length = htons(sizeof(msg) - sizeof(msg.hdr));
        msg.hdr.type = mt_login_rejected;
        msg.reason = reason;

        return msg;
    }
};

struct __attribute__((packed)) msg_client_heartbeat {
    msg_header hdr;

    [[nodiscard]] static msg_client_heartbeat build() {
        msg_client_heartbeat msg{};
        msg.hdr.length = htons(sizeof(msg) - sizeof(msg.hdr));
        msg.hdr.type = mt_client_heartbeat;

        return msg;
    }
};

struct __attribute__((packed)) msg_server_heartbeat {
    msg_header hdr;

    [[nodiscard]] static msg_server_heartbeat build() {
        msg_server_heartbeat msg{};
        msg.hdr.length = htons(sizeof(msg) - sizeof(msg.hdr));
        msg.hdr.type = mt_server_heartbeat;

        return msg;
    }
};

struct __attribute__((packed)) msg_unsequenced {
    msg_header hdr;
    std::byte data[];

    [[nodiscard]] static msg_unsequenced build(size_t payload_size) {
        msg_unsequenced msg{};
        msg.hdr.length = htons(payload_size);
        msg.hdr.type = mt_unsequenced;

        return msg;
    }
};

// NOLINTEND(*-c-arrays)

// -------------- bounds --------------

static inline constexpr size_t max_client_message_size = std::max({
    sizeof(msg_debug),
    sizeof(msg_login_request),
    sizeof(msg_client_heartbeat),
    sizeof(msg_unsequenced),
});

static inline constexpr size_t max_server_message_size = std::max({
    sizeof(msg_debug),
    sizeof(msg_login_accepted),
    sizeof(msg_login_rejected),
    sizeof(msg_server_heartbeat),
    sizeof(msg_unsequenced),
});

static inline constexpr size_t max_message_size = std::max({ max_client_message_size, max_server_message_size });

// -------------- formatting --------------

[[nodiscard]] inline std::string_view format_username(const char *username) {
    ASSERT(username != nullptr);

    auto view = std::string_view(username, username_len);
    auto end = view.find_last_not_of(' ');

    if (end == std::string_view::npos) {
        return std::string_view{};
    }

    return view.substr(0, end + 1);
}

[[nodiscard]] inline std::string_view format_password(const char *password) {
    ASSERT(password != nullptr);

    auto view = std::string_view(password, password_len);
    auto end = view.find_last_not_of(' ');

    if (end == std::string_view::npos) {
        return std::string_view{};
    }

    return view.substr(0, end + 1);
}

[[nodiscard]] inline std::string_view format_session_id(const char *session_id) {
    ASSERT(session_id != nullptr);

    auto view = std::string_view(session_id, session_id_len);
    size_t start = view.find_first_not_of(' ');

    if (start == std::string_view::npos) {
        return std::string_view{};
    }

    return view.substr(start);
}

[[nodiscard]] inline size_t format_sequence_num(const char *sequence_num) {
    ASSERT(sequence_num != nullptr);

    auto view = std::string_view(sequence_num, sequence_num_len);
    size_t start = view.find_first_not_of(' ');

    if (start == std::string_view::npos) {
        return 0;
    }

    return std::stoul(std::string(view.substr(start)));
}

} // namespace soupbin::detail

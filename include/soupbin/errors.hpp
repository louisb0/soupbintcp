#pragma once

#include <cstdint>
#include <system_error>

#include <netdb.h>

namespace soupbin {

// ----------- validation errors -----------

enum class errc : uint8_t {
    bad_hostname = 1,
    bad_port,
    bad_username,
    bad_password,
    bad_session_id,
    bad_sequence_number,
    bad_host,
    no_such_login,
    no_such_session,
    protocol,
};

struct soupbin_category_t final : std::error_category {
    [[nodiscard]] const char *name() const noexcept override { return "soupbin"; }

    [[nodiscard]] std::string message(int ev) const override {
        switch (static_cast<errc>(ev)) {
        case errc::bad_hostname:
            return "hostname must not be empty";
        case errc::bad_port:
            return "port must not be empty";
        case errc::bad_username:
            return "username must be between 1 and 6 alphanumeric characters";
        case errc::bad_password:
            return "password must be between 1 and 10 alphanumeric characters";
        case errc::bad_session_id:
            return "session id must be between 1 and 10 alpanumeric characters";
        case errc::bad_sequence_number:
            return "session id must be between 1 and 20 numeric characters";
        case errc::bad_host:
            return "no host could be resolved for the given hostname and port";
        case errc::no_such_login:
            return "no accounts matched the provided login";
        case errc::no_such_session:
            return "no session was found for the given login";
        case errc::protocol:
            return "a message was received which did not adhere to protocol";
        default:
            return "unknown";
        }
    }
};

inline const std::error_category &soupbin_category() {
    static soupbin_category_t inst;
    return inst;
}

inline std::error_code make_soupbin_error(errc e) {
    return { static_cast<int>(e), soupbin_category() };
}

// ----------- getaddrinfo errors -----------

struct gai_category_t final : std::error_category {
    [[nodiscard]] const char *name() const noexcept override { return "getaddrinfo"; }

    [[nodiscard]] std::string message(int ev) const override {
        const char *s = ::gai_strerror(ev);
        if (s == nullptr) {
            return "unknown";
        }

        return s;
    }
};

inline const std::error_category &gai_category() {
    static gai_category_t inst;
    return inst;
}

inline std::error_code make_gai_error(int eai_code) {
    return { eai_code, gai_category() };
}

} // namespace soupbin

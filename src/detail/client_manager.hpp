#pragma once

#include "detail/partial.hpp"

#include <chrono>
#include <span>
#include <unordered_map>
#include <vector>

namespace soupbin::detail {

class session;

struct client {
    int fd{ -1 };
    int auth_index{ -1 };

    detail::session *session{};
    detail::partial partial{};

    std::chrono::steady_clock::time_point last_recv;
    std::chrono::steady_clock::time_point last_send;

    [[nodiscard]] bool in_use() const noexcept {
        return fd != -1;
    }

    [[nodiscard]] bool authenticated() const noexcept {
        return auth_index != -1;
    }
};

class client_manager {
    std::unordered_map<int, client> store_;
    std::vector<client *> authenticated_;

public:
    [[nodiscard]] client *add(int cfd) noexcept;
    void authenticate(client *c, detail::session *s) noexcept;
    void remove(client *c) noexcept;

    [[nodiscard]] std::span<client *> authenticated() noexcept;
};

} // namespace soupbin::detail

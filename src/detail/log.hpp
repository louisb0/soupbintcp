#pragma once

#include <source_location>

#include <spdlog/spdlog.h>

#define LOG_INFO(msg, ...)                                             \
    do {                                                               \
        auto loc = std::source_location::current();                    \
        spdlog::info("[{}] " msg, loc.function_name(), ##__VA_ARGS__); \
    } while (0)

#define LOG_ERROR(msg, ...)                                             \
    do {                                                                \
        auto loc = std::source_location::current();                     \
        spdlog::error("[{}] " msg, loc.function_name(), ##__VA_ARGS__); \
    } while (0)

#define LOG_CRITICAL(msg, ...)                                             \
    do {                                                                   \
        auto loc = std::source_location::current();                        \
        spdlog::critical("[{}] " msg, loc.function_name(), ##__VA_ARGS__); \
    } while (0)

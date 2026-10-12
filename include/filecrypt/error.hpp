#pragma once

#include <stdexcept>
#include <string>

namespace filecrypt {

enum class ErrorCode { invalid_argument, length, logic, runtime };

struct Error {
    ErrorCode code;
    std::string message;
};

inline Error error_from_exception(const std::exception& error) {
    if (dynamic_cast<const std::invalid_argument*>(&error)) {
        return {ErrorCode::invalid_argument, error.what()};
    }
    if (dynamic_cast<const std::length_error*>(&error)) {
        return {ErrorCode::length, error.what()};
    }
    if (dynamic_cast<const std::logic_error*>(&error)) {
        return {ErrorCode::logic, error.what()};
    }
    return {ErrorCode::runtime, error.what()};
}

} // namespace filecrypt

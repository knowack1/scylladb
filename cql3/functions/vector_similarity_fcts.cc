/*
 * Copyright (C) 2025-present ScyllaDB
 */

/*
 * SPDX-License-Identifier: LicenseRef-ScyllaDB-Source-Available-1.0
 */

#include "vector_similarity_fcts.hh"

namespace cql3 {
namespace functions {

bytes_opt vector_similarity_fct::execute(std::span<const bytes_opt> parameters) {
    if (std::any_of(parameters.begin(), parameters.end(), [](const auto& param) {
            return !param;
        })) {
        throw exceptions::invalid_request_exception("Vector similarity functions cannot be executed with null arguments");
    }

    return std::nullopt; // Unimplemented
}

} // namespace functions
} // namespace cql3

/*
 * Copyright (C) 2025-present ScyllaDB
 */

/*
 * SPDX-License-Identifier: LicenseRef-ScyllaDB-Source-Available-1.0
 */

#pragma once

#include "native_scalar_function.hh"

namespace cql3 {
namespace functions {

static const function_name SIMILARITY_COSINE_FUNCTION_NAME = function_name::native_function("similarity_cosine");
static const function_name SIMILARITY_EUCLIDEAN_FUNCTION_NAME = function_name::native_function("similarity_euclidean");
static const function_name SIMILARITY_DOT_PRODUCT_FUNCTION_NAME = function_name::native_function("similarity_dot_product");

class vector_similarity_fct : public native_scalar_function {
public:
    vector_similarity_fct(const sstring& name)
        : native_scalar_function(name, float_type, {}) {
    }

    virtual bool is_pure() const override {
        return false;
    }

    virtual bytes_opt execute(std::span<const bytes_opt> parameters) override;
};

} // namespace functions
} // namespace cql3

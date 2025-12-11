/*
 * Copyright (C) 2025-present ScyllaDB
 */

/*
 * SPDX-License-Identifier: LicenseRef-ScyllaDB-Source-Available-1.0
 */

#include "vector_similarity_fcts.hh"
#include "cql3/column_identifier.hh"
#include "types/list.hh"
#include "types/types.hh"
#include "types/vector.hh"

namespace cql3 {
namespace functions {

namespace {

float compute_cosine_similarity(const std::vector<data_value>& v1, const std::vector<data_value>& v2) {
    double dot_product = 0.0;
    double norm_a = 0.0;
    double norm_b = 0.0;

    for (size_t i = 0; i < v1.size(); ++i) {
        double a = value_cast<float>(v1[i]);
        double b = value_cast<float>(v2[i]);

        dot_product += a * b;
        norm_a += a * a;
        norm_b += b * b;
    }

    if (norm_a == 0 && norm_b == 0) {
        return 0;
    }
    if (norm_a == 0 || norm_b == 0) {
        return 1;
    }
    return (1 + (dot_product / (std::sqrt(norm_a) * std::sqrt(norm_b)))) / 2;
}

float compute_euclidean_similarity(const std::vector<data_value>& v1, const std::vector<data_value>& v2) {
    double sum = 0.0;

    for (size_t i = 0; i < v1.size(); ++i) {
        double a = value_cast<float>(v1[i]);
        double b = value_cast<float>(v2[i]);

        double diff = a - b;
        sum += diff * diff;
    }

    return (1 / (1 + sum));
}

float compute_dot_product_similarity(const std::vector<data_value>& v1, const std::vector<data_value>& v2) {
    double dot_product = 0.0;

    for (size_t i = 0; i < v1.size(); ++i) {
        double a = value_cast<float>(v1[i]);
        double b = value_cast<float>(v2[i]);
        dot_product += a * b;
    }

    return ((1 + dot_product) / 2);
}

void validate_vector_type(const function_name& name, const data_type& type, const shared_ptr<assignment_testable>& arg, const data_dictionary::database& db) {
    if (!type->is_vector()) {
        throw exceptions::invalid_request_exception(fmt::format("Function {} requires a float vector argument, but found {} of type {}", name,
                arg->assignment_testable_source_context(), type->cql3_type_name()));
    }

    auto elem_type = dynamic_cast<const vector_type_impl&>(*type).get_elements_type();
    if (elem_type != float_type) {
        throw exceptions::invalid_request_exception(fmt::format("Function {} requires a float vector argument, but found {} of type {}", name,
                arg->assignment_testable_source_context(), type->cql3_type_name()));
    }

    if (!is_assignable(arg->test_assignment(db, {}, {}, column_specification({}, {}, ::make_shared<column_identifier>("<arg>", true), type)))) {
        throw exceptions::invalid_request_exception(
                fmt::format("Function {} requires a float vector argument, but found {}", name, arg->assignment_testable_source_context()));
    }
}

} // namespace

std::vector<data_type> vector_similarity_fct::provide_arg_types(
        const function_name& name, const std::vector<shared_ptr<assignment_testable>>& provided_args, const data_dictionary::database& db) {
    if (provided_args.size() != 2) {
        throw exceptions::invalid_request_exception(fmt::format("Invalid number of arguments for function {}(vector<float, n>, vector<float, n>)", name));
    }

    auto first_arg_type_opt = provided_args[0]->assignment_testable_type_opt();
    auto second_arg_type_opt = provided_args[1]->assignment_testable_type_opt();

    if (first_arg_type_opt) {
        auto type = *first_arg_type_opt;
        validate_vector_type(name, type, provided_args[0], db);
        validate_vector_type(name, type, provided_args[1], db);
        return {type, type};
    }

    if (second_arg_type_opt) {
        auto type = *second_arg_type_opt;
        validate_vector_type(name, type, provided_args[0], db);
        validate_vector_type(name, type, provided_args[1], db);
        return {type, type};
    }

    // If neither type is known use a list type to indicate unknown dimension.
    // The dimension compatibility will be checked at execution time.
    auto type = list_type_impl::get_instance(float_type, false);
    return {type, type};
}

bytes_opt vector_similarity_fct::execute(std::span<const bytes_opt> parameters) {
    if (std::any_of(parameters.begin(), parameters.end(), [](const auto& param) {
            return !param;
        })) {
        return std::nullopt;
    }

    const auto& type = arg_types()[0];
    data_value v1 = type->deserialize(*parameters[0]);
    data_value v2 = type->deserialize(*parameters[1]);

    auto get_vector_elements = [](const data_value& dv) -> const std::vector<data_value>& {
        return value_cast<std::vector<data_value>>(dv);
    };

    const auto& v1_elements = get_vector_elements(v1);
    const auto& v2_elements = get_vector_elements(v2);

    if (v1_elements.size() != v2_elements.size()) {
        throw exceptions::invalid_request_exception(
                fmt::format("All arguments must have the same vector dimensions, but found vector<float, {}> and vector<float, {}>", v1_elements.size(),
                        v2_elements.size()));
    }

    using similarity_function_t = std::function<float(const std::vector<data_value>&, const std::vector<data_value>&)>;
    static const std::unordered_map<function_name, similarity_function_t> SIMILARITY_FUNCTIONS = {
            {SIMILARITY_COSINE_FUNCTION_NAME,
                    [](const std::vector<data_value>& v1_elements, const std::vector<data_value>& v2_elements) -> float {
                    return compute_cosine_similarity(v1_elements, v2_elements);
                    }},
            {SIMILARITY_EUCLIDEAN_FUNCTION_NAME,
                    [](const std::vector<data_value>& v1_elements, const std::vector<data_value>& v2_elements) -> float {
                    return compute_euclidean_similarity(v1_elements, v2_elements);
                    }},
            {SIMILARITY_DOT_PRODUCT_FUNCTION_NAME,
                    [](const std::vector<data_value>& v1_elements, const std::vector<data_value>& v2_elements) -> float {
                    return compute_dot_product_similarity(v1_elements, v2_elements);
                    }},
    };

    float result = SIMILARITY_FUNCTIONS.at(_name)(v1_elements, v2_elements);
    return float_type->decompose(result);
}

} // namespace functions
} // namespace cql3

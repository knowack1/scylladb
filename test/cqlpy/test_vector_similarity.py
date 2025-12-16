# Copyright 2025-present ScyllaDB
#
# SPDX-License-Identifier: LicenseRef-ScyllaDB-Source-Available-1.0

import pytest
from .util import new_test_table, is_scylla
from cassandra.protocol import InvalidRequest
import math


###############################################################################
# Tests for vector search related functions
###############################################################################


REQUIRES_FLOAT_VECTOR = "Function system.similarity_{} requires a float vector argument"


@pytest.mark.parametrize("similarity_function", ["cosine", "euclidean", "dot_product"])
def test_vector_similarity_fails_on_non_float_vector_column(cql, test_keyspace, similarity_function):
    schema = 'pk int, ck int, v vector<float, 3>, c int, vs vector<text, 3>, PRIMARY KEY (pk, ck)'
    with new_test_table(cql, test_keyspace, schema) as table:
        cql.execute(f"INSERT INTO {table} (pk, ck, v, c, vs) VALUES (1, 2, [1.0, 2.0, 3.0], 5, ['a', 'b', 'c'])")
        with pytest.raises(InvalidRequest, match=REQUIRES_FLOAT_VECTOR.format(similarity_function)):
            cql.execute(f"SELECT pk, similarity_{similarity_function}(pk, [1.1, 1.2, 20.25]) FROM {table}")
        with pytest.raises(InvalidRequest, match=REQUIRES_FLOAT_VECTOR.format(similarity_function)):
            cql.execute(f"SELECT pk, similarity_{similarity_function}(ck, [1.1, 1.2, 20.25]) FROM {table}")
        with pytest.raises(InvalidRequest, match=REQUIRES_FLOAT_VECTOR.format(similarity_function)):
            cql.execute(f"SELECT pk, similarity_{similarity_function}(c, [1.1, 1.2, 20.25]) FROM {table}")
        with pytest.raises(InvalidRequest, match=REQUIRES_FLOAT_VECTOR.format(similarity_function)):
            cql.execute(f"SELECT pk, similarity_{similarity_function}(vs, [1.1, 1.2, 20.25]) FROM {table}")


@pytest.mark.parametrize("similarity_function", ["cosine", "euclidean", "dot_product"])
def test_vector_similarity_fails_on_non_vector_literal(cql, test_keyspace, similarity_function):
    schema = 'pk int primary key, v vector<float, 3>'
    with new_test_table(cql, test_keyspace, schema) as table:
        cql.execute(f"INSERT INTO {table} (pk, v) VALUES (1, [1.0, 2.0, 3.0])")
        with pytest.raises(InvalidRequest, match=REQUIRES_FLOAT_VECTOR.format(similarity_function)):
            cql.execute(f"SELECT pk, similarity_{similarity_function}(v, 5) FROM {table}")
        with pytest.raises(InvalidRequest, match=REQUIRES_FLOAT_VECTOR.format(similarity_function)):
            cql.execute(f"SELECT pk, similarity_{similarity_function}(v, 'dog') FROM {table}")
        with pytest.raises(InvalidRequest, match=REQUIRES_FLOAT_VECTOR.format(similarity_function)):
            cql.execute(f"SELECT pk, similarity_{similarity_function}(v, '{{1.1, 1.2, 20.25}}') FROM {table}")


@pytest.mark.parametrize("similarity_function", ["cosine", "euclidean", "dot_product"])
def test_vector_similarity_fails_on_non_float_vector(cql, test_keyspace, similarity_function):
    schema = 'pk int primary key, v vector<float, 3>'
    with new_test_table(cql, test_keyspace, schema) as table:
        cql.execute(f"INSERT INTO {table} (pk, v) VALUES (1, [1.0, 2.0, 3.0])")
        with pytest.raises(InvalidRequest, match=REQUIRES_FLOAT_VECTOR.format(similarity_function) if is_scylla(cql) else "Type error"):
            cql.execute(f"SELECT pk, similarity_{similarity_function}(v, [1.1, '2003-05-187T16:20:00.000', 20.25]) FROM {table}")
        with pytest.raises(InvalidRequest, match=REQUIRES_FLOAT_VECTOR.format(similarity_function) if is_scylla(cql) else "Type error"):
            cql.execute(f"SELECT pk, similarity_{similarity_function}(v, [1.1, 'dog', 20.25]) FROM {table}")
        with pytest.raises(InvalidRequest, match=REQUIRES_FLOAT_VECTOR.format(similarity_function) if is_scylla(cql) else "Type error"):
            cql.execute(f"SELECT pk, similarity_{similarity_function}(v, [1.1, {{1.0, 2.0, 3.0}}, 20.25]) FROM {table}")
        # This test is Scylla-only because Cassandra does not handle it properly and crashes on org.apache.cassandra.serializers.MarshalException.
        if is_scylla(cql):
            with pytest.raises(InvalidRequest, match=f"null is not supported inside vectors"):
                cql.execute(f"SELECT pk, similarity_{similarity_function}(v, [1.1, null, 20.25]) FROM {table}")


@pytest.mark.parametrize("similarity_function", ["cosine", "euclidean", "dot_product"])
def test_vector_similarity_fails_on_non_float_vector_constants(cql, test_keyspace, similarity_function):
    schema = 'pk int primary key'
    with new_test_table(cql, test_keyspace, schema) as table:
        cql.execute(f"INSERT INTO {table} (pk) VALUES (1)")
        with pytest.raises(InvalidRequest, match="Type error" if is_scylla(cql) else REQUIRES_FLOAT_VECTOR.format(similarity_function)):
            cql.execute(f"SELECT pk, similarity_{similarity_function}(1, 2) FROM {table}")
        with pytest.raises(InvalidRequest, match="Type error" if is_scylla(cql) else REQUIRES_FLOAT_VECTOR.format(similarity_function)):
            cql.execute(f"SELECT pk, similarity_{similarity_function}(1, [1.1, 1.2, 20.25]) FROM {table}")
        with pytest.raises(InvalidRequest, match="Type error" if is_scylla(cql) else REQUIRES_FLOAT_VECTOR.format(similarity_function)):
            cql.execute(f"SELECT pk, similarity_{similarity_function}([1.1, 1.2, 20.25], 2) FROM {table}")
        with pytest.raises(InvalidRequest, match="Type error" if is_scylla(cql) else REQUIRES_FLOAT_VECTOR.format(similarity_function)):
            cql.execute(f"SELECT pk, similarity_{similarity_function}('a', 'b') FROM {table}")
        with pytest.raises(InvalidRequest, match="Type error" if is_scylla(cql) else REQUIRES_FLOAT_VECTOR.format(similarity_function)):
            cql.execute(f"SELECT pk, similarity_{similarity_function}('a', [1.1, 1.2, 20.25]) FROM {table}")
        with pytest.raises(InvalidRequest, match="Type error" if is_scylla(cql) else REQUIRES_FLOAT_VECTOR.format(similarity_function)):
            cql.execute(f"SELECT pk, similarity_{similarity_function}([1.1, 1.2, 20.25], 'b') FROM {table}")
        with pytest.raises(InvalidRequest, match="Type error" if is_scylla(cql) else REQUIRES_FLOAT_VECTOR.format(similarity_function)):
            cql.execute(f"SELECT pk, similarity_{similarity_function}({{1.0, 2.0, 3.0}}, {{4.0, 5.0, 6.0}}) FROM {table}")
        with pytest.raises(InvalidRequest, match="Type error" if is_scylla(cql) else REQUIRES_FLOAT_VECTOR.format(similarity_function)):
            cql.execute(f"SELECT pk, similarity_{similarity_function}({{1.0, 2.0, 3.0}}, [1.1, 1.2, 20.25]) FROM {table}")
        with pytest.raises(InvalidRequest, match="Type error" if is_scylla(cql) else REQUIRES_FLOAT_VECTOR.format(similarity_function)):
            cql.execute(f"SELECT pk, similarity_{similarity_function}([1.1, 1.2, 20.25], {{4.0, 5.0, 6.0}}) FROM {table}")


@pytest.mark.parametrize("similarity_function", ["cosine", "euclidean", "dot_product"])
def test_vector_similarity_returns_null_on_null_arguments(cql, test_keyspace, similarity_function):
    schema = 'pk int primary key, v vector<float, 3>'
    with new_test_table(cql, test_keyspace, schema) as table:
        cql.execute(f"INSERT INTO {table} (pk, v) VALUES (1, [1.0, 2.0, 3.0])")
        result = cql.execute(f"SELECT pk, similarity_{similarity_function}(null, [1.1, 1.2, 20.25]) FROM {table}")
        for row in result:
            assert row[1] is None
        result = cql.execute(f"SELECT pk, similarity_{similarity_function}(v, null) FROM {table}")
        for row in result:
            assert row[1] is None
        if is_scylla(cql):
            result = cql.execute(f"SELECT pk, similarity_{similarity_function}(null, null) FROM {table}")
            for row in result:
                assert row[1] is None
        else:
            with pytest.raises(InvalidRequest, match="Cannot infer type of argument NULL"):
                cql.execute(f"SELECT pk, similarity_{similarity_function}(null, null) FROM {table}")


@pytest.mark.parametrize("similarity_function", ["cosine", "euclidean", "dot_product"])
def test_vector_similarity_allow_both_vector_columns_and_literals_as_arguments(cql, test_keyspace, similarity_function):
    schema = 'pk int primary key, v1 vector<float, 3>, v2 vector<float, 3>'
    with new_test_table(cql, test_keyspace, schema) as table:
        cql.execute(f"INSERT INTO {table} (pk, v1, v2) VALUES (1, [1.0, 2.0, 3.0], [4.0, 5.0, 6.0])")
        cql.execute(f"SELECT pk, similarity_{similarity_function}([1.1, 1.2, 20.25], [1.8, 0.5, 20.03]) FROM {table}")
        cql.execute(f"SELECT pk, similarity_{similarity_function}(v1, v2) FROM {table}")
        cql.execute(f"SELECT pk, similarity_{similarity_function}(v1, [1.8, 0.5, 20.03]) FROM {table}")
        cql.execute(f"SELECT pk, similarity_{similarity_function}([1.1, 1.2, 20.25], v2) FROM {table}")


@pytest.mark.parametrize("similarity_function", ["cosine", "euclidean", "dot_product"])
def test_vector_similarity_fails_on_vector_of_different_size(cql, test_keyspace, similarity_function):
    schema = 'pk int primary key, v vector<float, 3>'
    with new_test_table(cql, test_keyspace, schema) as table:
        cql.execute(f"INSERT INTO {table} (pk, v) VALUES (1, [1.0, 2.0, 3.0])")
        with pytest.raises(InvalidRequest, match="Invalid vector literal" if is_scylla(cql) else "All arguments must have the same vector dimensions"):
            cql.execute(f"SELECT pk, similarity_{similarity_function}(v, [1.1, 1.2]) FROM {table}")
        with pytest.raises(InvalidRequest, match="Invalid vector literal" if is_scylla(cql) else "All arguments must have the same vector dimensions"):
            cql.execute(f"SELECT pk, similarity_{similarity_function}(v, [1.1, 1.2, 20.25, 123.7]) FROM {table}")
        with pytest.raises(InvalidRequest, match="All arguments must have the same vector dimensions"):
            cql.execute(f"SELECT pk, similarity_{similarity_function}([1.0, 2.0, 3.0], [1.1, 1.2]) FROM {table}")
        with pytest.raises(InvalidRequest, match="All arguments must have the same vector dimensions"):
            cql.execute(f"SELECT pk, similarity_{similarity_function}([1.0, 2.0, 3.0], [1.1, 1.2, 20.25, 123.7]) FROM {table}")


def calculate_distance(similarity_function, v1, v2):
    if similarity_function == "cosine":
        dot = sum(a * b for a, b in zip(v1, v2))
        norm_v = math.sqrt(sum(x**2 for x in v1))
        norm_q = math.sqrt(sum(x**2 for x in v2))
        cosine = dot / (norm_v * norm_q) if norm_v * norm_q != 0 else 0
        return round((1 + cosine) / 2, 6)
    elif similarity_function == "euclidean":
        euclidean_sq = sum((a - b)**2 for a, b in zip(v1, v2))
        return round(1 / (1 + euclidean_sq), 6)
    elif similarity_function == "dot_product":
        dot_product = sum(a * b for a, b in zip(v1, v2))
        return round((1 + dot_product) / 2, 6)


@pytest.mark.parametrize("similarity_function", ["cosine", "euclidean", "dot_product"])
def test_vector_similarity_with_column_and_literal(cql, test_keyspace, similarity_function):
    schema = 'pk int primary key, v vector<float, 3>'
    data = [
        [0.267261, 0.534522, 0.801784],
        [0.455842, 0.569803, 0.683763],
        [0.502571, 0.574367, 0.646162],
    ]
    query_vector = [0.707107, 0.0, -0.707107]

    with new_test_table(cql, test_keyspace, schema) as table:
        cql.execute(f"INSERT INTO {table} (pk, v) VALUES (1, {data[0]})")
        cql.execute(f"INSERT INTO {table} (pk, v) VALUES (2, {data[1]})")
        cql.execute(f"INSERT INTO {table} (pk, v) VALUES (3, {data[2]})")
        result = cql.execute(f"SELECT v, similarity_{similarity_function}(v, {query_vector}) FROM {table}")
        for row in result:
            assert round(row[1], 6) == calculate_distance(similarity_function, row.v, query_vector)


@pytest.mark.parametrize("similarity_function", ["cosine", "euclidean", "dot_product"])
def test_vector_similarity_with_two_columns(cql, test_keyspace, similarity_function):
    schema = 'pk int primary key, v1 vector<float, 3>, v2 vector<float, 3>'
    data = [
        [0.267261, 0.534522, 0.801784],
        [0.455842, 0.569803, 0.683763],
        [0.502571, 0.574367, 0.646162],
    ]
    query_vector = [0.707107, 0.0, -0.707107]

    with new_test_table(cql, test_keyspace, schema) as table:
        cql.execute(f"INSERT INTO {table} (pk, v1, v2) VALUES (1, {data[0]}, {query_vector})")
        cql.execute(f"INSERT INTO {table} (pk, v1, v2) VALUES (2, {data[1]}, {query_vector})")
        cql.execute(f"INSERT INTO {table} (pk, v1, v2) VALUES (3, {data[2]}, {query_vector})")
        result = cql.execute(f"SELECT v1, v2, similarity_{similarity_function}(v1, v2) FROM {table}")
        for row in result:
            assert round(row[2], 6) == calculate_distance(similarity_function, row.v1, row.v2)


@pytest.mark.parametrize("similarity_function", ["cosine", "euclidean", "dot_product"])
def test_vector_similarity_with_two_literals(cql, test_keyspace, similarity_function):
    schema = 'pk int primary key'
    v1 = [0.267261, 0.534522, 0.801784]
    v2 = [0.707107, 0.0, -0.707107]

    with new_test_table(cql, test_keyspace, schema) as table:
        cql.execute(f"INSERT INTO {table} (pk) VALUES (1)")
        result = cql.execute(f"SELECT pk, similarity_{similarity_function}({v1}, {v2}) FROM {table}")
        for row in result:
            assert round(row[1], 6) == calculate_distance(similarity_function, v1, v2)


# Based on https://cassandra.apache.org/doc/5.0/cassandra/developing/cql/functions.html#vector-similarity-functions
@pytest.mark.parametrize("similarity_function", ["cosine", "euclidean", "dot_product"])
def test_cassandra_documentation_compatibility(cql, test_keyspace, similarity_function):
    schema = 'pk int primary key, v vector<float, 2>'
    expected_results = {
        "cosine": [1.0, 0.0, 0.964238],
        "euclidean": [1.0, 0.833333, 0.5],
        "dot_product": [0.525, 0.475, 0.625],
    }

    with new_test_table(cql, test_keyspace, schema) as table:
        cql.execute(f"INSERT INTO {table} (pk, v) VALUES (0, [0.1, 0.2])")
        result = cql.execute(f"SELECT pk, similarity_{similarity_function}(v, null) FROM {table}")
        for row in result:
            assert row[1] is None
        result = cql.execute(f"SELECT pk, similarity_{similarity_function}(v, [0.1, 0.2]) FROM {table}")
        for row in result:
            assert round(row[1], 6) == expected_results[similarity_function][0]
        result = cql.execute(f"SELECT pk, similarity_{similarity_function}(v, [-0.1, -0.2]) FROM {table}")
        for row in result:
            assert round(row[1], 6) == expected_results[similarity_function][1]
        result = cql.execute(f"SELECT pk, similarity_{similarity_function}(v, [0.9, 0.8]) FROM {table}")
        for row in result:
            assert round(row[1], 6) == expected_results[similarity_function][2]

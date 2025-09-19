# Copyright 2025-present ScyllaDB
#
# SPDX-License-Identifier: LicenseRef-ScyllaDB-Source-Available-1.0

import pytest
from .util import new_test_table, is_scylla
from cassandra.protocol import InvalidRequest


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

# Copyright 2025-present ScyllaDB
#
# SPDX-License-Identifier: LicenseRef-ScyllaDB-Source-Available-1.0

#############################################################################
# Tests for limits on the *names* of keyspaces, tables, indexes, views, function and columns.
#
# These tests are designed to run on both ScyllaDB and Cassandra. Because the two databases
# impose different naming limits, the tests focus on the ranges and behaviors that are common
# or relevant to both systems.
#
# For objects whose name length limit is based on the table name (tables, indexes, views):
#   1. The tests verify that it is possible to create such an object with a name up to 207 characters (the ScyllaDB limit).
#   2. The tests verify that creating such an object with a name longer than 222 characters (the Cassandra limit) fails gracefully.
#
# For keyspaces:
#   1. The tests verify that it is possible to create a keyspace with a name up to 48 characters (the Cassandra limit).
#   2. The tests verify that creating a keyspace with a name longer than 207 characters (the ScyllaDB limit) fails gracefully.
#
# For columns and functions:
#   - The tests verify that it is possible to create columns and functions with long names, as they are not subject to the same limits as tables or keyspaces.
#############################################################################

import pytest
import re
from contextlib import contextmanager
from cassandra.protocol import InvalidRequest
from .util import unique_name, new_test_table, new_secondary_index, new_function, is_scylla

# This context manager is similar to new_test_table() - creating a table and
# keeping it alive while the context manager is in scope - but allows the
# caller to pick the name of the table. This is useful to attempt to create
# a table whose name has different lengths or characters.
# Note that if used in a shared keyspace, it is recommended to base the
# given table name on the output of unique_name(), to avoid name clashes.
# See the padded_name() function below as an example.
@contextmanager
def new_named_table(cql, keyspace, table, schema, extra=""):
    tbl  = keyspace+'.'+table
    cql.execute(f'CREATE TABLE {tbl} ({schema}) {extra}')
    try:
        yield tbl
    finally:
        cql.execute(f'DROP TABLE {tbl}')

# padded_name() creates a unique name of given length by taking the
# output of unique_name() and padding it with extra 'x' characters:
def padded_name(length):
    u = unique_name()
    assert length >= len(u)
    return u + 'x'*(length-len(u))

# The ScyllaDB names limit. Check schema::NAME_LENGTH definition for details.
SCYLLA_NAME_MAX_LENGTH = 207

# Cassandra's documentation states that "Both keyspace and table name ... are
# limited in size to 48 characters". This was actually only true in Cassandra
# 3, and by Cassandra 4 and 5 this limitation was dropped for table name (see discussion
# in CASSANDRA-20425).
# The current effective limit is 222 characters, derived from the filesystem's 255-byte
# name limit minus 33 bytes reserved for a UUID and separator.
CASSANDRA_TABLE_NAME_MAX_LENGTH = 222

# Utility function to create a new keyspace with the given name.
# Created to avoid passing the same replication option in every tests.
@contextmanager
def new_keyspace(cql, ks_name=unique_name()):
    # keyspace = unique_name()
    cql.execute(f"CREATE KEYSPACE {ks_name} WITH REPLICATION = {{'class': 'SimpleStrategy', 'replication_factor': 1}}")
    try:
        yield ks_name
    finally:
        cql.execute(f"DROP KEYSPACE {ks_name}")

# Utility function to create a new table with the given name.
# Created to avoid passing the same schema option in every tests.
@contextmanager
def new_table(cql, ks_name, tbl_name=unique_name(), extra=""):
    qualified_table_name = ks_name + '.' + tbl_name
    cql.execute(f'CREATE TABLE {qualified_table_name} (p int, x int, PRIMARY KEY (p)) {extra}')
    try:
        yield qualified_table_name
    finally:
        cql.execute(f'DROP TABLE {qualified_table_name}')

# Utility function to create a materialized view with the given name.
# Created to avoid passing the same parameter values in every tests.
@contextmanager
def new_mv(cql, qualified_table_name, mv_name):
    keyspace = qualified_table_name.split('.')[0]
    qualified_mv_name = keyspace + "." + mv_name
    cql.execute(
        f"CREATE MATERIALIZED VIEW {qualified_mv_name} AS SELECT * FROM {qualified_table_name} WHERE p is not null and x is not null PRIMARY KEY (p, x)"
    )
    try:
        yield qualified_mv_name
    finally:
        cql.execute(f"DROP MATERIALIZED VIEW {qualified_mv_name}")


# Verifies that a table name equal Scylla limit (207 characters) is accepted.
# Reproduces #4480".
def test_table_name_length_eq_scylla_limit(cql, test_keyspace):
    with new_table(cql, test_keyspace, padded_name(SCYLLA_NAME_MAX_LENGTH)):
        pass

# Verifies that a table name longer than Cassandra limit (222 characters) is rejected with an InvalidRequest exception.
# The error message must contain the name of the table to indicate what actually is invalid for the client.
# With 223 characters, we run into the problem that an attempt to create a file or directory name based
# on the table name will fail. Even if we lift the 48-character limitation
# introduced in Cassandra 3, creating a 223-character name should fail gracefully.
# We mark this test cassandra_bug because Cassandra 5 hangs on this test (CASSANDRA-20425 and CASSANDRA-20389).
def test_table_name_length_gt_than_cassandra_limit(cql, test_keyspace, cassandra_bug):
    name = padded_name(CASSANDRA_TABLE_NAME_MAX_LENGTH + 1)
    with pytest.raises(InvalidRequest, match=name):
        with new_table(cql, test_keyspace, name):
            pass

# Verifies that a table name equal Scylla limit (207 characters) is accepted when CDC is enabled.
def test_table_name_length_eq_scylla_limit_and_cdc_enabled(cql, scylla_only):
    # Incompatible Cassandra <-> Scylla API to enable CDC. See #9859.
    cdc = "{'enabled': true}" if is_scylla(cql) else 'true'
    with new_keyspace(cql, ) as keyspace:
        with new_table(
                cql,
                keyspace,
                padded_name(SCYLLA_NAME_MAX_LENGTH),
                extra=f"with CDC = {cdc}",
        ):
            pass

# Verifies that a keyspace name equal Cassandra limit (48 characters) is accepted.
def test_keyspace_name_length_eq_cassandra_limit(cql):
    with new_keyspace(
            cql,
            name=padded_name(48),
    ):
        pass

# Verifies that a keyspace name longer than Scylla limit (207 characters) is rejected with an InvalidRequest exception.
# The error message must contain the name of the keyspace to indicate what actually is invalid for the client.
def test_keyspace_name_length_gt_than_scylla_limit(cql):
    name = padded_name(SCYLLA_NAME_MAX_LENGTH + 1)
    with pytest.raises(InvalidRequest, match=name):
        with new_keyspace(
                cql,
                name=name,
        ):
            pass

# Verifies that a materialized view name equal Scylla limit (207 characters) is accepted.
def test_mv_name_length_eq_scylla_limit(cql, test_keyspace):
    with new_table(cql, test_keyspace) as table:
        with new_mv(
                cql,
                table,
                padded_name(SCYLLA_NAME_MAX_LENGTH),
        ):
            pass

# Verifies that a materialized view name longer than Cassandra limit (222 characters) is rejected with an InvalidRequest exception.
# The error message must contain the name of the materialized view to indicate what actually is invalid for the client.
# This test is marked as cassandra_bug because Cassandra 5 hangs on this test (CASSANDRA-20425 and CASSANDRA-20389).
def test_mv_name_length_gt_than_cassandra_limit(cql, test_keyspace, cassandra_bug):
    name = padded_name(CASSANDRA_TABLE_NAME_MAX_LENGTH + 1)
    with new_table(cql, test_keyspace) as table:
        with pytest.raises(InvalidRequest, match=name):
            with new_mv(
                    cql,
                    table,
                    name,
            ):
                pass

# Verifies that a secondary index name equal Scylla limit (207 characters) is accepted.
def test_index_name_length_eq_scylla_limit(cql, test_keyspace):
    with new_table(cql, test_keyspace) as table:
        with new_secondary_index(cql, table, "x", padded_name(SCYLLA_NAME_MAX_LENGTH)):
            pass

# Verifies that a secondary index name longer than Cassandra limit (222 characters) is rejected with an InvalidRequest exception.
# The error message must contain the name of the index to indicate what actually is invalid for the client.
# This test is marked as cassandra_bug because Cassandra 5 hangs on this test (CASSANDRA-20425 and CASSANDRA-20389).
def test_index_name_length_gt_than_cassandra_limit(cql, test_keyspace , cassandra_bug):
    name = padded_name(CASSANDRA_TABLE_NAME_MAX_LENGTH + 1)
    with new_table(cql, test_keyspace) as table:
        with pytest.raises(InvalidRequest, match=name):
            with new_secondary_index(cql, table, "x", name):
                pass

# Verifies that function names are not limited.
def test_function_name_length(cql, test_keyspace):
    # ScyllaDB by default supports Lua functions while Cassandra Java only.
    # In this test we only want to verify function name, hence function body is not important.
    # func = is_scylla(cql) and lua_fun or java_fun
    lang = "lua" if is_scylla(cql) else "java"
    with new_function(
            cql,
            test_keyspace,
            f"() CALLED ON NULL INPUT RETURNS int LANGUAGE {lang} AS 'return 0;'",
            name=padded_name(SCYLLA_NAME_MAX_LENGTH * 2),
    ):
        pass

# Verifies that column names are not limited.
def test_column_name_length(cql, test_keyspace):
    with new_test_table(
            cql,
            test_keyspace,
            "p int primary key, " + padded_name(SCYLLA_NAME_MAX_LENGTH) * 2 + " int",
    ):
        pass

# TODO: add tests for the allowed characters in a table name
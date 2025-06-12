# Copyright 2025-present ScyllaDB
#
# SPDX-License-Identifier: LicenseRef-ScyllaDB-Source-Available-1.0

#############################################################################
# Tests for limits on the *names* of keyspaces, tables, indexes, views, function and columns.
#############################################################################

import pytest
import re
from contextlib import contextmanager
from cassandra.protocol import InvalidRequest
from .util import (
    unique_name,
    new_named_test_table,
    new_test_table,
    new_test_keyspace,
    new_secondary_index,
    new_materialized_view,
    new_function,
)


# passes_or_raises() is similar to pytest.raises(), except that while raises()
# expects a certain exception must happen, the new passes_or_raises()
# expects the code to either pass (not raise), or if it throws, it must
# throw the specific specified exception.
# This function is useful for tests that want to verify that if some feature
# is still not supported, it must throw some expected graceful error, but
# if one day it *will* be supported, the test should continue to pass.
@contextmanager
def passes_or_raises(expected_exception, match=None):
    # Sadly __tracebackhide__=True only drops some of the unhelpful backtrace
    # lines. See https://github.com/pytest-dev/pytest/issues/2057
    __tracebackhide__ = True
    try:
        yield
        # The user's "with" code is running during the yield. If it didn't
        # throw we return from the function - passes_or_raises() succeeded
        # in the "passes" case.
        return
    except expected_exception as err:
        if match == None or re.search(match, str(err)):
            # The passes_or_raises() succeeded in the "raises" case
            return
        pytest.fail(f"exception message '{err}' did not match '{match}'")
    except Exception as err:
        pytest.fail(
            f"Got unexpected exception type {type(err).__name__} instead of {expected_exception.__name__}: {err}"
        )


# padded_name() creates a unique name of given length by taking the
# output of unique_name() and padding it with extra 'x' characters:
def padded_name(length):
    u = unique_name()
    assert length >= len(u)
    return u + "x" * (length - len(u))


# The schema for the test tables used in this module.
SCHEMA = "p int, x int, PRIMARY KEY (p)"

# ScyllaDB names limit. Check schema::NAME_LENGTH definition for details.
MAX_NAME_LENGTH = 207


# Cassandra's documentation states that "Both keyspace and table name ... are
# limited in size to 48 characters". This was actually only true in Cassandra
# 3, and by Cassandra 4 and 5 this limitation was dropped (see discussion
# in CASSANDRA-20425).
# Verifies that a table name of exactly 207 characters is accepted.
# Reproduces #4480".
def test_table_name_length_eq_scylla_limit(cql, test_keyspace):
    with new_named_test_table(
        cql,
        test_keyspace,
        padded_name(MAX_NAME_LENGTH),
        SCHEMA,
    ):
        pass


# Verifies that a table name longer than the Scylla limit (207 characters)
# is accepted (Cassandra 4/5) or rejected with an InvalidRequest exception (Scylla/Cassandra 3).
# The error message must contain the name of the table, so that we can
# verify that the test is actually testing the name length limit, and not
# some other error.
def test_table_name_length_gt_the_scylla_limit(cql, test_keyspace):
    name = padded_name(MAX_NAME_LENGTH + 1)
    with passes_or_raises(InvalidRequest, match=name):
        with new_named_test_table(cql, test_keyspace, name, SCHEMA):
            pass


# Verifies that attempting to create a table with a name significantly longer than the limit
# (e.g., 500 characters—which exceeds the Linux filesystem limit of 255 characters)
# is gracefully rejected with an InvalidRequest exception.
# This test is disabled for Cassandra because it causes a hang
# (see CASSANDRA-20425 and CASSANDRA-20389).
def test_table_name_length_500(cql, test_keyspace, cassandra_bug):
    name = padded_name(500)
    with pytest.raises(InvalidRequest, match=name):
        with new_named_test_table(cql, test_keyspace, name, SCHEMA):
            pass


# Verifies that a table name of exactly 207 characters is accepted when CDC is enabled.
def test_table_name_length_eq_scylla_limit_and_cdc_enabled(cql):
    with new_test_keyspace(
        cql, "WITH REPLICATION = {'class': 'SimpleStrategy', 'replication_factor': 1}"
    ) as keyspace:
        with new_named_test_table(
            cql,
            keyspace,
            padded_name(MAX_NAME_LENGTH),
            SCHEMA,
            extra="with cdc = {'enabled': true}",
        ):
            pass


# Verifies that a keyspace name of exactly 207 characters is accepted.
def test_keyspace_name_length_eq_scylla_limit(cql):
    with new_test_keyspace(
        cql,
        "WITH REPLICATION = {'class': 'SimpleStrategy', 'replication_factor': 1}",
        name=padded_name(MAX_NAME_LENGTH),
    ):
        pass


# Verifies that a keyspace name longer than 207 characters is accepted (Cassandra 4/5)
# or rejected with an InvalidRequest exception (Scylla/Cassandra 3).
# The error message must contain the name of the keyspace, so that we can
# verify that the test is actually testing the name length limit, and not
# some other error.
def test_keyspace_name_length_gt_than_scylla_limit(cql):
    name = padded_name(MAX_NAME_LENGTH + 1)
    with passes_or_raises(InvalidRequest, match=name):
        with new_test_keyspace(
            cql,
            "WITH REPLICATION = {'class': 'SimpleStrategy', 'replication_factor': 1}",
            name=name,
        ):
            pass


# Verifies that a materialized view name of exactly 207 characters is accepted.
def test_mv_name_length_eq_scylla_limit(cql, test_keyspace):
    with new_test_table(cql, test_keyspace, SCHEMA) as table:
        pass
        with new_materialized_view(
            cql,
            table,
            "*",
            "p, x",
            "p is not null and x is not null",
            name=padded_name(MAX_NAME_LENGTH),
        ):
            pass


# Verifies that a materialized view name longer than 207 characters is accepted (Cassandra 4/5)
# or rejected with an InvalidRequest exception (Scylla/Cassandra 3).
# The error message must contain the name of the view, so that we can
# verify that the test is actually testing the name length limit, and not
# some other error.
def test_mv_name_length_gt_than_scylla_limit(cql, test_keyspace):
    name = padded_name(MAX_NAME_LENGTH + 1)
    with new_test_table(cql, test_keyspace, SCHEMA) as table:
        with passes_or_raises(InvalidRequest, match=name):
            with new_materialized_view(
                cql,
                table,
                "*",
                "p, x",
                "p is not null and x is not null",
                name=name,
            ):
                pass


# Verifies that a secondary index name of exactly 207 characters is accepted.
def test_index_name_length_eq_scylla_limit(cql, test_keyspace):
    with new_test_table(cql, test_keyspace, SCHEMA) as table:
        with new_secondary_index(cql, table, "x", padded_name(MAX_NAME_LENGTH)):
            pass


# Verifies that a secondary index name longer than 207 characters is accepted (Cassandra 4/5)
# or rejected with an InvalidRequest exception (Scylla/Cassandra 3).
# The error message must contain the name of the index, so that we can
# verify that the test is actually testing the name length limit, and not
# some other error.
def test_index_name_length_gt_than_scylla_limit(cql, test_keyspace):
    name = padded_name(MAX_NAME_LENGTH + 1)
    with new_test_table(cql, test_keyspace, SCHEMA) as table:
        with passes_or_raises(InvalidRequest, match=name):
            with new_secondary_index(cql, table, "x", name):
                pass


# Verifies that a column name of exactly 207 characters is accepted.
def test_column_name_length_eq_scylla_limit(cql, test_keyspace):
    with new_test_table(
        cql,
        test_keyspace,
        "p int primary key, " + padded_name(MAX_NAME_LENGTH) + " int",
    ):
        pass


# Verifies that a column name longer than 207 characters is accepted (Cassandra 4/5)
# or rejected with an InvalidRequest exception (Scylla/Cassandra 3).
# The error message must contain the name of the column, so that we can
# verify that the test is actually testing the name length limit, and not
# some other error.
def test_column_name_length_gt_than_scylla_limit(cql, test_keyspace):
    name = padded_name(MAX_NAME_LENGTH + 1)
    with passes_or_raises(InvalidRequest, match=name):
        with new_test_table(cql, test_keyspace, "p int primary key, " + name + " int"):
            pass


# Verifies that function names are not limited by MAX_NAME_LENGTH (can be much longer).
def test_function_name_length(cql, test_keyspace):
    with new_function(
        cql,
        test_keyspace,
        """
     ()
     CALLED ON NULL INPUT
     RETURNS int
     LANGUAGE lua
     AS 'return 0'
     """,
        name=padded_name(MAX_NAME_LENGTH * 2),
    ):
        pass

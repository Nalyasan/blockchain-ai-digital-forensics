"""Conflict-detecting, append-only persistence for accepted forensic records."""
import json
import sqlite3


class EvidenceConflictError(sqlite3.IntegrityError):
    """An existing identity has different forensic content."""


def insert_verified(conn, table, record, keys, *, replay_metadata=(), json_fields=()):
    """Insert or verify an identical replay, retaining the original stored bytes.

    Table/column names are internal constants, never external input. The INSERT
    acquires SQLite's write lock before checking a uniqueness conflict, so two
    concurrent writers cannot silently replace one another. Callers own commits.
    Only explicitly designated collection/generation timestamps may differ.
    """
    columns = tuple(record)
    try:
        conn.execute(
            f"INSERT INTO {table} ({','.join(columns)}) "
            f"VALUES ({','.join('?' for _ in columns)})",
            tuple(record.values()),
        )
        return True
    except sqlite3.IntegrityError:
        row = conn.execute(
            f"SELECT {','.join(columns)} FROM {table} WHERE "
            + ' AND '.join(f'{key} IS ?' for key in keys),
            tuple(record[key] for key in keys),
        ).fetchone()
        if row is None:
            raise
        for column, old in zip(columns, row):
            if column in replay_metadata:
                continue
            new = record[column]
            if column in json_fields:
                old, new = json.loads(old), json.loads(new)
            if old != new:
                raise EvidenceConflictError(f'{table}: conflicting {column} for accepted identity')
        return False

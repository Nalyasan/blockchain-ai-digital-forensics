"""P5 AI Investigator Read-Only Database Connection Layer.

This module provides hardened, strictly read-only and immutable SQLite connections
for forensics tools, reference checkers, and incident evaluations.

Security Guarantees:
1. File/VFS Layer: Opens databases using URI `file:<path>?mode=ro&immutable=1`.
   Prevents SQLite from opening write file descriptors, journal creation, or WAL writes.
2. Engine Layer: Sets `PRAGMA query_only = ON;`.
   Prevents query planner from executing any state-mutating queries.
3. Authorizer Layer: Registers SQLite authorizer denying write/DDL/ATTACH opcodes.
4. Python Guard Layer: Guarded connection & cursor wrappers intercept modifying
   keywords (INSERT, UPDATE, DELETE, CREATE, DROP, ALTER, ATTACH, DETACH, REPLACE, VACUUM)
   and explicitly raise `sqlite3.OperationalError`.
5. Fail-Closed: Missing database files immediately raise `sqlite3.OperationalError`.
6. G5-02 Invariant: Strictly zero insert-or-replace statements.
"""

import re
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator, Union

__all__ = [
    "get_readonly_connection",
    "readonly_connection",
    "build_readonly_uri",
    "ReadOnlyConnection",
    "ReadOnlyCursor",
]

_WRITE_KEYWORDS_REGEX = re.compile(
    r"^\s*(INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|ATTACH|DETACH|REPLACE|VACUUM|REINDEX|TRUNCATE)\b",
    re.IGNORECASE,
)

_DENIED_AUTHORIZER_ACTIONS = {
    getattr(sqlite3, name)
    for name in [
        "SQLITE_INSERT",
        "SQLITE_UPDATE",
        "SQLITE_DELETE",
        "SQLITE_CREATE_TABLE",
        "SQLITE_DROP_TABLE",
        "SQLITE_ALTER_TABLE",
        "SQLITE_CREATE_INDEX",
        "SQLITE_DROP_INDEX",
        "SQLITE_CREATE_VIEW",
        "SQLITE_DROP_VIEW",
        "SQLITE_CREATE_TRIGGER",
        "SQLITE_DROP_TRIGGER",
        "SQLITE_CREATE_TEMP_TABLE",
        "SQLITE_DROP_TEMP_TABLE",
        "SQLITE_CREATE_TEMP_INDEX",
        "SQLITE_DROP_TEMP_INDEX",
        "SQLITE_CREATE_TEMP_VIEW",
        "SQLITE_DROP_TEMP_VIEW",
        "SQLITE_CREATE_TEMP_TRIGGER",
        "SQLITE_DROP_TEMP_TRIGGER",
        "SQLITE_ATTACH",
        "SQLITE_DETACH",
        "SQLITE_TRANSACTION",
    ]
    if hasattr(sqlite3, name)
}


def readonly_authorizer(
    action: int,
    arg1: str | None,
    arg2: str | None,
    db_name: str | None,
    trigger_name: str | None,
) -> int:
    """Authorizer callback rejecting any DDL, modification, or attachment."""
    if action in _DENIED_AUTHORIZER_ACTIONS:
        return sqlite3.SQLITE_DENY
    return sqlite3.SQLITE_OK


class ReadOnlyCursor(sqlite3.Cursor):
    """Guarded cursor raising OperationalError on any write or DDL statement."""

    def execute(self, sql: str, *args, **kwargs):
        if _WRITE_KEYWORDS_REGEX.match(sql):
            first_word = sql.strip().split()[0].upper()
            raise sqlite3.OperationalError(
                f"Write/DDL operation prohibited on read-only connection: {first_word}"
            )
        try:
            return super().execute(sql, *args, **kwargs)
        except sqlite3.DatabaseError as e:
            if not isinstance(e, sqlite3.OperationalError):
                raise sqlite3.OperationalError(f"Database operation rejected: {e}") from e
            raise

    def executemany(self, sql: str, *args, **kwargs):
        if _WRITE_KEYWORDS_REGEX.match(sql):
            first_word = sql.strip().split()[0].upper()
            raise sqlite3.OperationalError(
                f"Write/DDL operation prohibited on read-only connection: {first_word}"
            )
        try:
            return super().executemany(sql, *args, **kwargs)
        except sqlite3.DatabaseError as e:
            if not isinstance(e, sqlite3.OperationalError):
                raise sqlite3.OperationalError(f"Database operation rejected: {e}") from e
            raise

    def executescript(self, sql_script: str):
        for stmt in sql_script.split(";"):
            cleaned = stmt.strip()
            if cleaned and _WRITE_KEYWORDS_REGEX.match(cleaned):
                first_word = cleaned.split()[0].upper()
                raise sqlite3.OperationalError(
                    f"Script contains prohibited write/DDL statement: {first_word}"
                )
        try:
            return super().executescript(sql_script)
        except sqlite3.DatabaseError as e:
            if not isinstance(e, sqlite3.OperationalError):
                raise sqlite3.OperationalError(f"Script execution rejected: {e}") from e
            raise


class ReadOnlyConnection(sqlite3.Connection):
    """Guarded SQLite connection ensuring strict read-only and immutable invariants."""

    def cursor(self, factory=ReadOnlyCursor) -> ReadOnlyCursor:
        return super().cursor(factory=factory)

    def execute(self, sql: str, *args, **kwargs):
        if _WRITE_KEYWORDS_REGEX.match(sql):
            first_word = sql.strip().split()[0].upper()
            raise sqlite3.OperationalError(
                f"Write/DDL operation prohibited on read-only connection: {first_word}"
            )
        try:
            return super().execute(sql, *args, **kwargs)
        except sqlite3.DatabaseError as e:
            if not isinstance(e, sqlite3.OperationalError):
                raise sqlite3.OperationalError(f"Database operation rejected: {e}") from e
            raise

    def executemany(self, sql: str, *args, **kwargs):
        if _WRITE_KEYWORDS_REGEX.match(sql):
            first_word = sql.strip().split()[0].upper()
            raise sqlite3.OperationalError(
                f"Write/DDL operation prohibited on read-only connection: {first_word}"
            )
        try:
            return super().executemany(sql, *args, **kwargs)
        except sqlite3.DatabaseError as e:
            if not isinstance(e, sqlite3.OperationalError):
                raise sqlite3.OperationalError(f"Database operation rejected: {e}") from e
            raise

    def executescript(self, sql_script: str):
        for stmt in sql_script.split(";"):
            cleaned = stmt.strip()
            if cleaned and _WRITE_KEYWORDS_REGEX.match(cleaned):
                first_word = cleaned.split()[0].upper()
                raise sqlite3.OperationalError(
                    f"Script contains prohibited write/DDL statement: {first_word}"
                )
        try:
            return super().executescript(sql_script)
        except sqlite3.DatabaseError as e:
            if not isinstance(e, sqlite3.OperationalError):
                raise sqlite3.OperationalError(f"Script execution rejected: {e}") from e
            raise


def build_readonly_uri(db_path: Union[str, Path]) -> str:
    """Builds a strict read-only and immutable SQLite URI for the target database file."""
    p = Path(db_path).resolve()
    if not p.is_file():
        raise sqlite3.OperationalError(f"Database file not found: {p}")
    return f"{p.as_uri()}?mode=ro&immutable=1"


def get_readonly_connection(
    db_path: Union[str, Path], timeout: float = 5.0
) -> ReadOnlyConnection:
    """Connects to SQLite database in strict read-only and immutable mode.

    Guarantees:
    - Opened via SQLite URI: file:<path>?mode=ro&immutable=1
    - Enforces PRAGMA query_only = ON;
    - Registers authorizer callback denying write/DDL/attach opcodes
    - Raises sqlite3.OperationalError on any write or DDL attempt
    - Uses sqlite3.Row as default row_factory
    """
    uri = build_readonly_uri(db_path)
    conn = sqlite3.connect(
        uri,
        uri=True,
        timeout=timeout,
        factory=ReadOnlyConnection,
    )
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA query_only = ON;")
    conn.set_authorizer(readonly_authorizer)
    return conn


@contextmanager
def readonly_connection(
    db_path: Union[str, Path], timeout: float = 5.0
) -> Iterator[ReadOnlyConnection]:
    """Context manager yielding a strictly read-only SQLite connection."""
    conn = get_readonly_connection(db_path, timeout=timeout)
    try:
        yield conn
    finally:
        conn.close()

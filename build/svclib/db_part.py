"""svc db: databases (postgres, mysql/mariadb) through a local tunnel."""
import os
import re
import subprocess
import sys

import tclib  # shared with tentacontrol (lib/tclib.py)

from . import core, gate, safeguards


# ---------- databases (db) ----------

DB_RO_BYPASS = re.compile(r"read\s+write|default_transaction_read_only|transaction_read_only|tx_read_only|"
                          r"session\s+characteristics|\bset\s+role\b|\bset\s+session\s+authorization\b", re.I)
# outside '…' literals: comments, dollar and unicode quoting, dynamic SQL and server-side files – a read-only session
# only gets SQL whose text both the check and the engine read the same way, and that can't leave the session
DB_RO_REFUSE = re.compile(r"--|#|/\*|\$|\bu&|\b(execute|exec|prepare|do|call|set_config|dblink\w*|query_to_xml\w*|"
                          r"copy|lo_\w+|pg_\w*file\w*|outfile|dumpfile)\b", re.I)


def ro_bypass(sql, pg=True):
    """True when SQL may leave a read-only session (switch it to read-write, run text as SQL, write server files) –
    or the check can't tell. Text in plain '…' literals and SHOW statements (they only read a setting) don't count"""
    if "\\" in sql:  # an escape in mysql, a plain character in postgres: the engines would split the text differently
        return True
    quotes = "'\"" if pg else "'\"`"  # backticks only quote in mysql
    out, i, n = [], 0, len(sql)
    while i < n:
        c = sql[i]
        if c in quotes:  # '…' dropped, "…"/`…` (identifiers, in mysql also "…" strings) kept
            j = i + 1
            while j < n and not (sql[j] == c and not (j + 1 < n and sql[j + 1] == c)):
                j += 2 if sql[j] == c else 1
            out.append("''" if c == "'" else sql[i:j + 1])
            i = j + 1
            continue
        out.append(c)
        i += 1
    text = "".join(out)
    if DB_RO_REFUSE.search(text):
        return True
    return any(DB_RO_BYPASS.search(st) for st in text.split(";") if not re.match(r"\s*show\b", st, re.I))


def pg_sslmode(db):
    """libpq sslmode; insecure_tls keeps the encryption but drops certificate verification"""
    mode = str(db.get("ssl", "prefer"))
    return "require" if db.get("insecure_tls") and mode in ("verify-ca", "verify-full") else mode


def db_engine(db):
    e = (db.get("engine") or "postgres").lower()
    return "mysql" if e in ("mysql", "mariadb") else "postgres"


def db_run(name, db, sql=None, fmt="table", interactive=False, ro=None):
    """run SQL (or an interactive client) – password only in env / a 0600 tmpfs file; ro (default: access read) makes
    the session read-only, so a write hidden in a read (SELECT … INTO, a function) fails there"""
    ro = gate.access_mode(db) == "read" if ro is None else ro
    if db_engine(db) == "postgres":
        addr, lport = core.tunnel(db.get("host", ""), db.get("port", 5432))
        env = dict(PGHOST=str(db.get("host", "")), PGHOSTADDR=addr, PGPORT=str(lport),
                   PGDATABASE=str(db.get("database", "")), PGUSER=str(db.get("user", "")), PGPASSWORD=str(db.get("password", "")),
                   PGSSLMODE=pg_sslmode(db), PGAPPNAME="tentaclai", PGCONNECT_TIMEOUT="10")
        if ro:
            env["PGOPTIONS"] = "-c default_transaction_read_only=on"
        cmd = ["psql", "-X", "-v", "ON_ERROR_STOP=1"]
        if fmt == "csv":
            cmd.append("--csv")
        if sql is not None:
            cmd += ["-c", sql]
        # psql runs as the service's user: shell escapes (\!) in the interactive shell get that user, not root
        return subprocess.call(cmd, **core.runner(name, env)) if interactive or sql is not None else 0
    addr, lport = core.tunnel(db.get("host", ""), db.get("port", 3306))
    cfg = core._shm_file("[client]\n" + "".join(f"{k}={v}\n" for k, v in (
        ("host", addr), ("port", lport), ("user", db.get("user", "")),
        ("password", db.get("password", "")), ("database", db.get("database", ""))) if v != ""), name)
    try:
        cmd = ["mariadb", f"--defaults-extra-file={cfg}", "--connect-timeout=10", "--sandbox"]
        if db.get("ssl") in (True, "require", "true"):
            cmd.append("--ssl")
            if db.get("insecure_tls"):
                cmd.append("--skip-ssl-verify-server-cert")
        if ro:
            cmd.append("--init-command=SET SESSION TRANSACTION READ ONLY")
        if sql is not None:
            cmd += (["--batch"] if fmt == "csv" else ["--table"]) + ["-e", sql]
        return subprocess.call(cmd, **core.runner(name))
    finally:
        os.unlink(cfg)


def cmd_db(services, args):
    dbs = core.part_services(services, "db")
    if not args:
        if not dbs:
            print("No database services.")
            return 0
        print(f"{'Name':<16}{'Engine':<10}{'Access':<8}{'Target':<36}Status")
        for n, s in dbs.items():
            d = core.render(s["db"])
            tgt = f"{d.get('host', '')}:{d.get('port') or (3306 if db_engine(d) == 'mysql' else 5432)}/{d.get('database', '')}"
            print(f"{n:<16}{db_engine(d):<10}{tclib.access(d.get('access')):<8}{tgt:<36}{core.status(s)}")
        return 0
    name, rest = args[0], args[1:]
    db = gate.get_part(services, name, "db")
    fmt = "table"
    if rest and rest[0] in ("--csv", "--tsv"):
        fmt, rest = "csv", rest[1:]
    if not rest:
        sys.exit(f"usage: svc db {name} \"<SQL>\" | tables | describe <table> | shell")
    pg = db_engine(db) == "postgres"
    mode = gate.access_mode(db)
    if rest[0] == "shell":
        if mode == "read":
            sys.exit(f"svc: {name} is read-only – use svc db {name} \"<SQL>\" (the shell could switch the session to read-write)")
        return gate.guarded(name, "db", mode, "interactive SQL shell", lambda: db_run(name, db, interactive=True), interactive=True)
    if rest[0] == "tables":
        return db_run(name, db, "\\dt+" if pg else "SHOW FULL TABLES", fmt)
    if rest[0] == "describe" and len(rest) == 2:
        t = rest[1]
        if not re.fullmatch(r"[A-Za-z0-9_.]+", t):
            sys.exit("svc: invalid table name")
        return db_run(name, db, f"\\d {t}" if pg else f"DESCRIBE `{t.replace('.', '`.`')}`", fmt)
    sql = " ".join(rest)
    if pg and sql.lstrip().startswith("\\"):  # psql would run it as a meta-command (\! runs a shell)
        sys.exit(f"svc: psql meta-commands are not allowed – svc db {name} tables | describe <table>, or plain SQL")
    # SQL a read-only session can't be trusted with is a write: approval on confirm, refused on read
    if mode != "read" and (sql_writes(sql, pg) or ro_bypass(sql, pg)):
        return gate.guarded(name, "db", mode, f"SQL: {sql}", lambda: db_run(name, db, sql, fmt))
    if ro_bypass(sql, pg):
        sys.exit(f"svc: {name} is read-only – no comments, backslashes, $ or U& quoting, EXECUTE/DO/CALL/set_config, COPY "
                 f"or file functions, and nothing that changes the transaction mode")
    return db_run(name, db, sql, fmt, ro=True)


def db_test(name, db):
    """(ok, detail)"""
    if db_engine(db) == "postgres":
        addr, lport = core.tunnel(db.get("host", ""), db.get("port", 5432))
        env = dict(PGHOST=str(db.get("host", "")), PGHOSTADDR=addr, PGPORT=str(lport), PGDATABASE=str(db.get("database", "")),
                   PGUSER=str(db.get("user", "")), PGPASSWORD=str(db.get("password", "")), PGSSLMODE=pg_sslmode(db),
                   PGCONNECT_TIMEOUT="8", PGOPTIONS="-c default_transaction_read_only=on")
        r = subprocess.run(["psql", "-X", "-At", "-c", "SELECT version()"], capture_output=True, text=True, timeout=20, **core.runner(name, env))
    else:
        addr, lport = core.tunnel(db.get("host", ""), db.get("port", 3306))
        cfg = core._shm_file("[client]\n" + "".join(f"{k}={v}\n" for k, v in (
            ("host", addr), ("port", lport), ("user", db.get("user", "")),
            ("password", db.get("password", "")), ("database", db.get("database", ""))) if v != ""), name)
        try:
            r = subprocess.run(["mariadb", f"--defaults-extra-file={cfg}", "--connect-timeout=8", "-N", "-e", "SELECT VERSION()"],
                               capture_output=True, text=True, timeout=20, **core.runner(name))
        finally:
            os.unlink(cfg)
    if r.returncode == 0:
        return True, f"{db_engine(db)} {db.get('host')}/{db.get('database', '')} → {r.stdout.strip()[:80]} ({tclib.access(db.get('access'))})"
    return False, (r.stderr.strip().splitlines() or ["error"])[-1][:180]


def sql_statements(sql, pg=True):
    """the statements of a script, split at ; outside quotes, dollar quotes and comments (backslash escapes and
    backtick quotes only in mysql)"""
    out, cur, i, n = [], [], 0, len(sql)
    while i < n:
        c = sql[i]
        if c in ("'\"" if pg else "'\"`"):
            j = i + 1
            while j < n and not (sql[j] == c and not (j + 1 < n and sql[j + 1] == c)):
                j += 2 if sql[j] == c or (sql[j] == "\\" and not pg and c != "`") else 1
            cur.append(sql[i:j + 1])
            i = j + 1
            continue
        if sql.startswith("--", i):
            j = sql.find("\n", i)
            i = n if j < 0 else j
            continue
        if sql.startswith("/*", i):
            j = sql.find("*/", i + 2)
            i = n if j < 0 else j + 2
            cur.append(" ")
            continue
        m = re.match(r"\$[A-Za-z_]*\$", sql[i:]) if c == "$" else None
        if m:
            j = sql.find(m.group(0), i + len(m.group(0)))
            j = n if j < 0 else j + len(m.group(0))
            cur.append(sql[i:j])
            i = j
            continue
        if c == ";":
            out.append("".join(cur))
            cur = []
        else:
            cur.append(c)
        i += 1
    out.append("".join(cur))
    return [s.strip() for s in out if s.strip()]


def sql_writes(sql, pg=True):
    """True when one of the statements may change something (it then needs approval on confirm databases)"""
    parts = sql_statements(sql, pg)
    return not parts or any(_statement_writes(s) for s in parts)


def _statement_writes(s):
    if safeguards.READ_SQL.match(s) and not (s.lower().startswith(("explain analyze",)) and safeguards.WRITE_SQL.search(s)):
        return False
    if re.match(r"^\s*with\b", s, re.I):
        return bool(safeguards.WRITE_SQL.search(s))
    return True

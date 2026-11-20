#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only

"""Prepare private input files for the Linux self-host service."""

import argparse
from datetime import datetime, timedelta, timezone
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import secrets
import stat
import sys
from urllib.parse import urlsplit


DATABASE_URL = "ARCFORGES_CENTER_DATABASE_URL"
MAX_SECRET_BYTES = 16 * 1024


def read_runtime_url(path, role):
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), "rb") as source:
        mode = os.fstat(source.fileno()).st_mode
        if not stat.S_ISREG(mode) or mode & 0o077:
            raise ValueError("expected one private regular credential file")
        contents = source.read(MAX_SECRET_BYTES + 1)
    if len(contents) > MAX_SECRET_BYTES:
        raise ValueError("credential file exceeds the allowed size")

    # Read object members as pairs so a repeated credential key is refused.
    fields = json.loads(contents, object_pairs_hook=list)
    if not isinstance(fields, list) or len(fields) != 1 or not isinstance(fields[0], tuple):
        raise ValueError("credential file must hold one database URL")
    key, value = fields[0]
    if key != DATABASE_URL or not isinstance(value, str):
        raise ValueError("credential file must hold one database URL")
    if not value.isascii() or any(char <= " " or char == "\x7f" or char in '\"\\' for char in value):
        raise ValueError("runtime URL cannot be stored safely")

    url = urlsplit(value)
    if (
        url.scheme not in ("postgres", "postgresql")
        or url.hostname != "127.0.0.1"
        or url.port == 0
        or url.username not in (role + "_a", role + "_b")
        or not url.password
        or not re.fullmatch(r"/[a-z][a-z0-9_]{0,62}", url.path)
        or url.fragment
        or url.query != "sslmode=disable"
    ):
        raise ValueError("expected a rotated login for the local PostgreSQL database")
    return value


def write_private(path, value):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="ascii", newline="\n") as output:
        output.write(value)


def bootstrap(directory, hours):
    directory.mkdir(mode=0o700)
    token = "afb1." + secrets.token_urlsafe(32)
    digest = sha256(token.encode("ascii")).hexdigest()
    expiry = datetime.now(timezone.utc) + timedelta(hours=hours)
    write_private(directory / "bootstrap-token", token + "\n")
    write_private(
        directory / "bootstrap.env",
        f"ARCFORGES_CENTER_BOOTSTRAP_SHA256={digest}\n"
        f"ARCFORGES_CENTER_BOOTSTRAP_EXPIRES_AT={expiry:%Y-%m-%dT%H:%M:%SZ}\n",
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    operations = parser.add_subparsers(dest="action", required=True)
    runtime = operations.add_parser("runtime-env")
    runtime.add_argument("credential", type=Path)
    runtime.add_argument("output", type=Path)
    runtime.add_argument("--role", default="arcforges_center_runtime")
    owner = operations.add_parser("bootstrap")
    owner.add_argument("directory", type=Path)
    owner.add_argument("--hours", type=int, default=2)
    args = parser.parse_args()

    try:
        if args.action == "runtime-env":
            if not re.fullmatch(r"[a-z][a-z0-9_]{2,40}", args.role):
                parser.error("runtime group role must be a lowercase database role")
            url = read_runtime_url(args.credential, args.role)
            write_private(args.output, f'{DATABASE_URL}="{url}"\n')
        else:
            if not 1 <= args.hours <= 168:
                parser.error("bootstrap duration must be between 1 and 168 hours")
            bootstrap(args.directory, args.hours)
    except (OSError, ValueError, RecursionError):
        print("Unable to prepare private input. Check the source format, permissions, and unused output path.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

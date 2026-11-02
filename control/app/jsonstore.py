"""tentacontrol's small JSON state files (data/control/*.json): read with a default, write atomically."""
import contextlib
import fcntl
import json
import os
import tempfile


def load(path, default=None):
    """the file's content, or default when it is missing or broken"""
    try:
        with open(path) as f:
            return json.load(f)
    except (OSError, ValueError):
        return {} if default is None else default


@contextlib.contextmanager
def locked(path):
    """hold the file's lock (<path>.lock) for a read-modify-write – two requests changing the same file one after the
    other, so neither loses the other's change (an exclusive flock: threads and processes alike)"""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    fd = os.open(path + ".lock", os.O_WRONLY | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)


def save(path, data, indent=1, mode=None, readable=False):
    """write to a temporary file and rename it – readers never see half a file; mode e.g. 0o600 for secrets.
    readable: a file people edit by hand (services/, systems/, templates) – indent 2, UTF-8, a final newline.
    Each write has a temporary file of its own: two at once never write into the same one"""
    d = os.path.dirname(path)
    os.makedirs(d, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=d, prefix="." + os.path.basename(path) + ".")
    try:
        with os.fdopen(fd, "w") as f:
            if readable:
                json.dump(data, f, ensure_ascii=False, indent=2)
                f.write("\n")
            else:
                json.dump(data, f, indent=indent)
        os.chmod(tmp, mode if mode is not None else 0o644)
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise

"""Reads the strace log of a sandboxed command: what it opened, changed and connected to.

The log comes from `strace -f -y`, so every successful open ends with the resolved path
(`= 3</workspace/.env>`), whatever the working directory or relative path was.
"""

import posixpath
import re
from dataclasses import dataclass

# Syscalls that take (dirfd, path) pairs, and which pairs they change. symlinkat's only pair is
# the link being created; linkat's second pair is the new name; rename changes both names.
CHANGED_PAIR_INDEXES: dict[str, tuple[int, ...]] = {
    "unlinkat": (0,),
    "renameat": (0, 1),
    "renameat2": (0, 1),
    "mkdirat": (0,),
    "fchmodat": (0,),
    "fchownat": (0,),
    "utimensat": (0,),
    "mknodat": (0,),
    "linkat": (1,),
    "symlinkat": (0,),
}
# These take a plain path with no dirfd, so only an absolute path can be classified.
PATH_ONLY_SYSCALLS = ("truncate", "setxattr")
TRACED_CHANGE_SYSCALLS = (*CHANGED_PAIR_INDEXES, *PATH_ONLY_SYSCALLS)
TRACED_SYSCALLS = ",".join(("openat", "openat2", "connect", *TRACED_CHANGE_SYSCALLS))
SANDBOX_HOME = "/home/sandbox"
DNS_ADDRESS = ("127.0.0.11", 53)  # Docker's embedded DNS
MAX_REPORTED_PATHS = 10

WRITE_FLAGS = ("O_WRONLY", "O_RDWR", "O_CREAT", "O_TRUNC", "O_APPEND")
# Writes here are the command's normal business, not something outside the repo.
EXPECTED_WRITE_PREFIXES = ("/workspace/", "/tmp/", "/proc/", "/dev/", "/sys/")
OPEN_SYSCALLS = ("openat", "openat2")

_SYSCALL_PATTERN = re.compile(r"^(?:\d+\s+)?(?:<\.\.\. (\w+) resumed>|(\w+)\()")
_RESULT_PATTERN = re.compile(r"\)\s+=\s+(-?\d+)(?:<([^>]*)>)?(?:\s+([A-Z][A-Z0-9]+))?")
_QUOTED_PATTERN = re.compile(r'"((?:[^"\\]|\\.)*)"')
# `AT_FDCWD</home/sandbox>, "victim"`: with -y the directory is spelled out after the dirfd.
_DIRFD_PAIR_PATTERN = re.compile(r'(?:AT_FDCWD|\d+)(?:<([^>]*)>)?,\s*"((?:[^"\\]|\\.)*)"')
_FLAGS_PATTERN = re.compile(r'"(?:[^"\\]|\\.)*",\s*([A-Z_0-9|]+)')
_OPENAT2_FLAGS_PATTERN = re.compile(r"flags=([A-Z_0-9|]+)")
_IPV4_PATTERN = re.compile(r'sin_port=htons\((\d+)\), sin_addr=inet_addr\("([\d.]+)"\)')
_IPV6_PATTERN = re.compile(r'sin6_port=htons\((\d+)\).*?inet_pton\(AF_INET6, "([^"]+)"')


@dataclass(frozen=True)
class StraceFindings:
    opened_paths: list[str]  # files successfully opened, resolved
    outside_writes: list[str]  # changed outside the repo, collapsed to a few entries
    failed_changes: list[str]  # absolute paths the command tried to change that do not exist
    direct_connections: list[str]  # "ip:port" connects that did not go through the proxy
    used_dns: bool  # used Docker's DNS (also needed just to find the proxy by name)
    used_proxy: bool  # connected to the logging proxy


def _collapse(path: str) -> str:
    """Folders under the sandbox home collapse to their first level (one entry for ~/.npm)."""
    if path.startswith(f"{SANDBOX_HOME}/"):
        return f"{SANDBOX_HOME}/{path[len(SANDBOX_HOME) + 1:].split('/')[0]}"
    return path


def _is_outside_repo(path: str) -> bool:
    return path.startswith("/") and not path.startswith(EXPECTED_WRITE_PREFIXES)


def _open_flags(syscall: str, line: str) -> str:
    pattern = _OPENAT2_FLAGS_PATTERN if syscall == "openat2" else _FLAGS_PATTERN
    match = pattern.search(line)
    return match.group(1) if match else ""


def _resolve(directory: str | None, path: str) -> str | None:
    """An absolute path, resolved against the call's directory if it was relative, else None."""
    if path.startswith("/"):
        return posixpath.normpath(path)
    return posixpath.normpath(posixpath.join(directory, path)) if directory else None


def _changed_paths(syscall: str, line: str, opened_path: str | None) -> list[str]:
    """Absolute paths this call changes (or tried to change); empty if it only reads."""
    pairs = [(match.group(1), match.group(2)) for match in _DIRFD_PAIR_PATTERN.finditer(line)]
    if syscall in OPEN_SYSCALLS:
        if not any(flag in _open_flags(syscall, line) for flag in WRITE_FLAGS):
            return []
        # A successful open already carries the resolved path; a failed one is resolved here.
        resolved = [opened_path] if opened_path else [_resolve(*pairs[0])] if pairs else []
    elif syscall in CHANGED_PAIR_INDEXES:
        resolved = [_resolve(*pairs[index]) for index in CHANGED_PAIR_INDEXES[syscall] if index < len(pairs)]
    elif syscall in PATH_ONLY_SYSCALLS:
        quoted = _QUOTED_PATTERN.findall(line)
        resolved = [_resolve(None, quoted[0])] if quoted else []
    else:
        return []
    return [path for path in resolved if path]


def _addresses(line: str) -> list[tuple[str, int]]:
    found = [(ip, int(port)) for port, ip in _IPV4_PATTERN.findall(line)]
    found += [(ip, int(port)) for port, ip in _IPV6_PATTERN.findall(line)]
    return found


def _is_loopback(address: str) -> bool:
    return address.startswith("127.") or address == "::1"


def parse_strace_log(log: str, proxy_addresses: set[tuple[str, int]]) -> StraceFindings:
    """Summarize the log. `proxy_addresses` are the (ip, port) pairs of the connection logger."""
    opened: list[str] = []
    outside_writes: list[str] = []
    failed_changes: list[str] = []
    direct: list[str] = []
    used_dns = False
    used_proxy = False

    for line in log.splitlines():
        syscall_match = _SYSCALL_PATTERN.match(line)
        if syscall_match is None:
            continue
        resumed_name, called_name = syscall_match.groups()
        syscall = resumed_name or called_name
        result_match = _RESULT_PATTERN.search(line)
        result = int(result_match.group(1)) if result_match else None
        resolved = result_match.group(2) if result_match else None
        errno_name = result_match.group(3) if result_match else None

        if syscall == "connect":
            for address in _addresses(line):
                if address == DNS_ADDRESS:
                    used_dns = True
                elif address in proxy_addresses:
                    used_proxy = True
                elif not _is_loopback(address[0]):
                    direct.append(f"{address[0]}:{address[1]}")
            continue

        if syscall in OPEN_SYSCALLS and result is not None and result >= 0 and resolved:
            opened.append(resolved)

        # Only complete calls carry their arguments; a resumed call has just the result.
        if called_name is None:
            continue
        for path in _changed_paths(syscall, line, resolved if result is not None and result >= 0 else None):
            if result is not None and result >= 0 and _is_outside_repo(path):
                outside_writes.append(_collapse(path))
            elif errno_name == "ENOENT" and _is_outside_repo(path):
                failed_changes.append(path)

    return StraceFindings(
        opened_paths=list(dict.fromkeys(opened)),
        outside_writes=list(dict.fromkeys(outside_writes))[:MAX_REPORTED_PATHS],
        failed_changes=list(dict.fromkeys(failed_changes))[:MAX_REPORTED_PATHS],
        direct_connections=list(dict.fromkeys(direct))[:MAX_REPORTED_PATHS],
        used_dns=used_dns,
        used_proxy=used_proxy,
    )

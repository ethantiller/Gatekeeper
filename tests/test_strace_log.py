"""Reading strace logs: tripwire opens, writes outside the repo, and proxy bypass attempts."""

from gatekeeper.sandbox.strace_log import parse_strace_log

PROXY = {("172.18.0.2", 8080)}


def _parse(*lines: str):
    return parse_strace_log("\n".join(lines), PROXY)


def test_open_is_resolved_whatever_the_relative_path() -> None:
    findings = _parse('14 openat(AT_FDCWD</tmp>, "../workspace/.env", O_RDONLY) = 3</workspace/.env>')

    assert findings.opened_paths == ["/workspace/.env"]


def test_resumed_open_still_gives_the_path() -> None:
    findings = _parse(
        '15 openat(AT_FDCWD</workspace>, ".env", O_RDONLY <unfinished ...>',
        "15 <... openat resumed>) = 4</workspace/.env>",
    )

    assert findings.opened_paths == ["/workspace/.env"]


def test_failed_open_is_not_an_open() -> None:
    findings = _parse('14 openat(AT_FDCWD</workspace>, ".env", O_RDONLY) = -1 ENOENT (No such file)')

    assert findings.opened_paths == []


def test_writes_outside_the_repo_collapse_to_the_first_level_under_home() -> None:
    findings = _parse(
        '1 openat(AT_FDCWD</>, "/home/sandbox/.npm/_logs/a.log", O_WRONLY|O_CREAT, 0666) = 3</home/sandbox/.npm/_logs/a.log>',
        '1 openat(AT_FDCWD</>, "/home/sandbox/.bashrc", O_WRONLY|O_APPEND, 0666) = 3</home/sandbox/.bashrc>',
        '1 openat(AT_FDCWD</>, "/workspace/out.txt", O_WRONLY|O_CREAT, 0666) = 3</workspace/out.txt>',
        '1 openat(AT_FDCWD</>, "/etc/hosts", O_RDONLY) = 3</etc/hosts>',
    )

    assert findings.outside_writes == ["/home/sandbox/.npm", "/home/sandbox/.bashrc"]


def test_failed_changes_to_paths_the_sandbox_lacks_are_reported() -> None:
    findings = _parse(
        '1 unlinkat(AT_FDCWD</workspace>, "/Users/me/proj/src", AT_REMOVEDIR) = -1 ENOENT (No such file)',
        '1 unlinkat(AT_FDCWD</workspace>, "relative", 0) = -1 ENOENT (No such file)',
    )

    assert findings.failed_changes == ["/Users/me/proj/src"]


def test_connections_through_the_proxy_are_not_bypasses() -> None:
    findings = _parse(
        '1 connect(3<socket:[1]>, {sa_family=AF_INET, sin_port=htons(8080), sin_addr=inet_addr("172.18.0.2")}, 16) = 0',
        '1 connect(4<socket:[2]>, {sa_family=AF_INET, sin_port=htons(80), sin_addr=inet_addr("1.2.3.4")}, 16) = -1 ENETUNREACH',
        '1 connect(5<socket:[3]>, {sa_family=AF_INET, sin_port=htons(53), sin_addr=inet_addr("127.0.0.11")}, 16) = 0',
        '1 connect(6<socket:[4]>, {sa_family=AF_UNIX, sun_path="/var/run/nscd/socket"}, 110) = -1 ENOENT',
    )

    assert findings.direct_connections == ["1.2.3.4:80"]
    assert findings.used_dns
    assert findings.used_proxy


def test_unfinished_connect_still_counts() -> None:
    findings = _parse(
        '7 connect(9<socket:[5]>, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("5.6.7.8")}, 16 <unfinished ...>',
    )

    assert findings.direct_connections == ["5.6.7.8:443"]


def test_dns_without_the_proxy_is_visible() -> None:
    findings = _parse(
        '1 connect(5<socket:[3]>, {sa_family=AF_INET, sin_port=htons(53), sin_addr=inet_addr("127.0.0.11")}, 16) = 0',
    )

    assert findings.used_dns
    assert not findings.used_proxy

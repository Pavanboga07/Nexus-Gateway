"""M11 regression tests: hardening.

Covers the two remaining hardening findings that live in code:

* **`L2` the keep-alive self-ping.** It was enabled by default and pinged a URL
  taken straight from configuration. That is an SSRF primitive armed by default
  for anyone who can set `GATEWAY_PUBLIC_URL` (or for an operator typo), and it
  silently did nothing on a platform that does not define
  `RENDER_EXTERNAL_URL`.
* **Unpinned dependencies and no secret scanning.** There is no CI in these
  repositories to put a scanner in, so the gate lives here: it fails the build if
  a dependency loses its pin, or if a credential-shaped string appears in a
  **tracked** file.

Note on layout: `nexus/` and `nexus-gateway/` are two independent git
repositories, not one. Anything that scans "the repository" has to iterate over
both, and must ask git which files are tracked rather than walking the directory
tree - the whole point of the secret check is to ignore a developer's local
`.env`, which is where a real credential is *supposed* to live.
"""

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path

import pytest

GATEWAY_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = GATEWAY_ROOT.parent
NEXUS_ROOT = REPO_ROOT / "nexus"

#: Both projects, each its own repository.
REPO_DIRS = tuple(p for p in (NEXUS_ROOT, GATEWAY_ROOT) if p.is_dir())


# ---------------------------------------------------------------------------
# L2: the keep-alive self-ping
# ---------------------------------------------------------------------------


def test_self_ping_is_off_by_default() -> None:
    """Opt-in, not opt-out.

    A workaround for one hosting platform's idle spin-down must not be the
    default posture of a service that is also expected to run on a platform
    where the outbound request is pointless or unwanted.
    """
    from app.config import GatewaySettings

    assert GatewaySettings(_env_file=None).self_ping_enabled is False, (
        "self-ping is enabled by default again; it issues an outbound HTTP "
        "request to a configuration-supplied URL from every deployment"
    )


@pytest.mark.parametrize(
    "url",
    [
        "http://gateway.example.com",  # not HTTPS
        "https://127.0.0.1",  # loopback
        "https://localhost",
        "https://10.0.0.5",  # private
        "https://192.168.1.10",
        "https://169.254.169.254",  # link-local / cloud metadata
        "ftp://gateway.example.com",
    ],
)
def test_self_ping_refuses_a_dangerous_target(url: str, monkeypatch) -> None:
    """The ping target is validated, because we choose to fetch it.

    `169.254.169.254` is the interesting case: on several clouds that address
    serves instance credentials, and a keep-alive that will fetch whatever it is
    told is a way to reach it from inside the network.
    """
    import app.main as main

    monkeypatch.delenv("RENDER_EXTERNAL_URL", raising=False)
    monkeypatch.setattr(main, "get_settings", lambda: _StubSettings(url))

    assert main._resolve_self_ping_target() is None


def test_self_ping_accepts_a_public_https_target(monkeypatch) -> None:
    """The escape hatch must still work when it is correctly configured."""
    import app.main as main

    monkeypatch.delenv("RENDER_EXTERNAL_URL", raising=False)
    monkeypatch.setattr(
        main, "get_settings", lambda: _StubSettings("https://gw.example.com/")
    )

    # The trailing slash must not produce a double slash in the path.
    assert main._resolve_self_ping_target() == "https://gw.example.com/health"


def test_self_ping_exits_instead_of_looping_when_unconfigured(monkeypatch) -> None:
    """No target must mean "stopped", not "sleeping forever on a debug line".

    The old loop logged at DEBUG and continued, so a keep-alive that was keeping
    nothing alive looked identical to a working one.
    """
    import asyncio

    import app.main as main

    monkeypatch.delenv("RENDER_EXTERNAL_URL", raising=False)
    monkeypatch.setattr(main, "get_settings", lambda: _StubSettings(None))

    # If it looped, this would hang rather than return.
    asyncio.run(asyncio.wait_for(main._self_ping_loop(0.01), timeout=5))


def test_private_host_helper_classifies_addresses() -> None:
    """An IP literal is classified; a name is not.

    A name is deliberately not resolved here: resolution happens at request
    time, so blocking a name would be a false sense of safety. `203.0.113.0/24`
    is TEST-NET-3, and `ipaddress` treats it as private (it is not globally
    routable), so it belongs on the private side of this assertion.
    """
    import app.main as main

    assert main._is_private_host("10.1.2.3")
    assert main._is_private_host("127.0.0.1")
    assert main._is_private_host("169.254.169.254")
    assert main._is_private_host("203.0.113.10")  # TEST-NET-3, not routable
    assert not main._is_private_host("8.8.8.8")
    assert not main._is_private_host("gateway.example.com")


class _StubSettings:
    """Minimal stand-in so the resolver can be tested without the env cache."""

    def __init__(self, public_url: str | None) -> None:
        self.public_url = public_url


# ---------------------------------------------------------------------------
# Dependencies: every direct requirement pinned
# ---------------------------------------------------------------------------

_ALLOWED_UNPINNED_PREFIXES = ("-r ", "-c ", "--", "#", "-e ")


def _requirement_files() -> list[Path]:
    return [
        path
        for path in (
            NEXUS_ROOT / "requirements.txt",
            GATEWAY_ROOT / "requirements.txt",
        )
        if path.exists()
    ]


def test_both_requirement_files_exist() -> None:
    """A missing requirements file would make the pin check vacuously pass."""
    missing = [
        str(p)
        for p in (NEXUS_ROOT / "requirements.txt", GATEWAY_ROOT / "requirements.txt")
        if not p.exists()
    ]
    assert not missing, f"requirements file(s) missing: {missing}"


def test_direct_dependencies_are_pinned() -> None:
    """`M8 unpinned deps` / `M11`: a floating requirement is an unreproducible build.

    Only `==` counts as pinned. `>=` does not: it permits a major upgrade to
    arrive unannounced on the next install, which is the exact failure mode the
    audit named - a dependency bump that changes behaviour with no commit that
    mentions it.
    """
    unpinned: list[str] = []
    checked = 0
    for path in _requirement_files():
        for number, raw in enumerate(
            path.read_text(encoding="utf-8").splitlines(), start=1
        ):
            line = raw.strip()
            if not line or line.startswith(_ALLOWED_UNPINNED_PREFIXES):
                continue
            checked += 1
            if not re.match(
                r"^[A-Za-z0-9_.-]+\s*(\[[^\]]*\]\s*)?==\s*[0-9]", line
            ):
                unpinned.append(f"{path.parent.name}/{path.name}:{number} {line}")

    assert checked > 5, f"only checked {checked} requirements; the parser is broken"
    assert not unpinned, (
        "these direct requirements are not pinned with '==', so the build is not "
        "reproducible:\n  " + "\n  ".join(unpinned)
    )


def test_pins_match_what_is_actually_installed() -> None:
    """A pin nobody has ever installed is a claim, not a version.

    Catches the failure mode where requirements.txt is edited by hand and the
    resulting combination was never resolved - the file looks pinned and the
    build is still unreproducible, because the stated version does not work.
    """
    import importlib.metadata

    mismatches: list[str] = []
    for path in _requirement_files():
        for raw in path.read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            if not line or line.startswith(_ALLOWED_UNPINNED_PREFIXES):
                continue
            match = re.match(r"^([A-Za-z0-9_.-]+)\s*(?:\[[^\]]*\])?\s*==\s*(\S+)", line)
            if not match:
                continue
            name, pinned = match.group(1), match.group(2)
            try:
                installed = importlib.metadata.version(name)
            except importlib.metadata.PackageNotFoundError:
                # Not installed in this environment (the gateway extras might
                # not be). Absence is not a mismatch - only a wrong version is.
                continue
            if installed != pinned:
                mismatches.append(f"{name}: pinned {pinned}, installed {installed}")

    assert not mismatches, (
        "requirements.txt pins versions that are not what this environment has, "
        "so the pin was never verified by running it:\n  " + "\n  ".join(mismatches)
    )


# ---------------------------------------------------------------------------
# Secrets: no credential-shaped string in a TRACKED file
# ---------------------------------------------------------------------------

#: Deliberately narrow. A broad entropy heuristic would flag the test fixtures
#: and public key material this repository intentionally contains, and a scanner
#: that cries wolf gets disabled - which is worse than not having one.
_SECRET_PATTERNS = (
    (
        "database password in a URL",
        re.compile(
            r"postgresql(?:\+\w+)?://(?P<user>[A-Za-z0-9_.-]+):(?P<pw>[^@/\s]{6,})@"
        ),
    ),
    ("OpenAI-style key", re.compile(r"\bsk-[A-Za-z0-9]{20,}\b")),
    ("AWS access key id", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b")),
    ("Slack token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b")),
    (
        "private key block",
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    ),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("Neon/Postgres hosted credential", re.compile(r"\bnpg_[A-Za-z0-9]{12,}\b")),
)

#: Passwords that are placeholders, with why each is acceptable.
_PLACEHOLDER_PASSWORDS = {
    "nexus": "the local Docker Postgres password, in docker-compose and docs",
    "password": "documentation example",
    "pass": "documentation example",
    "changeme": "documentation example",
    "yourpassword": "documentation example",
    "secret": "documentation example",
    "test": "test fixture",
    "postgres": "documentation example",
    "example": "documentation example",
    "xxx": "documentation example",
    "gateway_secret": "the local Docker Postgres password in docker-compose.yml",
    "nexus_gateway": "local compose service name used as the user",
}

_SKIP_SUFFIXES = {
    ".pyc", ".woff", ".woff2", ".ico", ".png", ".jpg", ".jpeg", ".gif", ".svg",
}
_SKIP_DIRS = {
    ".git", "node_modules", ".next", "__pycache__", ".venv", "venv",
    ".pytest_cache", ".mypy_cache", "dist", "build", ".ruff_cache", "coverage",
}


def _tracked_files(repo: Path) -> list[Path]:
    """Files git says are tracked in `repo`.

    Tracked-only is the load-bearing part: a developer's `.env` is gitignored
    precisely because that is where a real credential belongs, and a scanner
    that flags it teaches people to ignore the scanner.
    """
    result = subprocess.run(
        ["git", "ls-files"],
        cwd=repo,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, (
        f"git ls-files failed in {repo}; this check must scan tracked files, not "
        f"the working tree, or it will flag gitignored secrets: {result.stderr}"
    )
    return [repo / line for line in result.stdout.splitlines() if line.strip()]


def test_env_files_are_not_tracked() -> None:
    """The gitignore rule that keeps a real credential out of history.

    `C4` was a committed database credential. Removing the line does not remove
    it from history, so the only durable fix is that the file never gets added.
    """
    offenders: list[str] = []
    for repo in REPO_DIRS:
        for path in _tracked_files(repo):
            name = path.name
            if name == ".env" or name.startswith(".env.") and name != ".env.example":
                offenders.append(str(path.relative_to(REPO_ROOT)))

    assert not offenders, (
        "these environment files are tracked by git; a real credential in one of "
        "them is in history forever:\n  " + "\n  ".join(offenders)
    )


def test_env_example_is_the_documented_pattern() -> None:
    """The committed template must exist, or `.env` gets re-added by hand."""
    for repo in REPO_DIRS:
        assert (repo / ".env.example").exists(), (
            f"{repo.name} has no .env.example; there is nothing to copy for a new "
            "checkout, which is how a real .env ends up committed"
        )


def test_no_credential_shaped_string_is_committed() -> None:
    """The gate that keeps `C4` shut."""
    findings: list[str] = []
    scanned = 0
    for repo in REPO_DIRS:
        for path in _tracked_files(repo):
            if (
                path.suffix.lower() in _SKIP_SUFFIXES
                or any(part in _SKIP_DIRS for part in path.parts)
                or not path.is_file()
            ):
                continue
            try:
                text = path.read_text(encoding="utf-8")
            except (UnicodeDecodeError, OSError):
                continue
            scanned += 1
            relative = path.relative_to(REPO_ROOT)
            for label, pattern in _SECRET_PATTERNS:
                for match in pattern.finditer(text):
                    if label == "database password in a URL" and (
                        match.group("pw").lower() in _PLACEHOLDER_PASSWORDS
                    ):
                        continue
                    findings.append(
                        f"{relative}: {label} -> {match.group(0)[:70]!r}"
                    )

    assert scanned > 20, f"only scanned {scanned} tracked files; the walk is broken"
    assert not findings, (
        "these tracked files contain credential-shaped strings:\n  "
        + "\n  ".join(findings)
        + "\n\nIf a real credential was committed, ROTATE it: removing the line "
        "does not remove it from git history."
    )

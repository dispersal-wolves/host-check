"""Read-only host security posture checks."""

from __future__ import annotations

import argparse
import json
import os
import platform
import re
import shutil
import stat
import subprocess
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Callable


@dataclass(frozen=True)
class Finding:
    check: str
    status: str
    summary: str
    detail: str = ""


def run_command(command: list[str], timeout: int = 8) -> tuple[int, str]:
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            encoding="utf-8",
            errors="replace",
        )
        return result.returncode, (result.stdout + result.stderr).strip()
    except (OSError, subprocess.TimeoutExpired) as exc:
        return 127, str(exc)


def parse_windows_firewall_states(output: str) -> list[bool]:
    positive = {"on", "enabled", "ligado", "activé", "active", "attivo", "activado", "ein"}
    negative = {"off", "disabled", "desligado", "désactivé", "inactive", "disattivo", "desactivado", "aus"}
    states = []
    for raw in output.splitlines():
        words = re.findall(r"[^\W\d_]+", raw.lower(), flags=re.UNICODE)
        if not words:
            continue
        if any(word in negative for word in words):
            states.append(False)
        elif any(word in positive for word in words) and any(label in words for label in ("state", "status", "estado", "état", "stato")):
            states.append(True)
    return states


def check_firewall(system: str) -> Finding:
    if system == "Windows":
        code, output = run_command(["netsh", "advfirewall", "show", "allprofiles", "state"])
        states = parse_windows_firewall_states(output)
        if code == 0 and states:
            disabled = sum(not state for state in states)
            return Finding("firewall", "pass" if disabled == 0 else "fail", f"{len(states) - disabled}/{len(states)} firewall profiles enabled")
        return Finding("firewall", "unknown", "Could not read Windows Firewall state")

    probes = [
        (["ufw", "status"], lambda text: "Status: active" in text, "UFW"),
        (["firewall-cmd", "--state"], lambda text: "running" in text, "firewalld"),
        (["nft", "list", "ruleset"], lambda text: bool(text.strip()), "nftables"),
    ]
    for command, active, label in probes:
        if not shutil.which(command[0]):
            continue
        code, output = run_command(command)
        if code == 0:
            return Finding("firewall", "pass" if active(output) else "warn", f"{label} {'has active rules' if active(output) else 'appears inactive'}")
    return Finding("firewall", "unknown", "No supported firewall controller was found")


def parse_ss_listeners(output: str) -> tuple[int, int]:
    listeners = 0
    wildcard = 0
    for line in output.splitlines():
        fields = line.split()
        if not fields:
            continue
        listeners += 1
        address = fields[4] if len(fields) > 4 else fields[-1]
        if address.startswith(("0.0.0.0:", "[::]:", "*:", ":::")):
            wildcard += 1
    return listeners, wildcard


def check_listeners(system: str) -> Finding:
    if system == "Windows":
        command = ["powershell", "-NoProfile", "-Command", "@(Get-NetTCPConnection -State Listen -ErrorAction Stop).Count"]
        code, output = run_command(command)
        count_match = re.search(r"\d+", output)
        if code == 0 and count_match:
            return Finding("listeners", "pass", f"{count_match.group(0)} TCP listeners found", "Review them with Open Ports when the baseline changes.")
        code, output = run_command(["netstat", "-ano", "-p", "tcp"])
        if code == 0:
            listeners = sum("LISTENING" in line.upper() for line in output.splitlines())
            return Finding("listeners", "pass", f"{listeners} TCP listeners found", "Review them with Open Ports when the baseline changes.")
        return Finding("listeners", "unknown", "Could not enumerate TCP listeners")
    if shutil.which("ss"):
        code, output = run_command(["ss", "-H", "-lntu"])
        if code == 0:
            count, wildcard = parse_ss_listeners(output)
            status = "warn" if wildcard else "pass"
            return Finding("listeners", status, f"{count} listeners; {wildcard} bound to all interfaces")
    return Finding("listeners", "unknown", "The ss utility is unavailable")


def parse_sshd_settings(text: str) -> dict[str, str]:
    settings: dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        key, _, value = line.partition(" ")
        if key.lower() == "match":
            break
        settings.setdefault(key.lower(), value.strip().lower())
    return settings


def check_ssh(system: str) -> Finding:
    if system == "Windows":
        path = Path(os.environ.get("ProgramData", "C:/ProgramData")) / "ssh/sshd_config"
    else:
        path = Path("/etc/ssh/sshd_config")
    if not path.exists():
        return Finding("ssh", "pass", "No SSH server configuration found")
    try:
        settings = parse_sshd_settings(path.read_text(encoding="utf-8", errors="replace"))
    except OSError as exc:
        return Finding("ssh", "unknown", "SSH configuration is not readable", str(exc))
    root = settings.get("permitrootlogin", "prohibit-password")
    password = settings.get("passwordauthentication", "yes")
    risky = []
    if root == "yes":
        risky.append("root login")
    if password == "yes":
        risky.append("password authentication")
    return Finding("ssh", "warn" if risky else "pass", "SSH review: " + (", ".join(risky) if risky else "no basic exposure found"))


def check_privileged_accounts(system: str) -> Finding:
    if system != "Linux":
        return Finding("accounts", "unknown", "Privileged-account enumeration is currently Linux-only")
    try:
        privileged = []
        interactive = 0
        for line in Path("/etc/passwd").read_text(encoding="utf-8").splitlines():
            fields = line.split(":")
            if len(fields) < 7:
                continue
            if fields[2] == "0":
                privileged.append(fields[0])
            if fields[6] not in ("/usr/sbin/nologin", "/sbin/nologin", "/bin/false"):
                interactive += 1
        status = "pass" if privileged == ["root"] else "warn"
        return Finding("accounts", status, f"UID 0 accounts: {', '.join(privileged) or 'none'}; {interactive} interactive shells")
    except OSError as exc:
        return Finding("accounts", "unknown", "Could not inspect local accounts", str(exc))


def check_shadow_permissions(system: str) -> Finding:
    if system != "Linux" or not Path("/etc/shadow").exists():
        return Finding("credential-files", "unknown", "Credential-file permission check is not applicable")
    try:
        mode = stat.S_IMODE(Path("/etc/shadow").stat().st_mode)
        exposed = bool(mode & (stat.S_IRGRP | stat.S_IROTH | stat.S_IWGRP | stat.S_IWOTH))
        return Finding("credential-files", "fail" if exposed else "pass", f"/etc/shadow permissions are {mode:04o}")
    except OSError as exc:
        return Finding("credential-files", "unknown", "Could not inspect /etc/shadow", str(exc))


def collect() -> dict[str, object]:
    system = platform.system()
    checks: list[Callable[[str], Finding]] = [
        check_firewall,
        check_listeners,
        check_ssh,
        check_privileged_accounts,
        check_shadow_permissions,
    ]
    findings = [check(system) for check in checks]
    counts = {status: sum(item.status == status for item in findings) for status in ("pass", "warn", "fail", "unknown")}
    return {
        "schema": "dispersal-wolves/host-check/v1",
        "platform": {"system": system, "release": platform.release(), "architecture": platform.machine()},
        "summary": counts,
        "findings": [asdict(item) for item in findings],
    }


def render_text(report: dict[str, object]) -> str:
    platform_data = report["platform"]
    lines = [f"Host Check · {platform_data['system']} {platform_data['release']} ({platform_data['architecture']})", ""]
    for finding in report["findings"]:
        lines.append(f"[{finding['status'].upper():7}] {finding['check']}: {finding['summary']}")
        if finding["detail"]:
            lines.append(f"          {finding['detail']}")
    summary = report["summary"]
    lines.extend(["", f"{summary['pass']} passed · {summary['warn']} warnings · {summary['fail']} failures · {summary['unknown']} unknown"])
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--format", choices=("text", "json"), default="text")
    parser.add_argument("--output", type=Path, help="Write the report to a file instead of stdout")
    parser.add_argument("--strict", action="store_true", help="Return non-zero when warnings or failures exist")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    report = collect()
    rendered = json.dumps(report, indent=2) if args.format == "json" else render_text(report)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered + "\n", encoding="utf-8")
    else:
        print(rendered)
    summary = report["summary"]
    return 1 if args.strict and (summary["warn"] or summary["fail"]) else 0


if __name__ == "__main__":
    sys.exit(main())

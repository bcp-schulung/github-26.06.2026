#!/usr/bin/env python3
"""
GitHub Seminar — Hetzner + Cloudflare Provisioner
==================================================

Provisions 3 VMs (ben-coeppicus, andreas-miske, robert-ohlenforst) on
Hetzner Cloud. On each VM:
  - creates a 'student' user with passwordless sudo
  - installs code-server (browser IDE) behind Caddy with Let's Encrypt TLS
  - installs git and clones the github-26.06.2026 repo to ~/github-26.06.2026
  - creates a DNS A record at <slug>.github.it-scholar.com

Prerequisites:
    pip install hcloud cloudflare fabric python-dotenv paramiko
    Same .env as provision.py (HCLOUD_TOKEN, CF_API_TOKEN, CF_ZONE_ID,
    SSH_PRIVATE_KEY_PATH, SSH_PUBLIC_KEY_PATH).

Usage:
    python provision_github.py
"""

from __future__ import annotations

import io
import os
import secrets
import string
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import cloudflare as cf_module
from dotenv import load_dotenv
from fabric import Connection
from hcloud import Client as HCloudClient
from hcloud.firewalls.domain import FirewallRule
from hcloud.images.domain import Image
from hcloud.locations.domain import Location
from hcloud.server_types.domain import ServerType
from hcloud.servers.domain import ServerCreatePublicNetwork
import paramiko

# ─────────────────────────────────────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────────────────────────────────────

SERVER_TYPE      = "cx23"                        # 2 vCPU / 4 GB RAM (Intel)
IMAGE_NAME       = "ubuntu-24.04"
LOCATION_NAME    = "hel1"                        # Helsinki, Finland
DOMAIN_SUFFIX    = "github.it-scholar.com"
HETZNER_KEY_NAME = "tf-seminar-provisioner"      # Reuse key from terraform seminar
FW_NAME          = "github-seminar-fw"

GITHUB_REPO_URL  = "https://github.com/bcp-schulung/github-26.06.2026.git"
GITHUB_REPO_DIR  = "github-26.06.2026"           # Clone destination in ~/

STUDENTS = [
    {"slug": "ben-coeppicus",     "display": "ben-coeppicus"},
    {"slug": "andreas-miske",     "display": "andreas-miske"},
    {"slug": "robert-ohlenforst", "display": "robert-ohlenforst"},
]

# ─────────────────────────────────────────────────────────────────────────────
# Systemd service for code-server (runs as the student user)
# ─────────────────────────────────────────────────────────────────────────────

CODESERVER_SERVICE = """\
[Unit]
Description=code-server IDE (student)
After=network.target

[Service]
Type=simple
User=student
Group=student
WorkingDirectory=/home/student
ExecStart=/usr/bin/code-server --config /home/student/.config/code-server/config.yaml
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
"""

# ─────────────────────────────────────────────────────────────────────────────
# Credentials — loaded from .env
# ─────────────────────────────────────────────────────────────────────────────

load_dotenv()


def _require(key: str) -> str:
    val = os.getenv(key)
    if not val:
        sys.exit(f"ERROR: Missing required environment variable '{key}'. Check .env.")
    return val


HCLOUD_TOKEN    = _require("HCLOUD_TOKEN")
CF_API_TOKEN    = _require("CF_API_TOKEN")
CF_ZONE_ID      = _require("CF_ZONE_ID")
SSH_PRIVATE_KEY = os.path.expanduser(_require("SSH_PRIVATE_KEY_PATH"))
SSH_PUBLIC_KEY  = os.path.expanduser(_require("SSH_PUBLIC_KEY_PATH"))

hc = HCloudClient(token=HCLOUD_TOKEN)
cf = cf_module.Cloudflare(api_token=CF_API_TOKEN)

# ─────────────────────────────────────────────────────────────────────────────
# Utilities
# ─────────────────────────────────────────────────────────────────────────────


def log(msg: str) -> None:
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)


def gen_password(length: int = 16) -> str:
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


def connection(ip: str, user: str = "root") -> Connection:
    """Return a Fabric Connection for the given IP, forced over IPv4."""
    import socket as _socket
    sock = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
    sock.settimeout(90)
    sock.connect((ip, 22))
    conn = Connection(
        host=ip,
        user=user,
        connect_kwargs={
            "key_filename": SSH_PRIVATE_KEY,
            "timeout": 90,
            "look_for_keys": False,
            "allow_agent": False,
            "sock": sock,
        },
    )
    conn.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    return conn


def wait_for_ssh(ip: str, timeout: int = 600) -> None:
    """Block until port 22 on *ip* accepts TCP connections."""
    import subprocess
    log(f"  Waiting for SSH on {ip} ...")
    deadline = time.time() + timeout
    last_err = ""
    while time.time() < deadline:
        try:
            r = subprocess.run(["nc", "-zw3", ip, "22"], capture_output=True, timeout=10)
            if r.returncode == 0:
                log(f"  SSH ready: {ip}")
                return
            last_err = f"nc exited {r.returncode}: {r.stderr.decode().strip()}"
        except Exception as e:
            last_err = f"{type(e).__name__}: {e}"
        time.sleep(3)
    raise TimeoutError(
        f"SSH never became available on {ip} after {timeout}s (last: {last_err})"
    )


def put_text(c: Connection, content: str, remote_path: str) -> None:
    """Upload a string as a remote file via SFTP (avoids shell-quoting issues)."""
    c.put(io.BytesIO(content.encode("utf-8")), remote_path)


# ─────────────────────────────────────────────────────────────────────────────
# Phase 1 — Hetzner Infrastructure
# ─────────────────────────────────────────────────────────────────────────────


def ensure_hetzner_ssh_key() -> object:
    """Upload provisioner public key to Hetzner; reuse if already present."""
    existing = hc.ssh_keys.get_by_name(HETZNER_KEY_NAME)
    if existing:
        log(f"Hetzner SSH key '{HETZNER_KEY_NAME}' already exists, reusing.")
        return existing
    pub = Path(SSH_PUBLIC_KEY).read_text().strip()
    log(f"Uploading SSH key '{HETZNER_KEY_NAME}' to Hetzner ...")
    return hc.ssh_keys.create(name=HETZNER_KEY_NAME, public_key=pub)


def ensure_firewall() -> object:
    """Create a firewall allowing SSH + HTTP + HTTPS; reuse if present."""
    existing = hc.firewalls.get_by_name(FW_NAME)
    if existing:
        log(f"Firewall '{FW_NAME}' already exists, reusing.")
        return existing
    log(f"Creating firewall '{FW_NAME}' ...")
    rules = [
        FirewallRule(
            direction="in",
            protocol="tcp",
            port=p,
            source_ips=["0.0.0.0/0", "::/0"],
            description=f"Allow inbound TCP {p}",
        )
        for p in ["22", "80", "443"]
    ]
    result = hc.firewalls.create(name=FW_NAME, rules=rules)
    return result.firewall


def create_vm(name: str, ssh_key: object) -> tuple[str, str]:
    """Create a single VM; return (name, public_ipv4)."""
    existing = hc.servers.get_by_name(name)
    if existing:
        ip = existing.public_net.ipv4.ip
        log(f"  VM '{name}' already exists (IP: {ip}), skipping.")
        return name, ip
    log(f"  Creating VM '{name}' ({SERVER_TYPE}, {IMAGE_NAME}, {LOCATION_NAME}) ...")
    hc.servers.create(
        name=name,
        server_type=ServerType(name=SERVER_TYPE),
        image=Image(name=IMAGE_NAME),
        location=Location(name=LOCATION_NAME),
        ssh_keys=[ssh_key],
        public_net=ServerCreatePublicNetwork(enable_ipv4=True, enable_ipv6=True),
    )
    deadline = time.time() + 600
    server = None
    while time.time() < deadline:
        server = hc.servers.get_by_name(name)
        if server and server.status == "running":
            break
        time.sleep(5)
    if not server:
        raise RuntimeError(f"Server '{name}' never appeared in Hetzner API after 600s")
    ip = server.public_net.ipv4.ip
    log(f"  VM '{name}' created (IP: {ip})")
    return name, ip


def provision_hetzner() -> dict[str, str]:
    """Phase 1: SSH key, firewall, and all VMs. Returns {slug: ip}."""
    log("=== Phase 1: Hetzner Infrastructure ===")
    ssh_key = ensure_hetzner_ssh_key()
    ensure_firewall()

    vm_ips: dict[str, str] = {}
    with ThreadPoolExecutor(max_workers=len(STUDENTS)) as pool:
        futures = {
            pool.submit(create_vm, s["slug"], ssh_key): s["slug"]
            for s in STUDENTS
        }
        for f in as_completed(futures):
            name, ip = f.result()
            vm_ips[name] = ip

    # Apply firewall to all servers
    fw = hc.firewalls.get_by_name(FW_NAME)
    for slug in vm_ips:
        server = hc.servers.get_by_name(slug)
        if server:
            try:
                hc.firewalls.apply_to_resources(
                    firewall=fw,
                    resources=[{"type": "server", "server": {"id": server.id}}],
                )
                log(f"  Firewall applied to '{slug}'.")
            except Exception as e:
                log(f"  Warning: could not apply firewall to '{slug}': {e}")

    log("Phase 1 complete.\n")
    return vm_ips


# ─────────────────────────────────────────────────────────────────────────────
# Phase 2 — Cloudflare DNS
# ─────────────────────────────────────────────────────────────────────────────


def setup_dns(vm_ips: dict[str, str]) -> None:
    """Phase 2: create/update A records for every student VM."""
    log("=== Phase 2: Cloudflare DNS ===")
    for student in STUDENTS:
        dns_name = f"{student['slug']}.{DOMAIN_SUFFIX}"
        ip       = vm_ips[student["slug"]]

        all_records = list(cf.dns.records.list(zone_id=CF_ZONE_ID))
        existing = [
            r for r in all_records
            if getattr(r, "name", "") == dns_name and getattr(r, "type", "") == "A"
        ]

        if existing:
            rec = existing[0]
            if getattr(rec, "content", "") == ip:
                log(f"  DNS {dns_name} -> {ip} already correct, skipping.")
                continue
            log(f"  Updating DNS {dns_name} -> {ip} ...")
            cf.dns.records.update(
                dns_record_id=rec.id,
                zone_id=CF_ZONE_ID,
                name=dns_name,
                type="A",
                content=ip,
                proxied=False,
                ttl=300,
            )
        else:
            log(f"  Creating DNS {dns_name} -> {ip} ...")
            cf.dns.records.create(
                zone_id=CF_ZONE_ID,
                name=dns_name,
                type="A",
                content=ip,
                proxied=False,
                ttl=300,
            )
    log("Phase 2 complete.\n")


# ─────────────────────────────────────────────────────────────────────────────
# Phase 3 — Base OS Configuration (all VMs)
# ─────────────────────────────────────────────────────────────────────────────


def configure_base_vm(name: str, ip: str) -> None:
    """
    On a single VM:
      - upgrade packages, install essentials (including git)
      - create 'student' user with passwordless sudo
      - place provisioner's public key in student's authorized_keys
    """
    pub_key      = Path(SSH_PUBLIC_KEY).read_text().strip()
    sudoers_line = "student ALL=(ALL) NOPASSWD:ALL\n"

    log(f"  [{name}] Configuring base OS ...")
    for attempt in range(1, 6):
        try:
            with connection(ip) as c:
                # Wait for any cloud-init / unattended-upgrades apt lock to clear
                c.run(
                    "systemctl stop unattended-upgrades 2>/dev/null || true && "
                    "flock --timeout 120 /var/lib/dpkg/lock-frontend true 2>/dev/null || true",
                    hide=True,
                )
                c.run(
                    "apt-get update -qq && "
                    "NEEDRESTART_SUSPEND=1 DEBIAN_FRONTEND=noninteractive "
                    "apt-get upgrade -y -qq",
                    hide=True,
                )
                c.run(
                    "NEEDRESTART_SUSPEND=1 DEBIAN_FRONTEND=noninteractive "
                    "apt-get install -y -qq "
                    "curl git vim net-tools gnupg lsb-release "
                    "apt-transport-https ca-certificates",
                    hide=True,
                )
                # Create student user (idempotent)
                c.run("id student &>/dev/null || useradd -m -s /bin/bash student", hide=True)

                # Passwordless sudo
                put_text(c, sudoers_line, "/etc/sudoers.d/student")
                c.run("chmod 440 /etc/sudoers.d/student", hide=True)

                # SSH authorised key for student
                c.run(
                    "install -d -m 700 -o student -g student /home/student/.ssh",
                    hide=True,
                )
                put_text(c, pub_key + "\n", "/home/student/.ssh/authorized_keys")
                c.run(
                    "chmod 600 /home/student/.ssh/authorized_keys && "
                    "chown student:student /home/student/.ssh/authorized_keys",
                    hide=True,
                )
            log(f"  [{name}] Base configuration done.")
            return
        except Exception as e:
            log(f"  [{name}] Attempt {attempt}/5 failed: {type(e).__name__}: {e}")
            if attempt < 5:
                time.sleep(15)
    raise RuntimeError(f"[{name}] All 5 base-configuration attempts failed")


def configure_all_base(vm_ips: dict[str, str]) -> None:
    """Phase 3: wait for SSH, then configure base OS in parallel."""
    log("=== Phase 3: Base OS Configuration ===")
    for ip in vm_ips.values():
        wait_for_ssh(ip)

    with ThreadPoolExecutor(max_workers=8) as pool:
        futures = {
            pool.submit(configure_base_vm, name, ip): name
            for name, ip in vm_ips.items()
        }
        for f in as_completed(futures):
            f.result()
    log("Phase 3 complete.\n")


# ─────────────────────────────────────────────────────────────────────────────
# Phase 4 — code-server + Caddy + Git Clone
# ─────────────────────────────────────────────────────────────────────────────

_CADDY_INSTALL = """\
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
    debian-keyring debian-archive-keyring apt-transport-https
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' \
    | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg 2>/dev/null
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' \
    | tee /etc/apt/sources.list.d/caddy-stable.list >/dev/null
apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq caddy
"""


def configure_vm(ip: str, slug: str, password: str) -> None:
    """
    Install and configure the toolstack on one VM:
      code-server, Caddy, git clone of github-26.06.2026 repo.
    """
    fqdn = f"{slug}.{DOMAIN_SUFFIX}"

    cs_config = (
        "bind-addr: 127.0.0.1:8080\n"
        "auth: password\n"
        f"password: {password}\n"
        "cert: false\n"
    )

    caddyfile = (
        f"{fqdn} {{\n"
        f"    reverse_proxy localhost:8080\n"
        f"    log {{\n"
        f"        output file /var/log/caddy/access.log\n"
        f"    }}\n"
        f"}}\n"
    )

    with connection(ip) as c:
        log(f"  [{slug}] Installing code-server ...")
        c.run("curl -fsSL https://code-server.dev/install.sh | sh", hide=True)

        log(f"  [{slug}] Configuring code-server ...")
        c.run(
            "install -d -m 755 -o student -g student "
            "/home/student/.config/code-server",
            hide=True,
        )
        put_text(c, cs_config, "/home/student/.config/code-server/config.yaml")
        c.run(
            "chown student:student /home/student/.config/code-server/config.yaml",
            hide=True,
        )
        put_text(c, CODESERVER_SERVICE, "/etc/systemd/system/code-server.service")
        c.run(
            "systemctl daemon-reload && "
            "systemctl enable code-server && "
            "systemctl restart code-server",
            hide=True,
        )

        log(f"  [{slug}] Installing Caddy ...")
        c.run(_CADDY_INSTALL, hide=True)
        c.run("mkdir -p /var/log/caddy", hide=True)
        put_text(c, caddyfile, "/etc/caddy/Caddyfile")
        c.run("systemctl enable caddy && systemctl restart caddy", hide=True)

        log(f"  [{slug}] Cloning GitHub repository ...")
        c.run(
            f"test -d /home/student/{GITHUB_REPO_DIR} || "
            f"sudo -u student git clone {GITHUB_REPO_URL} "
            f"/home/student/{GITHUB_REPO_DIR}",
            hide=True,
        )

    log(f"  [{slug}] VM setup complete.")


def configure_all_vms(vm_ips: dict[str, str]) -> dict[str, str]:
    """Phase 4: configure all VMs in parallel. Returns {slug: password}."""
    log("=== Phase 4: code-server + Caddy + Git Clone ===")
    passwords: dict[str, str] = {s["slug"]: gen_password() for s in STUDENTS}

    with ThreadPoolExecutor(max_workers=len(STUDENTS)) as pool:
        futures = {
            pool.submit(
                configure_vm,
                vm_ips[s["slug"]],
                s["slug"],
                passwords[s["slug"]],
            ): s["slug"]
            for s in STUDENTS
        }
        for f in as_completed(futures):
            f.result()

    log("Phase 4 complete.\n")
    return passwords


# ─────────────────────────────────────────────────────────────────────────────
# Phase 5 — Summary
# ─────────────────────────────────────────────────────────────────────────────


def print_summary(vm_ips: dict[str, str], passwords: dict[str, str]) -> None:
    sep = "=" * 72
    print(f"\n{sep}")
    print("  PROVISIONING COMPLETE — GitHub Seminar")
    print(sep)
    for s in STUDENTS:
        slug = s["slug"]
        ip   = vm_ips[slug]
        url  = f"https://{slug}.{DOMAIN_SUFFIX}"
        print(f"\n  Student  : {s['display']}")
        print(f"  VM       : {slug}  ({ip})")
        print(f"  URL      : {url}")
        print(f"  Password : {passwords[slug]}")
        print(f"  SSH      : ssh student@{ip}")
    print()
    print("  NOTES:")
    print("  • Caddy obtains a Let's Encrypt cert on the first HTTPS request.")
    print("    Allow ~60 s after DNS propagates before opening the URLs.")
    print("  • DNS is set grey-cloud (proxy OFF) — required for HTTP-01 challenge.")
    print(f"  • Repo cloned to ~/github-26.06.2026 on each VM.")
    print(sep)

    # Write a machine-readable credentials markdown file alongside this script
    md_path = Path(__file__).parent / "github-seminar-credentials.md"
    rows = "\n".join(
        f"| {s['display']} "
        f"| https://{s['slug']}.{DOMAIN_SUFFIX} "
        f"| `{passwords[s['slug']]}` "
        f"| {vm_ips[s['slug']]} |"
        for s in STUDENTS
    )
    md_path.write_text(
        "# GitHub Seminar — Credentials\n\n"
        "| Student | URL | Password | IP |\n"
        "|---|---|---|---|\n"
        f"{rows}\n\n"
        "SSH login: `ssh student@<ip>`  \n"
        f"Repo cloned at: `~/{GITHUB_REPO_DIR}`  \n"
    )
    print(f"\n  Credentials written to: {md_path}")


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────


def main() -> None:
    vm_ips = provision_hetzner()

    # DNS setup and base OS config are independent — run them concurrently
    with ThreadPoolExecutor(max_workers=2) as pool:
        dns_f  = pool.submit(setup_dns, vm_ips)
        base_f = pool.submit(configure_all_base, vm_ips)
        dns_f.result()
        base_f.result()

    passwords = configure_all_vms(vm_ips)
    print_summary(vm_ips, passwords)


if __name__ == "__main__":
    main()

"""
╔═══════════════════════════════════════════════════════╗
║           DXD VPS Manager Bot - Individual LXC       ║
║  • Each user gets their own LXC container            ║
║  • Full root access in their container               ║
║  • Direct SSH access with password                   ║
║  • 1 container per user limit                        ║
║  • Default: 32GB RAM, 6 CPU, 80GB Disk              ║
║  • Anti-mining protection                            ║
║  • FIXED: IPv4 networking with lxcbr0               ║
║  • TMATE Backup SSH included                         ║
║  • Admin can create VPS for any user                 ║
║  • !deploy command for ALL users                     ║
╚═══════════════════════════════════════════════════════╝
"""

import os
import time
import socket
import random
import string
import secrets
import asyncio
import logging
import sqlite3
import datetime
import subprocess
import tempfile
import traceback

import discord
import psutil
import requests
from discord import app_commands
from discord.ext import commands, tasks
from dotenv import load_dotenv

# Fix for Python < 3.11
try:
    from datetime import UTC
except ImportError:
    from datetime import timezone
    UTC = timezone.utc

load_dotenv()

# ─────────────────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────────────────
DISCORD_TOKEN = os.getenv("DISCORD_TOKEN", "")
ADMIN_ROLE_ID = int(os.getenv("ADMIN_ROLE_ID", "0"))
ADMIN_USER_IDS = set()
for x in os.getenv("ADMIN_USER_IDS", "").split(","):
    if x.strip().isdigit():
        ADMIN_USER_IDS.add(int(x.strip()))

SERVER_IP = os.getenv("SERVER_IP", "127.0.0.1")
SSH_PORT_START = int(os.getenv("SSH_PORT_START", "20000"))
SSH_PORT_END = int(os.getenv("SSH_PORT_END", "29999"))

LXC_STORAGE_POOL = os.getenv("LXC_STORAGE_POOL", "default")
LXC_NETWORK_BRIDGE = os.getenv("LXC_NETWORK_BRIDGE", "lxcbr0")

DEFAULT_RAM_MB = int(os.getenv("DEFAULT_RAM_MB", "32768"))
DEFAULT_CPU_CORES = float(os.getenv("DEFAULT_CPU_CORES", "6"))
DEFAULT_DISK_GB = int(os.getenv("DEFAULT_DISK_GB", "80"))

LXC_IMAGES = {
    "ubuntu20": ("ubuntu:20.04", "Ubuntu 20.04"),
    "ubuntu22": ("ubuntu:22.04", "Ubuntu 22.04"),
    "ubuntu24": ("ubuntu:24.04", "Ubuntu 24.04"),
    "debian11": ("debian:11", "Debian 11"),
    "debian12": ("debian:12", "Debian 12"),
}

DB_FILE = "DXD.db"

ANTI_MINING_ENABLED = os.getenv("ANTI_MINING_ENABLED", "true").lower() == "true"
ANTI_MINING_CHECK_INTERVAL = int(os.getenv("ANTI_MINING_CHECK_INTERVAL", "300"))
ANTI_MINING_CPU_THRESHOLD = float(os.getenv("ANTI_MINING_CPU_THRESHOLD", "80.0"))

# ─────────────────────────────────────────────────────
# LOGGING
# ─────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("DXD.log"),
        logging.StreamHandler(),
    ],
)
log = logging.getLogger("DXD")

# ─────────────────────────────────────────────────────
# COLORS
# ─────────────────────────────────────────────────────
BLUE = 0x5865F2
GREEN = 0x57F287
RED = 0xED4245
YELLOW = 0xFEE75C
DARK = 0x2F3136
FOOTER = "Powered by DXD VPS"

# ─────────────────────────────────────────────────────
# DATABASE
# ─────────────────────────────────────────────────────
def get_db():
    try:
        c = sqlite3.connect(DB_FILE)
        c.row_factory = sqlite3.Row
        return c
    except Exception as e:
        log.error(f"Database connection failed: {e}")
        raise

def init_db():
    try:
        with get_db() as c:
            c.executescript("""
                CREATE TABLE IF NOT EXISTS allowed_users (
                    user_id  INTEGER PRIMARY KEY,
                    added_by INTEGER,
                    added_at TEXT DEFAULT (datetime('now'))
                );
                CREATE TABLE IF NOT EXISTS vps (
                    vps_id       TEXT    PRIMARY KEY,
                    owner_id     INTEGER NOT NULL,
                    container_id TEXT,
                    os_image     TEXT,
                    os_label     TEXT,
                    ram_mb       INTEGER,
                    cpu_cores    REAL,
                    disk_gb      INTEGER,
                    ssh_port     INTEGER DEFAULT NULL,
                    root_pass    TEXT    DEFAULT '',
                    ssh_cmd      TEXT    DEFAULT '',
                    status       TEXT    DEFAULT 'running',
                    expires_at   TEXT    DEFAULT NULL,
                    mining_flag  INTEGER DEFAULT 0,
                    created_at   TEXT    DEFAULT (datetime('now'))
                );
                CREATE TABLE IF NOT EXISTS mining_logs (
                    id           INTEGER PRIMARY KEY AUTOINCREMENT,
                    vps_id       TEXT    NOT NULL,
                    detected_at  TEXT    DEFAULT (datetime('now')),
                    cpu_usage    REAL,
                    reasons      TEXT,
                    action_taken TEXT,
                    resolved     INTEGER DEFAULT 0
                );
            """)
        log.info("Database ready.")
    except Exception as e:
        log.error(f"Database init failed: {e}")
        raise

# ─────────────────────────────────────────────────────
# LXC HELPERS
# ─────────────────────────────────────────────────────
def lxc_command(args, check=True):
    cmd = ["lxc"] + args
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=check)
        return result
    except subprocess.CalledProcessError as e:
        if check:
            log.error(f"LXC command failed: {' '.join(cmd)}")
            log.error(f"STDERR: {e.stderr}")
            raise RuntimeError(f"LXC command failed: {e.stderr}") from e
        return e
    except Exception as e:
        if check:
            raise
        return None

def lxc_exists(name):
    try:
        result = lxc_command(["info", name], check=False)
        return result is not None and hasattr(result, 'returncode') and result.returncode == 0
    except:
        return False

def lxc_is_running(name):
    try:
        result = lxc_command(["list", "--format", "csv"], check=False)
        if result is None or not hasattr(result, 'stdout'):
            return False
        for line in result.stdout.strip().split("\n"):
            if line and line.startswith(name + ","):
                parts = line.split(",")
                return len(parts) > 1 and parts[1].strip() == "RUNNING"
        return False
    except:
        return False

def lxc_get_ip(name):
    try:
        result = lxc_command(["info", name], check=False)
        if result is None or not hasattr(result, 'stdout'):
            return ""
        for line in result.stdout.split("\n"):
            if "inet" in line and "inet6" not in line:
                parts = line.strip().split()
                if len(parts) > 2:
                    ip = parts[1].split("/")[0]
                    if ip and ip != "127.0.0.1" and not ip.startswith("169.254"):
                        return ip
        return ""
    except:
        return ""

def lxc_stop(name):
    try:
        lxc_command(["stop", name, "--force"], check=False)
    except:
        pass

def lxc_start(name):
    try:
        lxc_command(["start", name])
    except Exception as e:
        log.error(f"Failed to start container {name}: {e}")
        raise

def lxc_restart(name):
    try:
        lxc_command(["restart", name, "--force"])
    except Exception as e:
        log.error(f"Failed to restart container {name}: {e}")
        raise

def lxc_delete(name):
    try:
        lxc_stop(name)
        time.sleep(1)
        lxc_command(["delete", name, "--force"], check=False)
    except:
        pass

def lxc_exec(name, command, check=True):
    try:
        result = lxc_command(["exec", name, "--", "bash", "-c", command], check=check)
        if result is None:
            return ""
        if hasattr(result, 'stdout'):
            return result.stdout
        return ""
    except Exception as e:
        if check:
            raise
        return ""

def lxc_file_push(name, content, dest_path):
    temp_file = None
    try:
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            f.write(content)
            temp_file = f.name
        lxc_command(["file", "push", temp_file, f"{name}{dest_path}"])
    finally:
        if temp_file and os.path.exists(temp_file):
            try:
                os.unlink(temp_file)
            except:
                pass

def lxc_wait_for_network(name, timeout=120):
    start = time.time()
    while time.time() - start < timeout:
        ip = lxc_get_ip(name)
        if ip:
            return True
        time.sleep(3)
    return False

def lxc_wait_for_ssh(name, timeout=180):
    start = time.time()
    while time.time() - start < timeout:
        try:
            result = lxc_command(["exec", name, "--", "bash", "-c", 
                                 "ss -tln | grep ':22 ' || netstat -tln | grep ':22 '"],
                                 check=False)
            if result and hasattr(result, 'stdout') and "LISTEN" in result.stdout:
                return True
        except:
            pass
        time.sleep(3)
    return False

# ─────────────────────────────────────────────────────
# PORT + PASSWORD HELPERS
# ─────────────────────────────────────────────────────
def _port_in_use_locally(port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.3)
            return s.connect_ex(("127.0.0.1", port)) == 0
    except:
        return False

def find_free_port():
    with get_db() as c:
        used = {row["ssh_port"] for row in
                c.execute("SELECT ssh_port FROM vps WHERE ssh_port IS NOT NULL").fetchall()}
    for _ in range(200):
        p = random.randint(SSH_PORT_START, SSH_PORT_END)
        if p in used:
            continue
        if _port_in_use_locally(p):
            continue
        return p
    raise RuntimeError("No free SSH ports available in range.")

def gen_root_password(length=16):
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))

def next_id():
    try:
        with get_db() as c:
            row = c.execute("SELECT vps_id FROM vps ORDER BY vps_id DESC LIMIT 1").fetchone()
        db_num = 1 if not row else int(row["vps_id"].split("-")[-1]) + 1
    except:
        db_num = 1
    
    lxc_max = 0
    try:
        result = lxc_command(["list", "--format", "csv"], check=False)
        if result and hasattr(result, 'stdout'):
            for line in result.stdout.split("\n"):
                if line and "DXD-vps-" in line:
                    try:
                        parts = line.split(",")
                        name = parts[0]
                        num = int(name.split("-")[-1])
                        lxc_max = max(lxc_max, num)
                    except:
                        pass
    except:
        pass
    
    return f"DXD-vps-{max(db_num, lxc_max + 1):04d}"

# ─────────────────────────────────────────────────────
# FAKE /proc GENERATORS
# ─────────────────────────────────────────────────────
def fake_meminfo(mb):
    kb = mb * 1024
    return "\n".join([
        f"MemTotal:       {kb} kB",
        f"MemFree:        {int(kb*.88)} kB",
        f"MemAvailable:   {int(kb*.85)} kB",
        "Buffers:            128 kB",
        f"Cached:         {int(kb*.05)} kB",
        "SwapCached:           0 kB",
        f"Active:         {int(kb*.10)} kB",
        f"Inactive:       {int(kb*.02)} kB",
        "SwapTotal:            0 kB",
        "SwapFree:             0 kB",
        "Dirty:                4 kB",
        "Writeback:            0 kB",
        f"AnonPages:      {int(kb*.08)} kB",
        f"Mapped:         {int(kb*.02)} kB",
        "Shmem:               64 kB",
        "Slab:               512 kB",
        f"VmallocTotal:   {kb} kB",
        "VmallocUsed:          0 kB",
        f"VmallocChunk:   {kb} kB",
        "HugePages_Total:      0",
        "HugePages_Free:       0",
        "Hugepagesize:      2048 kB", "",
    ])

def fake_cpuinfo(cores):
    n = max(1, int(cores))
    blocks = []
    for i in range(n):
        blocks.append("\n".join([
            f"processor\t: {i}",
            f"vendor_id\t: AuthenticAMD",
            "cpu family\t: 25",
            "model\t\t: 97",
            "model name\t: AMD Ryzen 9 9950X 16-Core Processor",
            "stepping\t: 2",
            "cpu MHz\t\t: 4200.000",
            "cache size\t: 65536 KB",
            "physical id\t: 0",
            f"siblings\t: {n}",
            f"core id\t\t: {i}",
            f"cpu cores\t: {n}",
            "fpu\t\t: yes",
            "bogomips\t: 8400.00",
            "clflush size\t: 64",
            "cache_alignment\t: 64", "",
        ]))
    return "\n".join(blocks)

# ─────────────────────────────────────────────────────
# CORE VPS PROVISION
# ─────────────────────────────────────────────────────
def provision(vps_id, image, os_label, ram_mb, cpu_cores, disk_gb, host_port, root_pass):
    log.info(f"[{vps_id}] Provisioning LXC — RAM:{ram_mb}MB CPU:{cpu_cores} Disk:{disk_gb}GB")

    if lxc_exists(vps_id):
        log.warning(f"[{vps_id}] Removing leftover container")
        lxc_delete(vps_id)
        time.sleep(2)

    log.info(f"[{vps_id}] Creating LXC container from {image}...")
    
    try:
        lxc_command(["init", image, vps_id])
        log.info(f"[{vps_id}] Container created")
    except Exception as e:
        log.warning(f"[{vps_id}] Init failed: {e}")
        raise
    
    time.sleep(2)
    
    try:
        lxc_command(["config", "device", "add", vps_id, "eth0", "nic", 
                     "network=lxcbr0", "name=eth0", "type=nic"])
        log.info(f"[{vps_id}] Network device added on lxcbr0")
    except Exception as e:
        log.warning(f"[{vps_id}] Network device add failed: {e}")
    
    ip_suffix = random.randint(100, 250)
    static_ip = f"10.0.3.{ip_suffix}"
    try:
        lxc_command(["config", "set", vps_id, "raw.lxc", 
                     f'lxc.net.0.ipv4.address = {static_ip}/24'])
        log.info(f"[{vps_id}] Static IP set: {static_ip}")
    except Exception as e:
        log.warning(f"[{vps_id}] Static IP set failed: {e}")
    
    configs = [
        (["config", "set", vps_id, "limits.memory", f"{ram_mb}MB"], "memory"),
        (["config", "set", vps_id, "limits.cpu", str(int(cpu_cores))], "cpu"),
        (["config", "set", vps_id, "security.nesting", "true"], "nesting"),
        (["config", "set", vps_id, "security.privileged", "true"], "privileged"),
    ]
    
    for args, name in configs:
        try:
            lxc_command(args)
            log.info(f"[{vps_id}] {name} configured")
        except Exception as e:
            log.warning(f"[{vps_id}] Failed to set {name}: {e}")
    
    log.info(f"[{vps_id}] Starting container...")
    lxc_start(vps_id)
    
    time.sleep(10)
    container_ip = lxc_get_ip(vps_id)
    
    if not container_ip:
        log.warning(f"[{vps_id}] No IP found, setting manually...")
        try:
            lxc_exec(vps_id, f"ip addr add {static_ip}/24 dev eth0", check=False)
            lxc_exec(vps_id, "ip link set eth0 up", check=False)
            lxc_exec(vps_id, "ip route add default via 10.0.3.1", check=False)
            time.sleep(2)
            container_ip = static_ip
            log.info(f"[{vps_id}] Manual IP set: {container_ip}")
        except Exception as e:
            log.warning(f"[{vps_id}] Manual IP failed: {e}")
    
    log.info(f"[{vps_id}] Container IP: {container_ip}")
    
    log.info(f"[{vps_id}] Running apt update...")
    for i in range(3):
        try:
            lxc_exec(vps_id, "apt-get update -qq", check=False)
            break
        except:
            time.sleep(5)
    
    log.info(f"[{vps_id}] Installing packages...")
    lxc_exec(vps_id, 
        "DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "
        "openssh-server tmate neofetch curl wget sudo procps net-tools "
        "iproute2 htop systemd systemd-sysv", check=False)
    
    log.info(f"[{vps_id}] Setting root password...")
    lxc_exec(vps_id, f"echo 'root:{root_pass}' | chpasswd", check=False)
    lxc_exec(vps_id, "mkdir -p /run/sshd", check=False)
    
    ssh_config = """
sed -i 's/^#\\?PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config
sed -i 's/^#\\?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config
sed -i 's/^#\\?ChallengeResponseAuthentication.*/ChallengeResponseAuthentication yes/' /etc/ssh/sshd_config
grep -q '^PermitRootLogin' /etc/ssh/sshd_config || echo 'PermitRootLogin yes' >> /etc/ssh/sshd_config
grep -q '^PasswordAuthentication' /etc/ssh/sshd_config || echo 'PasswordAuthentication yes' >> /etc/ssh/sshd_config
"""
    lxc_exec(vps_id, ssh_config, check=False)
    
    log.info(f"[{vps_id}] Restarting SSH...")
    lxc_exec(vps_id, "systemctl enable ssh 2>/dev/null", check=False)
    lxc_exec(vps_id, "systemctl restart ssh 2>/dev/null", check=False)
    lxc_exec(vps_id, "systemctl restart sshd 2>/dev/null", check=False)
    lxc_exec(vps_id, "service ssh restart 2>/dev/null", check=False)
    
    time.sleep(5)
    
    if container_ip:
        log.info(f"[{vps_id}] Setting up port forwarding: {host_port} -> {container_ip}:22")
        try:
            subprocess.run(["iptables", "-t", "nat", "-D", "PREROUTING", "-p", "tcp", "--dport", str(host_port), "-j", "DNAT", "--to-destination", f"{container_ip}:22"], check=False, capture_output=True)
            subprocess.run(["iptables", "-D", "FORWARD", "-p", "tcp", "-d", container_ip, "--dport", "22", "-j", "ACCEPT"], check=False, capture_output=True)
            
            subprocess.run([
                "iptables", "-t", "nat", "-A", "PREROUTING",
                "-p", "tcp", "--dport", str(host_port),
                "-j", "DNAT", "--to-destination", f"{container_ip}:22"
            ], check=True, capture_output=True)
            
            subprocess.run([
                "iptables", "-A", "FORWARD",
                "-p", "tcp", "-d", container_ip, "--dport", "22",
                "-j", "ACCEPT"
            ], check=True, capture_output=True)
            
            subprocess.run(["iptables", "-A", "FORWARD", "-i", "lxcbr0", "-o", "eth0", "-j", "ACCEPT"], check=False, capture_output=True)
            subprocess.run(["iptables", "-A", "FORWARD", "-i", "eth0", "-o", "lxcbr0", "-j", "ACCEPT"], check=False, capture_output=True)
            
            subprocess.run(["iptables-save"], capture_output=True)
        except Exception as e:
            log.warning(f"[{vps_id}] Port forwarding failed: {e}")
    
    # Fake /proc files
    lxc_exec(vps_id, "mkdir -p /etc/DXD", check=False)
    lxc_file_push(vps_id, fake_meminfo(ram_mb), "/etc/DXD/meminfo")
    lxc_file_push(vps_id, fake_cpuinfo(cpu_cores), "/etc/DXD/cpuinfo")
    
    mount_script = """#!/bin/bash
mount --bind /etc/DXD/meminfo /proc/meminfo 2>/dev/null
mount --bind /etc/DXD/cpuinfo /proc/cpuinfo 2>/dev/null
exit 0
"""
    lxc_file_push(vps_id, mount_script, "/etc/rc.local")
    lxc_exec(vps_id, "chmod +x /etc/rc.local", check=False)
    
    lxc_exec(vps_id, f"hostnamectl set-hostname {vps_id} 2>/dev/null || hostname {vps_id}", check=False)
    lxc_exec(vps_id, f"echo {vps_id} > /etc/hostname", check=False)
    
    motd = f"""
  ╔══════════════════════════════════╗
  ║          🐉  DXD VPS            ║
  ╠══════════════════════════════════╣
  ║  VPS ID : {vps_id:<24}║
  ║  RAM    : {str(ram_mb)+' MB':<24}║
  ║  CPU    : {str(int(cpu_cores))+' vCore(s)':<24}║
  ║  Disk   : {str(disk_gb)+' GB':<24}║
  ║  OS     : {os_label:<24}║
  ╚══════════════════════════════════╝
"""
    lxc_file_push(vps_id, motd, "/etc/motd")
    
    # TMATE BACKUP SSH
    log.info(f"[{vps_id}] Starting tmate SSH session...")
    sock = "/tmp/tmate.sock"
    lxc_exec(vps_id, f"rm -f {sock}; tmate -S {sock} new-session -d", check=False)
    time.sleep(5)
    lxc_exec(vps_id, f"tmate -S {sock} wait tmate-ready", check=False)
    result = lxc_exec(vps_id, f"tmate -S {sock} display -p '#{{tmate_ssh}}'", check=False)
    ssh_backup = result.strip() if result else ""
    log.info(f"[{vps_id}] tmate backup SSH ready: {ssh_backup}")
    
    lxc_command(["config", "set", vps_id, "user.vps-id", vps_id])
    lxc_command(["config", "set", vps_id, "user.managed-by", "DXD"])
    
    return vps_id, ssh_backup, container_ip

# ─────────────────────────────────────────────────────
# EMBED HELPER
# ─────────────────────────────────────────────────────
def em(title, desc="", color=BLUE, fields=None):
    try:
        e = discord.Embed(
            title=title, description=desc,
            color=color, timestamp=datetime.datetime.now(UTC)
        )
    except:
        e = discord.Embed(
            title=title, description=desc,
            color=color
        )
    e.set_footer(text=FOOTER)
    if fields:
        for n, v, i in fields:
            try:
                e.add_field(name=n, value=v, inline=i)
            except:
                pass
    return e

# ─────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────
def is_admin(ix):
    if ix.user.id in ADMIN_USER_IDS:
        return True
    if ix.guild:
        try:
            return any(r.id == ADMIN_ROLE_ID for r in ix.user.roles)
        except:
            return False
    return False

def is_admin_prefix(user):
    if user.id in ADMIN_USER_IDS:
        return True
    if user.guild:
        try:
            return any(r.id == ADMIN_ROLE_ID for r in user.roles)
        except:
            return False
    return False

def owns(uid: int, vid: str) -> bool:
    with get_db() as c:
        return bool(c.execute("SELECT 1 FROM vps WHERE vps_id=? AND owner_id=?", (vid, uid)).fetchone())

def has_vps(uid):
    try:
        with get_db() as c:
            result = c.execute("SELECT 1 FROM vps WHERE owner_id=? AND status != 'deleted'", (uid,)).fetchone()
            return result is not None
    except:
        return False

def get_user_vps(uid):
    try:
        with get_db() as c:
            return c.execute("SELECT * FROM vps WHERE owner_id=? AND status != 'deleted'", (uid,)).fetchone()
    except:
        return None

# ─────────────────────────────────────────────────────
# BOT
# ─────────────────────────────────────────────────────
intents = discord.Intents.default()
intents.members = True
intents.message_content = True

class DXD(commands.Bot):
    def __init__(self):
        super().__init__(command_prefix="!", intents=intents)

    async def setup_hook(self):
        try:
            await self.tree.sync()
            log.info("Commands synced.")
        except Exception as e:
            log.error(f"Failed to sync commands: {e}")
        
        if ANTI_MINING_ENABLED:
            try:
                anti_mining_scan.start()
                log.info("Anti-mining scan started.")
            except Exception as e:
                log.error(f"Failed to start anti-mining scan: {e}")

    async def on_ready(self):
        log.info(f"✅ Online as {self.user}")
        try:
            await self.tree.sync()
            log.info("Commands re-synced on ready.")
        except Exception as e:
            log.error(f"Failed to re-sync commands: {e}")
        
        if not update_status.is_running():
            try:
                update_status.start()
            except Exception as e:
                log.error(f"Failed to start status update: {e}")

bot = DXD()

# ─────────────────────────────────────────────────────
# TASKS
# ─────────────────────────────────────────────────────
@tasks.loop(minutes=2)
async def update_status():
    try:
        with get_db() as c:
            count = c.execute("SELECT COUNT(*) AS n FROM vps WHERE status='running'").fetchone()
            if count:
                await bot.change_presence(activity=discord.Activity(
                    type=discord.ActivityType.watching,
                    name=f"DXD | {count['n']} VPS Running"))
    except Exception as e:
        log.warning(f"Status update failed: {e}")

@update_status.before_loop
async def _status_before():
    await bot.wait_until_ready()

@tasks.loop(minutes=ANTI_MINING_CHECK_INTERVAL // 60 if ANTI_MINING_CHECK_INTERVAL > 60 else 5)
async def anti_mining_scan():
    if not ANTI_MINING_ENABLED:
        return
    
    try:
        log.info("Running anti-mining scan...")
        with get_db() as c:
            vps_list = c.execute("SELECT * FROM vps WHERE status='running'").fetchall()
        
        for vps in vps_list:
            container_name = vps["container_id"] or vps["vps_id"]
            try:
                if not lxc_exists(container_name) or not lxc_is_running(container_name):
                    continue
                
                stats = lxc_exec(container_name, "top -bn1 | grep 'Cpu(s)' | awk '{print $2}' | cut -d'%' -f1", check=False)
                if stats and stats.strip():
                    try:
                        cpu_usage = float(stats.strip())
                        if cpu_usage > ANTI_MINING_CPU_THRESHOLD:
                            mining_check = lxc_exec(container_name, 
                                "ps aux | grep -E 'xmrig|minerd|cpuminer|miner|ccminer|cgminer|ethminer|t-rex' | grep -v grep",
                                check=False)
                            
                            if mining_check and mining_check.strip():
                                log.warning(f"[{vps['vps_id']}] Mining detected!")
                                
                                lxc_stop(container_name)
                                with get_db() as db:
                                    db.execute("UPDATE vps SET status='suspended', mining_flag=1 WHERE vps_id=?", (vps["vps_id"],))
                                
                                with get_db() as db:
                                    db.execute("""
                                        INSERT INTO mining_logs (vps_id, cpu_usage, reasons, action_taken)
                                        VALUES (?, ?, ?, ?)
                                    """, (vps["vps_id"], cpu_usage, mining_check[:200], "Suspended"))
                                
                                try:
                                    user = await bot.fetch_user(vps["owner_id"])
                                    if user:
                                        await user.send(embed=em(
                                            "🚨 VPS Suspended - Mining Detected",
                                            f"Your VPS **{vps['vps_id']}** has been suspended for mining.\n"
                                            f"CPU Usage: {cpu_usage}%\n"
                                            f"Detected: {mining_check[:100]}",
                                            RED
                                        ))
                                except:
                                    pass
                                
                                for admin_id in ADMIN_USER_IDS:
                                    try:
                                        admin = await bot.fetch_user(admin_id)
                                        if admin:
                                            await admin.send(embed=em(
                                                "🚨 Mining Alert",
                                                f"VPS **{vps['vps_id']}** was mining.\n"
                                                f"CPU: {cpu_usage}%\n"
                                                f"Processes: {mining_check[:100]}",
                                                RED
                                            ))
                                    except:
                                        pass
                    except ValueError:
                        pass
            except Exception as e:
                log.error(f"Error scanning {vps['vps_id']}: {e}")
    except Exception as e:
        log.error(f"Anti-mining scan failed: {e}")

@anti_mining_scan.before_loop
async def _before_anti_mining():
    await bot.wait_until_ready()

# ─────────────────────────────────────────────────────
# USER COMMANDS (SLASH)
# ─────────────────────────────────────────────────────
@bot.tree.command(name="my-vps", description="View your VPS info")
async def cmd_my_vps(ix: discord.Interaction):
    try:
        await ix.response.defer(ephemeral=True)
        
        vps = get_user_vps(ix.user.id)
        if not vps:
            return await ix.followup.send(embed=em("❌ No VPS", "You don't have a VPS. Use `!deploy`.", RED))
        
        container_name = vps["container_id"] or vps["vps_id"]
        running = lxc_is_running(container_name) if lxc_exists(container_name) else False
        ram_gb = vps["ram_mb"] / 1024
        
        await ix.followup.send(embed=em(
            "📊 Your VPS",
            f"**VPS ID:** `{vps['vps_id']}`\n"
            f"**Status:** {'🟢 Running' if running else '🔴 Stopped'}\n"
            f"**SSH Port:** `{vps['ssh_port']}`\n"
            f"**OS:** {vps['os_label']}\n"
            f"**RAM:** {vps['ram_mb']} MB ({ram_gb:.0f} GB)\n"
            f"**CPU:** {vps['cpu_cores']} Core(s)\n"
            f"**Disk:** {vps['disk_gb']} GB\n"
            f"**Mining Flag:** {'🚨 Yes' if vps['mining_flag'] else '✅ No'}",
            GREEN if running else RED
        ))
    except Exception as e:
        log.error(f"my-vps command error: {e}")
        try:
            await ix.followup.send(embed=em("❌ Error", str(e)[:200], RED))
        except:
            pass

@bot.tree.command(name="start", description="Start your VPS")
async def cmd_start(ix: discord.Interaction):
    try:
        await ix.response.defer(ephemeral=True)
        
        vps = get_user_vps(ix.user.id)
        if not vps:
            return await ix.followup.send(embed=em("❌ No VPS", "You don't have a VPS.", RED))
        
        if vps["status"] == "suspended":
            return await ix.followup.send(embed=em("⛔ Suspended", "Your VPS is suspended. Contact admin.", RED))
        
        container_name = vps["container_id"] or vps["vps_id"]
        if lxc_exists(container_name):
            lxc_start(container_name)
            with get_db() as c:
                c.execute("UPDATE vps SET status='running' WHERE vps_id=?", (vps["vps_id"],))
            await ix.followup.send(embed=em("✅ Started", f"**{vps['vps_id']}** is running.", GREEN))
        else:
            await ix.followup.send(embed=em("❌ Error", "Container not found.", RED))
    except Exception as e:
        log.error(f"start command error: {e}")
        try:
            await ix.followup.send(embed=em("❌ Error", str(e)[:200], RED))
        except:
            pass

@bot.tree.command(name="stop", description="Stop your VPS")
async def cmd_stop(ix: discord.Interaction):
    try:
        await ix.response.defer(ephemeral=True)
        
        vps = get_user_vps(ix.user.id)
        if not vps:
            return await ix.followup.send(embed=em("❌ No VPS", "You don't have a VPS.", RED))
        
        container_name = vps["container_id"] or vps["vps_id"]
        if lxc_exists(container_name):
            lxc_stop(container_name)
            with get_db() as c:
                c.execute("UPDATE vps SET status='stopped' WHERE vps_id=?", (vps["vps_id"],))
            await ix.followup.send(embed=em("🛑 Stopped", f"**{vps['vps_id']}** stopped.", YELLOW))
        else:
            await ix.followup.send(embed=em("❌ Error", "Container not found.", RED))
    except Exception as e:
        log.error(f"stop command error: {e}")
        try:
            await ix.followup.send(embed=em("❌ Error", str(e)[:200], RED))
        except:
            pass

@bot.tree.command(name="restart", description="Restart your VPS")
async def cmd_restart(ix: discord.Interaction):
    try:
        await ix.response.defer(ephemeral=True)
        
        vps = get_user_vps(ix.user.id)
        if not vps:
            return await ix.followup.send(embed=em("❌ No VPS", "You don't have a VPS.", RED))
        
        container_name = vps["container_id"] or vps["vps_id"]
        if lxc_exists(container_name):
            lxc_restart(container_name)
            with get_db() as c:
                c.execute("UPDATE vps SET status='running' WHERE vps_id=?", (vps["vps_id"],))
            await ix.followup.send(embed=em("🔄 Restarted", f"**{vps['vps_id']}** restarted.", GREEN))
        else:
            await ix.followup.send(embed=em("❌ Error", "Container not found.", RED))
    except Exception as e:
        log.error(f"restart command error: {e}")
        try:
            await ix.followup.send(embed=em("❌ Error", str(e)[:200], RED))
        except:
            pass

@bot.tree.command(name="show-ssh", description="Show your VPS SSH credentials")
async def cmd_show_ssh(ix: discord.Interaction):
    try:
        await ix.response.defer(ephemeral=True)
        
        vps = get_user_vps(ix.user.id)
        if not vps:
            return await ix.followup.send(embed=em("❌ No VPS", "You don't have a VPS.", RED))
        
        container_name = vps["container_id"] or vps["vps_id"]
        running = lxc_is_running(container_name) if lxc_exists(container_name) else False
        
        direct_ssh_cmd = f"ssh root@{SERVER_IP} -p {vps['ssh_port']}"
        
        await ix.followup.send(embed=em(
            "🔑 Your SSH Credentials",
            f"**{vps['vps_id']}**\n"
            f"**Status:** {'🟢 Running' if running else '🔴 Stopped'}\n\n"
            f"**🔑 MAIN SSH:**\n"
            f"```{direct_ssh_cmd}```\n"
            f"**Password:** ```{vps['root_pass']}```\n\n"
            f"**🔄 BACKUP SSH (tmate):**\n"
            f"```{vps['ssh_cmd'] or 'Not available'}```\n\n"
            f"📡 **Port:** `{vps['ssh_port']}`",
            GREEN if running else YELLOW
        ))
    except Exception as e:
        log.error(f"show-ssh command error: {e}")
        try:
            await ix.followup.send(embed=em("❌ Error", str(e)[:200], RED))
        except:
            pass

@bot.tree.command(name="regen-ssh", description="Regenerate your VPS SSH credentials (new password + tmate)")
@app_commands.describe(vps_id="VPS ID (optional, if you have multiple)")
async def cmd_regen_ssh(ix: discord.Interaction, vps_id: str = None):
    try:
        await ix.response.defer(ephemeral=True)
        
        if vps_id:
            if not owns(ix.user.id, vps_id):
                return await ix.followup.send(embed=em("❌ Access Denied", "That VPS doesn't belong to you.", RED))
            with get_db() as c:
                vps = c.execute("SELECT * FROM vps WHERE vps_id=?", (vps_id,)).fetchone()
        else:
            vps = get_user_vps(ix.user.id)
        
        if not vps:
            return await ix.followup.send(embed=em("❌ No VPS", "You don't have a VPS.", RED))
        
        if vps["status"] == "suspended":
            return await ix.followup.send(embed=em("⛔ Suspended", "Your VPS is suspended. Contact admin.", RED))
        
        container_name = vps["container_id"] or vps["vps_id"]
        
        if not lxc_exists(container_name):
            return await ix.followup.send(embed=em("❌ Error", "Container not found.", RED))
        
        if not lxc_is_running(container_name):
            return await ix.followup.send(embed=em("⚠️ Not Running", "Start your VPS first with `/start`.", YELLOW))
        
        new_password = gen_root_password()
        lxc_exec(container_name, f"echo 'root:{new_password}' | chpasswd", check=False)
        
        # Regenerate tmate
        log.info(f"[{vps['vps_id']}] Regenerating tmate SSH...")
        sock = "/tmp/tmate.sock"
        lxc_exec(container_name, f"rm -f {sock}; tmate -S {sock} new-session -d", check=False)
        time.sleep(3)
        lxc_exec(container_name, f"tmate -S {sock} wait tmate-ready", check=False)
        result = lxc_exec(container_name, f"tmate -S {sock} display -p '#{{tmate_ssh}}'", check=False)
        ssh_backup = result.strip() if result else ""
        
        lxc_exec(container_name, "systemctl restart ssh 2>/dev/null", check=False)
        lxc_exec(container_name, "systemctl restart sshd 2>/dev/null", check=False)
        
        with get_db() as c:
            c.execute("UPDATE vps SET root_pass=?, ssh_cmd=? WHERE vps_id=?", 
                      (new_password, ssh_backup, vps["vps_id"]))
        
        try:
            dm = await ix.user.create_dm()
            direct_ssh_cmd = f"ssh root@{SERVER_IP} -p {vps['ssh_port']}"
            await dm.send(embed=em(
                "🔄 SSH Credentials Regenerated",
                f"**{vps['vps_id']}**\n\n"
                f"**🔑 NEW MAIN SSH:**\n"
                f"```{direct_ssh_cmd}```\n"
                f"**New Password:** ```{new_password}```\n\n"
                f"**🔄 BACKUP SSH (tmate):**\n"
                f"```{ssh_backup}```\n\n"
                f"⚠️ **Old password no longer works!**",
                GREEN
            ))
            dm_ok = True
        except:
            dm_ok = False
        
        await ix.followup.send(embed=em(
            "✅ SSH Credentials Regenerated",
            f"**{vps['vps_id']}**\n"
            f"{'✅ New credentials sent to DM.' if dm_ok else '⚠️ Could not DM you.'}",
            GREEN
        ))
    except Exception as e:
        log.error(f"regen-ssh command error: {e}")
        try:
            await ix.followup.send(embed=em("❌ Error", str(e)[:200], RED))
        except:
            pass

@bot.tree.command(name="delete-vps", description="Delete your VPS (WARNING: All data lost)")
async def cmd_delete_vps(ix: discord.Interaction):
    try:
        await ix.response.defer(ephemeral=True)
        
        vps = get_user_vps(ix.user.id)
        if not vps:
            return await ix.followup.send(embed=em("❌ No VPS", "You don't have a VPS.", RED))
        
        container_name = vps["container_id"] or vps["vps_id"]
        if lxc_exists(container_name):
            lxc_delete(container_name)
        
        with get_db() as c:
            c.execute("DELETE FROM vps WHERE vps_id=?", (vps["vps_id"],))
        
        await ix.followup.send(embed=em("🗑 Deleted", f"**{vps['vps_id']}** permanently deleted.", YELLOW))
    except Exception as e:
        log.error(f"delete-vps command error: {e}")
        try:
            await ix.followup.send(embed=em("❌ Error", str(e)[:200], RED))
        except:
            pass

# ─────────────────────────────────────────────────────
# ADMIN COMMANDS (SLASH)
# ─────────────────────────────────────────────────────
@bot.tree.command(name="admin-add-user", description="[Admin] Grant access")
@app_commands.describe(user="User to grant access")
async def cmd_add(ix: discord.Interaction, user: discord.Member):
    try:
        await ix.response.defer(ephemeral=True)
        if not is_admin(ix):
            return await ix.followup.send(embed=em("⛔ Forbidden", "Admin only.", RED))
        with get_db() as c:
            c.execute("INSERT OR IGNORE INTO allowed_users (user_id, added_by) VALUES (?,?)", (user.id, ix.user.id))
        await ix.followup.send(embed=em("✅ Added", f"{user.mention} can now create VPS.", GREEN))
    except Exception as e:
        log.error(f"admin-add-user error: {e}")
        try:
            await ix.followup.send(embed=em("❌ Error", str(e)[:200], RED))
        except:
            pass

@bot.tree.command(name="admin-remove-user", description="[Admin] Revoke access")
@app_commands.describe(user="User to revoke")
async def cmd_rm(ix: discord.Interaction, user: discord.Member):
    try:
        await ix.response.defer(ephemeral=True)
        if not is_admin(ix):
            return await ix.followup.send(embed=em("⛔ Forbidden", "Admin only.", RED))
        with get_db() as c:
            c.execute("DELETE FROM allowed_users WHERE user_id=?", (user.id,))
        await ix.followup.send(embed=em("🗑 Removed", f"{user.mention} access revoked.", YELLOW))
    except Exception as e:
        log.error(f"admin-remove-user error: {e}")
        try:
            await ix.followup.send(embed=em("❌ Error", str(e)[:200], RED))
        except:
            pass

@bot.tree.command(name="admin-create", description="[Admin] Create VPS for any user")
@app_commands.describe(
    user="User to create VPS for",
    ram="RAM in MB (default: 32768 = 32GB)",
    cpu="CPU cores (default: 6)",
    disk="Disk in GB (default: 80)",
    os="Operating System",
    days="Auto-suspend after days (0 = never)"
)
@app_commands.choices(
    os=[
        app_commands.Choice(name="Ubuntu 20.04", value="ubuntu20"),
        app_commands.Choice(name="Ubuntu 22.04", value="ubuntu22"),
        app_commands.Choice(name="Ubuntu 24.04", value="ubuntu24"),
        app_commands.Choice(name="Debian 11", value="debian11"),
        app_commands.Choice(name="Debian 12", value="debian12"),
    ]
)
async def cmd_admin_create(
    ix: discord.Interaction, 
    user: discord.Member, 
    ram: int = 32768, 
    cpu: float = 6.0, 
    disk: int = 80,
    os: app_commands.Choice[str] = None,
    days: int = 0
):
    try:
        await ix.response.defer(ephemeral=True)
        
        if not is_admin(ix):
            return await ix.followup.send(embed=em("⛔ Forbidden", "Admin only.", RED))
        
        if has_vps(user.id):
            return await ix.followup.send(embed=em(
                "❌ User Already Has VPS",
                f"{user.mention} already has a VPS. Only 1 VPS per user.",
                RED
            ))
        
        os_key = "ubuntu22" if not os else os.value
        image, os_label = LXC_IMAGES[os_key]
        
        vps_id = next_id()
        root_pass = gen_root_password()
        host_port = find_free_port()
        
        if ram < 1024:
            return await ix.followup.send(embed=em("❌ Invalid", "RAM must be at least 1024 MB (1 GB).", RED))
        if cpu < 0.5:
            return await ix.followup.send(embed=em("❌ Invalid", "CPU must be at least 0.5 cores.", RED))
        if disk < 5:
            return await ix.followup.send(embed=em("❌ Invalid", "Disk must be at least 5 GB.", RED))
        
        exp_at = None
        exp_note = "Never expires"
        if days > 0:
            try:
                dt = datetime.datetime.now(UTC) + datetime.timedelta(days=days)
            except:
                dt = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=days)
            exp_at = dt.isoformat()
            exp_note = f"Auto-suspends <t:{int(dt.timestamp())}:R>"
        
        await ix.followup.send(embed=em(
            "⏳ Admin Creating VPS...",
            f"**{vps_id}** for {user.mention}\n\n"
            "```\n"
            "[1/5] Creating LXC container      ⏳\n"
            "[2/5] Configuring network         ⏳\n"
            "[3/5] Installing packages         ⏳\n"
            "[4/5] Setting up SSH             ⏳\n"
            "[5/5] Starting services          ⏳\n"
            "```\n"
            "⏱ ~90 seconds — SSH sent to user's DM.",
            BLUE,
            [
                ("👤 User", user.mention, True),
                ("🖥 OS", os_label, True),
                ("🧠 RAM", f"{ram} MB ({ram//1024} GB)", True),
                ("💻 CPU", f"{cpu} Core(s)", True),
                ("💾 Disk", f"{disk} GB", True),
                ("⏰ Expiry", exp_note, False),
            ]
        ))
        
        try:
            container_id, ssh_backup, container_ip = await asyncio.get_event_loop().run_in_executor(
                None, lambda: provision(vps_id, image, os_label, ram, cpu, disk, host_port, root_pass)
            )
        except Exception as e:
            log.error(f"[{vps_id}] Failed: {e}")
            if lxc_exists(vps_id):
                lxc_delete(vps_id)
            return await ix.followup.send(embed=em(
                "❌ Provisioning Failed",
                f"**{vps_id}** could not be created.\n```{str(e)[:300]}```",
                RED
            ))
        
        with get_db() as c:
            c.execute("""
                INSERT INTO vps (vps_id, owner_id, container_id, os_image, os_label,
                    ram_mb, cpu_cores, disk_gb, ssh_port, root_pass, ssh_cmd, status, expires_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'running', ?)
            """, (vps_id, user.id, container_id, image, os_label,
                  ram, cpu, disk, host_port, root_pass, ssh_backup, exp_at))
        
        direct_ssh_cmd = f"ssh root@{SERVER_IP} -p {host_port}"
        
        dm_ok = False
        try:
            dm = await user.create_dm()
            await dm.send(embed=em(
                "⚡ Your VPS is Ready",
                f"**{vps_id}** has been deployed by an admin!\n\n"
                f"**🔑 MAIN SSH:**\n"
                f"```{direct_ssh_cmd}```\n"
                f"**Password:** ```{root_pass}```\n\n"
                f"**🔄 BACKUP SSH (tmate):**\n"
                f"```{ssh_backup}```\n\n"
                f"**Specs:**\n"
                f"• RAM: {ram} MB ({ram//1024} GB)\n"
                f"• CPU: {cpu} Core(s)\n"
                f"• Disk: {disk} GB\n"
                f"• OS: {os_label}\n"
                f"• Expiry: {exp_note}\n\n"
                f"⚠️ **Keep your password safe!**",
                GREEN
            ))
            dm_ok = True
        except:
            pass
        
        await ix.followup.send(embed=em(
            "✅ VPS Created Successfully",
            f"**{vps_id}** is live for {user.mention}\n"
            f"{'✅ SSH sent to user DM.' if dm_ok else '⚠️ Could not DM user.'}",
            GREEN,
            [
                ("🆔 VPS ID", vps_id, True),
                ("👤 User", str(user), True),
                ("🖥 OS", os_label, True),
                ("🧠 RAM", f"{ram} MB", True),
                ("💻 CPU", f"{cpu} Core(s)", True),
                ("💾 Disk", f"{disk} GB", True),
                ("📡 SSH Port", f"`{host_port}`", True),
                ("⏰ Expiry", exp_note, False),
            ]
        ))
        
    except Exception as e:
        log.error(f"admin-create error: {e}")
        try:
            await ix.followup.send(embed=em("❌ Error", str(e)[:200], RED))
        except:
            pass

@bot.tree.command(name="list-vps", description="[Admin] List all VPS")
async def cmd_list_vps(ix: discord.Interaction):
    try:
        await ix.response.defer(ephemeral=True)
        if not is_admin(ix):
            return await ix.followup.send(embed=em("⛔ Forbidden", "Admin only.", RED))
        
        with get_db() as c:
            vps_list = c.execute("SELECT * FROM vps ORDER BY created_at DESC").fetchall()
        
        if not vps_list:
            return await ix.followup.send(embed=em("📋 VPS List", "No VPS created yet.", BLUE))
        
        fields = []
        for v in vps_list:
            status_emoji = "🟢" if v["status"] == "running" else ("🔴" if v["status"] == "stopped" else "⛔")
            mining = "🚨" if v["mining_flag"] else "✅"
            ram_gb = v["ram_mb"] / 1024
            fields.append((f"{status_emoji} {v['vps_id']}", 
                          f"Owner: <@{v['owner_id']}>\n"
                          f"RAM: {ram_gb:.0f}GB | CPU: {v['cpu_cores']} | Disk: {v['disk_gb']}GB\n"
                          f"Status: {v['status']} {mining}", False))
        
        await ix.followup.send(embed=em(f"📋 VPS List ({len(vps_list)})", "", BLUE, fields[:25]))
    except Exception as e:
        log.error(f"list-vps error: {e}")
        try:
            await ix.followup.send(embed=em("❌ Error", str(e)[:200], RED))
        except:
            pass

@bot.tree.command(name="suspend-vps", description="[Admin] Suspend a VPS")
@app_commands.describe(vps_id="VPS ID to suspend")
async def cmd_suspend_vps(ix: discord.Interaction, vps_id: str):
    try:
        await ix.response.defer(ephemeral=True)
        if not is_admin(ix):
            return await ix.followup.send(embed=em("⛔ Forbidden", "Admin only.", RED))
        
        with get_db() as c:
            vps = c.execute("SELECT * FROM vps WHERE vps_id=?", (vps_id,)).fetchone()
            if not vps:
                return await ix.followup.send(embed=em("❌ Not Found", f"VPS **{vps_id}** not found.", RED))
            c.execute("UPDATE vps SET status='suspended' WHERE vps_id=?", (vps_id,))
        
        container_name = vps["container_id"] or vps_id
        if lxc_exists(container_name):
            lxc_stop(container_name)
        
        await ix.followup.send(embed=em("⛔ Suspended", f"**{vps_id}** suspended.", YELLOW))
    except Exception as e:
        log.error(f"suspend-vps error: {e}")
        try:
            await ix.followup.send(embed=em("❌ Error", str(e)[:200], RED))
        except:
            pass

@bot.tree.command(name="unsuspend-vps", description="[Admin] Unsuspend a VPS")
@app_commands.describe(vps_id="VPS ID to unsuspend")
async def cmd_unsuspend_vps(ix: discord.Interaction, vps_id: str):
    try:
        await ix.response.defer(ephemeral=True)
        if not is_admin(ix):
            return await ix.followup.send(embed=em("⛔ Forbidden", "Admin only.", RED))
        
        with get_db() as c:
            vps = c.execute("SELECT * FROM vps WHERE vps_id=?", (vps_id,)).fetchone()
            if not vps:
                return await ix.followup.send(embed=em("❌ Not Found", f"VPS **{vps_id}** not found.", RED))
            c.execute("UPDATE vps SET status='running', mining_flag=0 WHERE vps_id=?", (vps_id,))
        
        container_name = vps["container_id"] or vps_id
        if lxc_exists(container_name):
            lxc_start(container_name)
        
        await ix.followup.send(embed=em("✅ Unsuspended", f"**{vps_id}** unsuspended.", GREEN))
    except Exception as e:
        log.error(f"unsuspend-vps error: {e}")
        try:
            await ix.followup.send(embed=em("❌ Error", str(e)[:200], RED))
        except:
            pass

@bot.tree.command(name="remove-vps", description="[Admin] Delete a VPS")
@app_commands.describe(vps_id="VPS ID to delete")
async def cmd_remove_vps(ix: discord.Interaction, vps_id: str):
    try:
        await ix.response.defer(ephemeral=True)
        if not is_admin(ix):
            return await ix.followup.send(embed=em("⛔ Forbidden", "Admin only.", RED))
        
        with get_db() as c:
            vps = c.execute("SELECT * FROM vps WHERE vps_id=?", (vps_id,)).fetchone()
            if not vps:
                return await ix.followup.send(embed=em("❌ Not Found", f"VPS **{vps_id}** not found.", RED))
            c.execute("DELETE FROM vps WHERE vps_id=?", (vps_id,))
        
        container_name = vps["container_id"] or vps_id
        if lxc_exists(container_name):
            lxc_delete(container_name)
        
        await ix.followup.send(embed=em("🗑 Deleted", f"**{vps_id}** permanently deleted.", YELLOW))
    except Exception as e:
        log.error(f"remove-vps error: {e}")
        try:
            await ix.followup.send(embed=em("❌ Error", str(e)[:200], RED))
        except:
            pass

@bot.tree.command(name="container-status", description="[Admin] Check a container status")
@app_commands.describe(vps_id="VPS ID to check")
async def cmd_container_status(ix: discord.Interaction, vps_id: str):
    try:
        await ix.response.defer(ephemeral=True)
        if not is_admin(ix):
            return await ix.followup.send(embed=em("⛔ Forbidden", "Admin only.", RED))
        
        with get_db() as c:
            vps = c.execute("SELECT * FROM vps WHERE vps_id=?", (vps_id,)).fetchone()
            if not vps:
                return await ix.followup.send(embed=em("❌ Not Found", f"VPS **{vps_id}** not found.", RED))
        
        container_name = vps["container_id"] or vps_id
        exists = lxc_exists(container_name)
        running = lxc_is_running(container_name) if exists else False
        ip = lxc_get_ip(container_name) if running else ""
        ram_gb = vps["ram_mb"] / 1024
        
        await ix.followup.send(embed=em(
            "🖥️ Container Status",
            f"**VPS:** {vps_id}\n"
            f"**Container:** {container_name}\n"
            f"**Exists:** {'✅' if exists else '❌'}\n"
            f"**Running:** {'✅' if running else '❌'}\n"
            f"**IP:** {ip or 'N/A'}\n"
            f"**RAM:** {ram_gb:.0f} GB\n"
            f"**CPU:** {vps['cpu_cores']} Cores\n"
            f"**Disk:** {vps['disk_gb']} GB\n"
            f"**Status in DB:** {vps['status']}\n"
            f"**Mining Flag:** {'🚨' if vps['mining_flag'] else '✅'}",
            GREEN if running else RED
        ))
    except Exception as e:
        log.error(f"container-status error: {e}")
        try:
            await ix.followup.send(embed=em("❌ Error", str(e)[:200], RED))
        except:
            pass

@bot.tree.command(name="mining-logs", description="[Admin] View mining logs")
async def cmd_mining_logs(ix: discord.Interaction):
    try:
        await ix.response.defer(ephemeral=True)
        if not is_admin(ix):
            return await ix.followup.send(embed=em("⛔ Forbidden", "Admin only.", RED))
        
        with get_db() as c:
            logs = c.execute("SELECT * FROM mining_logs ORDER BY detected_at DESC LIMIT 20").fetchall()
        
        if not logs:
            return await ix.followup.send(embed=em("📋 Mining Logs", "No mining detections logged.", BLUE))
        
        fields = []
        for l in logs:
            status = "✅ Resolved" if l["resolved"] else "⚠️ Unresolved"
            fields.append((f"ID: {l['id']} - {l['vps_id']}", 
                          f"CPU: {l['cpu_usage']}%\nStatus: {status}", False))
        
        await ix.followup.send(embed=em(f"📋 Mining Logs ({len(logs)})", "", BLUE, fields[:10]))
    except Exception as e:
        log.error(f"mining-logs error: {e}")
        try:
            await ix.followup.send(embed=em("❌ Error", str(e)[:200], RED))
        except:
            pass

@bot.tree.command(name="resolve-mining", description="[Admin] Mark mining as resolved")
@app_commands.describe(log_id="Log ID to resolve")
async def cmd_resolve_mining(ix: discord.Interaction, log_id: int):
    try:
        await ix.response.defer(ephemeral=True)
        if not is_admin(ix):
            return await ix.followup.send(embed=em("⛔ Forbidden", "Admin only.", RED))
        
        with get_db() as c:
            row = c.execute("SELECT * FROM mining_logs WHERE id=?", (log_id,)).fetchone()
            if not row:
                return await ix.followup.send(embed=em("❌ Not Found", f"Log ID {log_id} not found.", RED))
            c.execute("UPDATE mining_logs SET resolved=1 WHERE id=?", (log_id,))
        
        await ix.followup.send(embed=em("✅ Resolved", f"Mining log {log_id} marked as resolved.", GREEN))
    except Exception as e:
        log.error(f"resolve-mining error: {e}")
        try:
            await ix.followup.send(embed=em("❌ Error", str(e)[:200], RED))
        except:
            pass

# ─────────────────────────────────────────────────────
# PREFIX COMMANDS (!) - FOR ALL USERS
# ─────────────────────────────────────────────────────
@bot.command(name="deploy")
async def cmd_deploy_prefix(ctx: commands.Context):
    """Deploy your own VPS (6 CPU, 32GB RAM, 80GB Disk) - FOR ALL USERS"""
    try:
        # Check if user already has VPS (1 VPS per user)
        if has_vps(ctx.author.id):
            await ctx.send(embed=em(
                "❌ Already Have VPS",
                "You already have a VPS. Only 1 VPS per user.",
                RED
            ))
            return
        
        # ✅ NO AUTHORIZATION CHECK - SAB KE LIYE ALLOWED
        
        vps_id = next_id()
        root_pass = gen_root_password()
        host_port = find_free_port()
        
        # SPECS: 6 CPU, 32GB RAM, 80GB Disk
        ram = 32768
        cpu = 6.0
        disk = 80
        os_key = "ubuntu22"
        image, os_label = LXC_IMAGES[os_key]
        
        await ctx.send(embed=em(
            "⏳ Deploying VPS...",
            f"**{vps_id}** for {ctx.author.mention}\n\n"
            "```\n"
            "[1/5] Creating LXC container      ⏳\n"
            "[2/5] Configuring network         ⏳\n"
            "[3/5] Installing packages         ⏳\n"
            "[4/5] Setting up SSH             ⏳\n"
            "[5/5] Starting services          ⏳\n"
            "```\n"
            "⏱ ~90 seconds — SSH sent to DM.",
            BLUE,
            [
                ("🖥 OS", os_label, True),
                ("🧠 RAM", "32 GB (32768 MB)", True),
                ("💻 CPU", "6 Core(s)", True),
                ("💾 Disk", "80 GB", True),
            ]
        ))
        
        try:
            container_id, ssh_backup, container_ip = await asyncio.get_event_loop().run_in_executor(
                None, lambda: provision(vps_id, image, os_label, ram, cpu, disk, host_port, root_pass)
            )
        except Exception as e:
            log.error(f"[{vps_id}] Failed: {e}")
            if lxc_exists(vps_id):
                lxc_delete(vps_id)
            await ctx.send(embed=em(
                "❌ Provisioning Failed",
                f"**{vps_id}** could not be created.\n```{str(e)[:300]}```",
                RED
            ))
            return
        
        with get_db() as c:
            c.execute("""
                INSERT INTO vps (vps_id, owner_id, container_id, os_image, os_label,
                    ram_mb, cpu_cores, disk_gb, ssh_port, root_pass, ssh_cmd, status)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'running')
            """, (vps_id, ctx.author.id, container_id, image, os_label,
                  ram, cpu, disk, host_port, root_pass, ssh_backup))
        
        direct_ssh_cmd = f"ssh root@{SERVER_IP} -p {host_port}"
        dm_ok = False
        
        try:
            dm = await ctx.author.create_dm()
            await dm.send(embed=em(
                "⚡ Your VPS is Ready",
                f"**{vps_id}** is ready!\n\n"
                f"**🔑 MAIN SSH:**\n"
                f"```{direct_ssh_cmd}```\n"
                f"**Password:** ```{root_pass}```\n\n"
                f"**🔄 BACKUP SSH (tmate):**\n"
                f"```{ssh_backup}```\n\n"
                f"**Specs:**\n"
                f"• RAM: 32 GB (32768 MB)\n"
                f"• CPU: 6 Cores\n"
                f"• Disk: 80 GB\n\n"
                f"⚠️ **Keep your password safe!**",
                GREEN
            ))
            dm_ok = True
        except:
            pass
        
        await ctx.send(embed=em(
            "✅ VPS Deployed Successfully",
            f"**{vps_id}** is live!\n"
            f"{'✅ SSH sent to DM.' if dm_ok else '⚠️ Could not DM you.'}",
            GREEN,
            [
                ("🆔 VPS ID", vps_id, True),
                ("🖥 OS", os_label, True),
                ("🧠 RAM", "32 GB", True),
                ("💻 CPU", "6 Core(s)", True),
                ("💾 Disk", "80 GB", True),
                ("📡 SSH Port", f"`{host_port}`", True),
            ]
        ))
    except Exception as e:
        log.error(f"deploy command error: {e}")
        await ctx.send(embed=em("❌ Error", f"Something went wrong: {str(e)[:200]}", RED))

# ─────────────────────────────────────────────────────
# COMMANDS LIST
# ─────────────────────────────────────────────────────
@bot.tree.command(name="commands", description="Show all commands")
async def cmd_commands(ix: discord.Interaction):
    try:
        await ix.response.defer(ephemeral=True)
        
        u = em("👤 User Commands", "VPS Management (Default: 32GB RAM, 6 CPU, 80GB Disk)", BLUE, [
            ("`!deploy`", "Deploy your VPS (6 CPU, 32GB RAM, 80GB Disk) - ALL USERS", False),
            ("`/my-vps`", "View your VPS info", False),
            ("`/start`", "Start your VPS", False),
            ("`/stop`", "Stop your VPS", False),
            ("`/restart`", "Restart your VPS", False),
            ("`/show-ssh`", "Show your SSH credentials", False),
            ("`/regen-ssh`", "Regenerate SSH password + tmate", False),
            ("`/delete-vps`", "Delete your VPS (all data lost)", False),
            ("`/commands`", "Show this help", False),
        ])
        
        a = em("🛡️ Admin Commands", "", RED, [
            ("`/admin-add-user <user>`", "Grant access", False),
            ("`/admin-remove-user <user>`", "Revoke access", False),
            ("`/admin-create <user> [ram] [cpu] [disk] [os] [days]`", "Create VPS for any user", False),
            ("`/list-vps`", "List all VPS", False),
            ("`/suspend-vps <id>`", "Suspend a VPS", False),
            ("`/unsuspend-vps <id>`", "Unsuspend a VPS", False),
            ("`/remove-vps <id>`", "Delete a VPS", False),
            ("`/container-status <id>`", "Check container status", False),
            ("`/mining-logs`", "View mining logs", False),
            ("`/resolve-mining <log_id>`", "Mark mining as resolved", False),
        ])
        
        r = em("📖 Default Specs", 
            f"**RAM:** 32 GB (32768 MB)\n"
            f"**CPU:** 6 Cores\n"
            f"**Disk:** 80 GB\n"
            f"**OS:** Ubuntu 22.04\n\n"
            f"⚠️ **1 VPS per user limit**",
            DARK)
        
        await ix.followup.send(embeds=[u, a, r])
    except Exception as e:
        log.error(f"commands command error: {e}")
        try:
            await ix.followup.send(embed=em("❌ Error", str(e)[:200], RED))
        except:
            pass

# ─────────────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────────────
if __name__ == "__main__":
    try:
        if not DISCORD_TOKEN:
            log.critical("❌ DISCORD_TOKEN not set in .env!")
            raise SystemExit(1)
        
        try:
            result = subprocess.run(["lxc", "version"], capture_output=True, check=True)
            log.info("✅ LXC is installed and ready.")
        except:
            log.critical("❌ LXC is not installed! Please install LXC first:")
            log.critical("  sudo apt-get install lxc lxc-templates")
            raise SystemExit(1)
        
        init_db()
        log.info("🚀 Starting DXD VPS Manager (32GB RAM, 6 CPU, 80GB Disk)...")
        bot.run(DISCORD_TOKEN, log_handler=None)
    except KeyboardInterrupt:
        log.info("Bot stopped by user")
    except Exception as e:
        log.critical(f"Fatal error: {e}")
        log.critical(traceback.format_exc())
        raise

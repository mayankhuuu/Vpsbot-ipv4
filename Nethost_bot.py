"""
╔═══════════════════════════════════════════════════════╗
║           NETHOST VPS Manager Bot                  ║
║  Server: 180GB RAM | 94 Core CPU | LXC Containers    ║
║  • LXC VPS containers with full systemd support      ║
║  • Full systemctl support                            ║
║  • Direct root SSH (IP:port + password)              ║
║  • tmate SSH as backup access                        ║
║  • Fake neofetch specs                               ║
║  • Pterodactyl Panel + Wings                         ║
║  • 1-click deploy (32GB RAM, 4 CPU, 80GB Disk)      ║
║  • 1 VPS limit per user                              ║
║  • Anti-mining protection                            ║
╚═══════════════════════════════════════════════════════╝
"""

import os, io, time, socket, random, string, secrets, uuid, tarfile, asyncio, logging, sqlite3, datetime, subprocess, tempfile
import discord, psutil, requests, aiohttp
from aiohttp import web
from discord import app_commands
from discord.ext import commands, tasks
from dotenv import load_dotenv

load_dotenv()

# ─────────────────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────────────────
DISCORD_TOKEN  = os.getenv("DISCORD_TOKEN", "")
ADMIN_ROLE_ID  = int(os.getenv("ADMIN_ROLE_ID", "0"))
ADMIN_USER_IDS = {
    int(x) for x in os.getenv("ADMIN_USER_IDS", "").split(",")
    if x.strip().isdigit()
}
PTERO_URL  = os.getenv("PTERO_URL", "").rstrip("/")
PTERO_KEY  = os.getenv("PTERO_API_KEY", "")
PTERO_ON   = bool(PTERO_URL and PTERO_KEY)

# Public IP of this host — shown to users as their "Shared IPv4".
SERVER_IP      = os.getenv("SERVER_IP", "127.0.0.1")
SSH_PORT_START = int(os.getenv("SSH_PORT_START", "20000"))
SSH_PORT_END   = int(os.getenv("SSH_PORT_END", "29999"))

# LXC Storage pool - defaults to "default" or create one
LXC_STORAGE_POOL = os.getenv("LXC_STORAGE_POOL", "default")
LXC_NETWORK_BRIDGE = os.getenv("LXC_NETWORK_BRIDGE", "lxcbr0")

# Port the built-in node-agent WebSocket server listens on.
AGENT_PORT = int(os.getenv("AGENT_PORT", "8788"))

# LXC image aliases (use Ubuntu/Debian cloud images)
LXC_IMAGES = {
    "ubuntu20": ("ubuntu:20.04", "Ubuntu 20.04"),
    "ubuntu22": ("ubuntu:22.04", "Ubuntu 22.04"),
    "ubuntu24": ("ubuntu:24.04", "Ubuntu 24.04"),
    "debian11": ("debian:11", "Debian 11"),
    "debian12": ("debian:12", "Debian 12"),
}

CPU_MAP = {
    "ryzen9": "AMD Ryzen 9 9950X 16-Core Processor",
    "xeon":   "Intel(R) Xeon(R) Platinum 8480+ @ 3.80GHz",
}

DB_FILE = "NETHOST.db"

# ─────────────────────────────────────────────────────
# ANTI-MINING CONFIG
# ─────────────────────────────────────────────────────
ANTI_MINING_ENABLED = os.getenv("ANTI_MINING_ENABLED", "true").lower() == "true"
ANTI_MINING_CHECK_INTERVAL = int(os.getenv("ANTI_MINING_CHECK_INTERVAL", "300"))  # 5 minutes
ANTI_MINING_CPU_THRESHOLD = float(os.getenv("ANTI_MINING_CPU_THRESHOLD", "80.0"))  # 80% CPU usage
ANTI_MINING_MEMORY_THRESHOLD = float(os.getenv("ANTI_MINING_MEMORY_THRESHOLD", "90.0"))  # 90% memory usage
ANTI_MINING_SUSPEND_ON_DETECT = os.getenv("ANTI_MINING_SUSPEND_ON_DETECT", "true").lower() == "true"
ANTI_MINING_NOTIFY_ADMIN = os.getenv("ANTI_MINING_NOTIFY_ADMIN", "true").lower() == "true"

# Common mining process names to detect
MINING_PROCESSES = [
    "xmrig", "minerd", "cpuminer", "miner", "ccminer", "cgminer",
    "bfgminer", "sgminer", "claymore", "ethminer", "t-rex", "phoenixminer",
    "nbminer", "gminer", "lolminer", "teamredminer", "teamred",
    "nanominer", "wildrig", "bminer", "z-enemy", "ewbf",
    "cryptonight", "stratum", "mining", "kawpow", "etchash",
    "randomx", "monero", "xmr", "bitcoin", "btc", "ethereum", "eth",
    "nicehash", "hiveos", "simplemining", "awesome-miner",
    "dwarfpool", "nanopool", "minergate", "hashflare", "genesis-mining",
]

# Suspicious ports commonly used by mining pools
MINING_PORTS = [4444, 5555, 7777, 14444, 14433, 14434, 14435, 14436, 14437, 14438, 14439]

# Mining pool domains to check in processes and connections
MINING_POOL_DOMAINS = [
    "stratum", "pool", "mine", "mining", "cryptonight", "xmr",
    "supportxmr", "minexmr", "nanopool", "dwarfpool", "ethermine",
    "sparkpool", "f2pool", "antpool", "btc.com", "viabtc",
]

# ─────────────────────────────────────────────────────
# LOGGING
# ─────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("NETHOST.log"),
        logging.StreamHandler(),
    ],
)
log = logging.getLogger("NETHOST")

# ─────────────────────────────────────────────────────
# COLORS
# ─────────────────────────────────────────────────────
BLUE   = 0x5865F2
GREEN  = 0x57F287
RED    = 0xED4245
YELLOW = 0xFEE75C
DARK   = 0x2F3136
FOOTER = "Powered by NETHOST"

# ─────────────────────────────────────────────────────
# DATABASE
# ─────────────────────────────────────────────────────
def get_db():
    c = sqlite3.connect(DB_FILE)
    c.row_factory = sqlite3.Row
    return c

def init_db():
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
                cpu_name     TEXT,
                ssh_cmd      TEXT    DEFAULT '',
                ssh_ip       TEXT    DEFAULT '',
                ssh_port     INTEGER DEFAULT NULL,
                root_pass    TEXT    DEFAULT '',
                username     TEXT    DEFAULT 'root',
                ptero_id     INTEGER DEFAULT NULL,
                status       TEXT    DEFAULT 'running',
                expires_at   TEXT    DEFAULT NULL,
                node_id      TEXT    DEFAULT NULL,
                mining_flag  INTEGER DEFAULT 0,
                created_at   TEXT    DEFAULT (datetime('now'))
            );
            CREATE TABLE IF NOT EXISTS nodes (
                node_id      TEXT    PRIMARY KEY,
                token        TEXT    NOT NULL,
                public_ip    TEXT    DEFAULT '',
                status       TEXT    DEFAULT 'offline',
                last_seen    TEXT    DEFAULT NULL,
                created_by   INTEGER,
                created_at   TEXT    DEFAULT (datetime('now'))
            );
            CREATE TABLE IF NOT EXISTS redeem_codes (
                code         TEXT    PRIMARY KEY,
                ram_mb       INTEGER NOT NULL,
                cpu_cores    REAL    NOT NULL,
                disk_gb      INTEGER NOT NULL,
                valid_days   INTEGER DEFAULT 0,
                created_by   INTEGER,
                created_at   TEXT    DEFAULT (datetime('now'))
            );
            CREATE TABLE IF NOT EXISTS mining_logs (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                vps_id       TEXT    NOT NULL,
                container_id TEXT,
                detected_at  TEXT    DEFAULT (datetime('now')),
                cpu_usage    REAL,
                mem_usage    REAL,
                reasons      TEXT,
                action_taken TEXT,
                resolved     INTEGER DEFAULT 0
            );
        """)
        cols = {row["name"] for row in c.execute("PRAGMA table_info(vps)").fetchall()}
        for col, ddl in [
            ("ssh_ip",    "ALTER TABLE vps ADD COLUMN ssh_ip TEXT DEFAULT ''"),
            ("ssh_port",  "ALTER TABLE vps ADD COLUMN ssh_port INTEGER DEFAULT NULL"),
            ("root_pass", "ALTER TABLE vps ADD COLUMN root_pass TEXT DEFAULT ''"),
            ("username",  "ALTER TABLE vps ADD COLUMN username TEXT DEFAULT 'root'"),
            ("node_id",   "ALTER TABLE vps ADD COLUMN node_id TEXT DEFAULT NULL"),
            ("mining_flag", "ALTER TABLE vps ADD COLUMN mining_flag INTEGER DEFAULT 0"),
        ]:
            if col not in cols:
                c.execute(ddl)
    log.info("Database ready.")

# ─────────────────────────────────────────────────────
# LXC HELPERS
# ─────────────────────────────────────────────────────
def lxc_command(args: list, check: bool = True) -> subprocess.CompletedProcess:
    """Run an LXC command and return the result."""
    cmd = ["lxc"] + args
    log.debug(f"Running: {' '.join(cmd)}")
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=check)
        return result
    except subprocess.CalledProcessError as e:
        log.error(f"LXC command failed: {' '.join(cmd)}")
        log.error(f"STDERR: {e.stderr}")
        raise RuntimeError(f"LXC command failed: {e.stderr}") from e

def lxc_exists(name: str) -> bool:
    """Check if an LXC container exists."""
    try:
        lxc_command(["info", name], check=False)
        return True
    except:
        return False

def lxc_is_running(name: str) -> bool:
    """Check if an LXC container is running."""
    result = lxc_command(["list", "--format", "csv"], check=False)
    for line in result.stdout.strip().split("\n"):
        if line and line.startswith(name + ","):
            parts = line.split(",")
            return len(parts) > 1 and parts[1].strip() == "RUNNING"
    return False

def lxc_get_ip(name: str) -> str:
    """Get the IP address of an LXC container."""
    result = lxc_command(["info", name])
    for line in result.stdout.split("\n"):
        if "inet" in line and "inet6" not in line:
            parts = line.strip().split()
            if len(parts) > 2:
                ip = parts[1].split("/")[0]
                if ip and ip != "127.0.0.1" and not ip.startswith("169.254"):
                    return ip
    return ""

def lxc_stop(name: str):
    """Stop an LXC container."""
    try:
        lxc_command(["stop", name, "--force"], check=False)
    except:
        pass

def lxc_start(name: str):
    """Start an LXC container."""
    lxc_command(["start", name])

def lxc_restart(name: str):
    """Restart an LXC container."""
    lxc_command(["restart", name, "--force"])

def lxc_delete(name: str):
    """Delete an LXC container."""
    try:
        lxc_stop(name)
        time.sleep(1)
        lxc_command(["delete", name, "--force"], check=False)
    except:
        pass

def lxc_exec(name: str, command: str, check: bool = True) -> str:
    """Execute a command inside an LXC container."""
    result = lxc_command(["exec", name, "--", "bash", "-c", command], check=check)
    return result.stdout

def lxc_file_push(name: str, content: str, dest_path: str):
    """Push a file to an LXC container."""
    with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
        f.write(content)
        temp_file = f.name
    try:
        lxc_command(["file", "push", temp_file, f"{name}{dest_path}"])
    finally:
        os.unlink(temp_file)

def lxc_wait_for_network(name: str, timeout: int = 120) -> bool:
    """Wait for the container to get a network IP."""
    start = time.time()
    while time.time() - start < timeout:
        ip = lxc_get_ip(name)
        if ip:
            return True
        time.sleep(2)
    return False

def lxc_wait_for_ssh(name: str, timeout: int = 180) -> bool:
    """Wait for SSH to be ready inside the container."""
    start = time.time()
    while time.time() - start < timeout:
        try:
            result = lxc_command(["exec", name, "--", "bash", "-c", 
                                 "ss -tln | grep ':22 ' || netstat -tln | grep ':22 '"],
                                 check=False)
            if "LISTEN" in result.stdout:
                return True
        except:
            pass
        time.sleep(3)
    return False

# ─────────────────────────────────────────────────────
# ANTI-MINING FUNCTIONS
# ─────────────────────────────────────────────────────
def detect_mining_activity(container_name: str) -> dict:
    """
    Detect cryptocurrency mining activity inside an LXC container.
    Returns a dict with detection results.
    """
    results = {
        "detected": False,
        "reasons": [],
        "suspicious_processes": [],
        "suspicious_connections": [],
        "cpu_usage": 0,
        "mem_usage": 0,
        "mining_processes_found": [],
    }
    
    try:
        # Check CPU usage
        stats = get_stats(container_name)
        results["cpu_usage"] = stats.get("cpu", 0)
        results["mem_usage"] = stats.get("mem_p", 0)
        
        # Check for suspicious processes
        process_result = lxc_exec(container_name, 
            "ps aux | grep -v 'grep' | awk '{print $11}'", 
            check=False)
        
        if process_result:
            processes = [p.strip() for p in process_result.split('\n') if p.strip()]
            for proc in processes:
                proc_lower = proc.lower()
                for mining_proc in MINING_PROCESSES:
                    if mining_proc in proc_lower:
                        results["mining_processes_found"].append(proc)
                        results["detected"] = True
                        results["reasons"].append(f"Suspicious process: {proc}")
                        break
                
                # Check for process arguments that might indicate mining
                args_result = lxc_exec(container_name, 
                    f"ps aux | grep -v 'grep' | grep '{proc}' | head -1", 
                    check=False)
                if args_result:
                    args_lower = args_result.lower()
                    for domain in MINING_POOL_DOMAINS:
                        if domain in args_lower:
                            results["detected"] = True
                            results["reasons"].append(f"Process {proc} connected to mining pool domain: {domain}")
                            break
        
        # Check network connections for mining pools
        net_result = lxc_exec(container_name, 
            "ss -tunp | grep -v 'grep' | grep ESTAB", 
            check=False)
        
        if net_result:
            connections = net_result.split('\n')
            for conn in connections:
                if not conn.strip():
                    continue
                
                for port in MINING_PORTS:
                    if f":{port}" in conn:
                        results["suspicious_connections"].append(conn)
                        results["detected"] = True
                        results["reasons"].append(f"Suspicious connection on port {port}")
                        break
                
                conn_lower = conn.lower()
                for domain in MINING_POOL_DOMAINS:
                    if domain in conn_lower:
                        results["suspicious_connections"].append(conn)
                        results["detected"] = True
                        results["reasons"].append(f"Connection to mining pool: {domain}")
                        break
        
        # Check for mining config files
        mining_configs = [
            "/config.json", "/config.txt", "/miner.conf", 
            "/xmrig.json", "/miner.json", "/pool.conf"
        ]
        for config in mining_configs:
            try:
                result = lxc_exec(container_name, f"test -f {config} && echo 'exists'", check=False)
                if result and "exists" in result:
                    results["detected"] = True
                    results["reasons"].append(f"Mining config file found: {config}")
                    break
            except:
                pass
        
        # Check for known mining software directories
        mining_dirs = [
            "/xmrig", "/miner", "/cpuminer", "/ccminer", 
            "/usr/local/bin/xmrig", "/opt/miner"
        ]
        for mining_dir in mining_dirs:
            try:
                result = lxc_exec(container_name, f"test -d {mining_dir} && echo 'exists'", check=False)
                if result and "exists" in result:
                    results["detected"] = True
                    results["reasons"].append(f"Mining directory found: {mining_dir}")
                    break
            except:
                pass
        
        # Check if CPU usage is abnormally high
        if results["cpu_usage"] > ANTI_MINING_CPU_THRESHOLD:
            results["detected"] = True
            results["reasons"].append(f"CPU usage at {results['cpu_usage']}% (threshold: {ANTI_MINING_CPU_THRESHOLD}%)")
        
        # Check if memory usage is abnormally high
        if results["mem_usage"] > ANTI_MINING_MEMORY_THRESHOLD:
            results["detected"] = True
            results["reasons"].append(f"Memory usage at {results['mem_usage']}% (threshold: {ANTI_MINING_MEMORY_THRESHOLD}%)")
        
        return results
        
    except Exception as e:
        log.error(f"Error detecting mining in {container_name}: {e}")
        return results

def handle_mining_detection(vps_id: str, container_name: str, detection_results: dict) -> str:
    """
    Handle the detection of mining activity.
    Returns the action taken as a string.
    """
    action_taken = []
    
    log.warning(f"[{vps_id}] Mining activity detected! Reasons: {detection_results['reasons']}")
    
    # Log to database
    with get_db() as c:
        c.execute("""
            INSERT INTO mining_logs (vps_id, container_id, cpu_usage, mem_usage, reasons, action_taken)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            vps_id, 
            container_name, 
            detection_results.get("cpu_usage", 0),
            detection_results.get("mem_usage", 0),
            "\n".join(detection_results.get("reasons", [])),
            "Suspended" if ANTI_MINING_SUSPEND_ON_DETECT else "Warning"
        ))
        
        # Update mining flag
        c.execute("UPDATE vps SET mining_flag=1 WHERE vps_id=?", (vps_id,))
    
    # Suspend the container if configured
    if ANTI_MINING_SUSPEND_ON_DETECT:
        try:
            if lxc_exists(container_name):
                lxc_stop(container_name)
                action_taken.append("Container suspended")
                
                with get_db() as c:
                    c.execute("UPDATE vps SET status='suspended' WHERE vps_id=?", (vps_id,))
                action_taken.append("Status updated in database")
                
                log.info(f"[{vps_id}] Container suspended due to mining detection")
        except Exception as e:
            log.error(f"[{vps_id}] Failed to suspend container: {e}")
            action_taken.append(f"Failed to suspend: {str(e)[:50]}")
    
    # Notify admins
    if ANTI_MINING_NOTIFY_ADMIN:
        try:
            with get_db() as c:
                row = c.execute("SELECT owner_id FROM vps WHERE vps_id=?", (vps_id,)).fetchone()
            
            reason_summary = "\n".join([f"• {r}" for r in detection_results['reasons'][:5]])
            if len(detection_results['reasons']) > 5:
                reason_summary += f"\n• ... and {len(detection_results['reasons']) - 5} more"
            
            cpu_usage = detection_results.get("cpu_usage", 0)
            mem_usage = detection_results.get("mem_usage", 0)
            suspicious_procs = detection_results.get("mining_processes_found", [])
            procs_str = "\n".join([f"• {p}" for p in suspicious_procs[:3]])
            if len(suspicious_procs) > 3:
                procs_str += f"\n• ... and {len(suspicious_procs) - 3} more"
            
            for admin_id in ADMIN_USER_IDS:
                try:
                    admin = bot.get_user(admin_id)
                    if admin:
                        embed = em(
                            "🚨 Mining Activity Detected!",
                            f"**VPS:** {vps_id}\n"
                            f"**CPU Usage:** {cpu_usage}%\n"
                            f"**Memory Usage:** {mem_usage}%\n"
                            f"**Action Taken:** {', '.join(action_taken) if action_taken else 'No action'}\n\n"
                            f"**Reasons:**\n{reason_summary}\n\n"
                            f"**Suspicious Processes:**\n{procs_str if procs_str else 'None detected'}",
                            RED,
                            fields=[
                                ("Owner", f"<@{row['owner_id']}>", True),
                                ("Container", container_name, True),
                                ("Status", "Suspended" if ANTI_MINING_SUSPEND_ON_DETECT else "Warning", True),
                            ]
                        )
                        await admin.send(embed=embed)
                except Exception as e:
                    log.warning(f"Could not notify admin {admin_id}: {e}")
            
            # Notify the owner
            try:
                user = await bot.fetch_user(row["owner_id"])
                embed = em(
                    "🚨 Mining Activity Detected on Your VPS",
                    f"Your VPS **{vps_id}** has been detected running cryptocurrency mining software.\n\n"
                    f"This is a violation of our Terms of Service.\n"
                    f"Your VPS has been **suspended**.\n\n"
                    f"**Detected Activity:**\n{reason_summary}\n\n"
                    f"If you believe this is a false positive, please contact an administrator.",
                    RED
                )
                await user.send(embed=embed)
            except Exception as e:
                log.warning(f"Could not notify owner of {vps_id}: {e}")
                
        except Exception as e:
            log.error(f"Failed to send mining notifications: {e}")
            action_taken.append(f"Notification failed: {str(e)[:50]}")
    
    return ", ".join(action_taken) if action_taken else "No action taken"

# ─────────────────────────────────────────────────────
# PORT + PASSWORD HELPERS
# ─────────────────────────────────────────────────────
def _port_in_use_locally(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.3)
        return s.connect_ex(("127.0.0.1", port)) == 0

def find_free_port() -> int:
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

def gen_root_password(length: int = 16) -> str:
    alphabet = string.ascii_letters + string.digits
    return "".join(random.SystemRandom().choice(alphabet) for _ in range(length))

def find_free_port_for_node(node_id: str) -> int:
    with get_db() as c:
        used = {row["ssh_port"] for row in c.execute(
            "SELECT ssh_port FROM vps WHERE node_id=? AND ssh_port IS NOT NULL", (node_id,)
        ).fetchall()}
    for _ in range(200):
        p = random.randint(SSH_PORT_START, SSH_PORT_END)
        if p not in used:
            return p
    raise RuntimeError("No free SSH ports available in range for this node.")

def gen_redeem_code() -> str:
    part = lambda: "".join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(4))
    return f"SN-{part()}-{part()}-{part()}"

# ─────────────────────────────────────────────────────
# EMBED HELPER
# ─────────────────────────────────────────────────────
def em(title, desc="", color=BLUE, fields=None):
    e = discord.Embed(
        title=title, description=desc,
        color=color, timestamp=datetime.datetime.utcnow()
    )
    e.set_footer(text=FOOTER)
    for n, v, i in (fields or []):
        e.add_field(name=n, value=v, inline=i)
    return e

# ─────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────
def is_admin(ix: discord.Interaction) -> bool:
    if ix.user.id in ADMIN_USER_IDS:
        return True
    if ix.guild:
        return any(r.id == ADMIN_ROLE_ID for r in ix.user.roles)
    return False

def owns(uid: int, vid: str) -> bool:
    with get_db() as c:
        return bool(c.execute(
            "SELECT 1 FROM vps WHERE vps_id=? AND owner_id=?", (vid, uid)
        ).fetchone())

# ─────────────────────────────────────────────────────
# NODE MANAGER — WebSocket RPC to remote node agents
# ─────────────────────────────────────────────────────
NODE_CONNECTIONS: dict[str, web.WebSocketResponse] = {}
PENDING_JOBS: dict[str, "asyncio.Future"] = {}

def node_is_online(node_id: str) -> bool:
    return node_id in NODE_CONNECTIONS

async def send_job_to_node(node_id: str, job: dict, timeout: int = 180) -> dict:
    ws = NODE_CONNECTIONS.get(node_id)
    if ws is None:
        raise RuntimeError(f"Node '{node_id}' is offline.")
    job_id = str(uuid.uuid4())
    job["job_id"] = job_id
    fut = asyncio.get_event_loop().create_future()
    PENDING_JOBS[job_id] = fut
    try:
        await ws.send_json(job)
        return await asyncio.wait_for(fut, timeout=timeout)
    finally:
        PENDING_JOBS.pop(job_id, None)

async def ws_agent_handler(request: web.Request) -> web.WebSocketResponse:
    ws = web.WebSocketResponse(heartbeat=30)
    await ws.prepare(request)
    node_id = None
    try:
        async for msg in ws:
            if msg.type != aiohttp.WSMsgType.TEXT:
                continue
            data = msg.json()
            mtype = data.get("type")

            if mtype == "hello":
                nid, token = data.get("node_id"), data.get("token")
                with get_db() as c:
                    row = c.execute(
                        "SELECT * FROM nodes WHERE node_id=?", (nid,)
                    ).fetchone()
                if not row or row["token"] != token:
                    await ws.send_json({"type": "hello_ack", "ok": False, "error": "Invalid node_id/token."})
                    await ws.close()
                    return ws
                node_id = nid
                peer_ip = request.remote or ""
                with get_db() as c:
                    c.execute(
                        "UPDATE nodes SET status='online', public_ip=?, last_seen=datetime('now') WHERE node_id=?",
                        (peer_ip, node_id),
                    )
                NODE_CONNECTIONS[node_id] = ws
                log.info(f"[node:{node_id}] connected from {peer_ip}")
                await ws.send_json({"type": "hello_ack", "ok": True})

            elif mtype == "job_result":
                fut = PENDING_JOBS.get(data.get("job_id"))
                if fut and not fut.done():
                    fut.set_result(data)

            elif mtype == "heartbeat" and node_id:
                with get_db() as c:
                    c.execute("UPDATE nodes SET last_seen=datetime('now') WHERE node_id=?", (node_id,))
    finally:
        if node_id:
            NODE_CONNECTIONS.pop(node_id, None)
            with get_db() as c:
                c.execute("UPDATE nodes SET status='offline' WHERE node_id=?", (node_id,))
            log.info(f"[node:{node_id}] disconnected")
    return ws

async def start_agent_server():
    app = web.Application()
    app.router.add_get("/agent/ws", ws_agent_handler)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "0.0.0.0", AGENT_PORT, reuse_address=True)
    try:
        await site.start()
        log.info(f"Node-agent WebSocket server listening on 0.0.0.0:{AGENT_PORT}")
    except OSError as e:
        if e.errno == 98:
            log.error(
                f"❌ Port {AGENT_PORT} is already in use — the node-agent server "
                f"did NOT start (Discord bot will still run normally otherwise).\n"
                f"   This usually means an old copy of this bot is still running. Fix with:\n"
                f"     sudo lsof -i :{AGENT_PORT}      # find the PID using this port\n"
                f"     sudo kill -9 <PID>              # stop it\n"
                f"   Or set a different AGENT_PORT in your .env and restart."
            )
        else:
            log.error(f"❌ Node-agent server failed to start: {e}")

def next_id() -> str:
    with get_db() as c:
        row = c.execute("SELECT vps_id FROM vps ORDER BY vps_id DESC LIMIT 1").fetchone()
    db_num = 1 if not row else int(row["vps_id"].split("-")[-1]) + 1
    lxc_max = 0
    try:
        result = lxc_command(["list", "--format", "csv"], check=False)
        for line in result.stdout.split("\n"):
            if line and "NETHOST-vps-" in line:
                try:
                    parts = line.split(",")
                    name = parts[0]
                    num = int(name.split("-")[-1])
                    lxc_max = max(lxc_max, num)
                except:
                    pass
    except:
        pass
    return f"NETHOST-vps-{max(db_num, lxc_max + 1):04d}"

def gb(b): return round(b / 1024**3, 2)

# ─────────────────────────────────────────────────────
# PTERODACTYL
# ─────────────────────────────────────────────────────
def ph():
    return {
        "Authorization": f"Bearer {PTERO_KEY}",
        "Accept": "application/json",
        "Content-Type": "application/json",
    }

def ptero_get(ep):
    r = requests.get(f"{PTERO_URL}/api/application/{ep}", headers=ph(), timeout=10)
    r.raise_for_status()
    return r.json()

def ptero_post(ep, data=None):
    r = requests.post(f"{PTERO_URL}/api/application/{ep}", headers=ph(), json=data or {}, timeout=10)
    r.raise_for_status()
    return r.json() if r.text.strip() else {}

def ptero_delete(ep):
    requests.delete(f"{PTERO_URL}/api/application/{ep}", headers=ph(), timeout=10).raise_for_status()

def ptero_check():
    try:
        n = ptero_get("nodes")
        return {"ok": True, "nodes": len(n.get("data", []))}
    except Exception as e:
        return {"ok": False, "error": str(e)}

def ptero_suspend(pid):   ptero_post(f"servers/{pid}/suspend")
def ptero_unsuspend(pid): ptero_post(f"servers/{pid}/unsuspend")
def ptero_remove(pid):    ptero_delete(f"servers/{pid}/force")

# ─────────────────────────────────────────────────────
# FAKE /proc GENERATORS
# ─────────────────────────────────────────────────────
def fake_meminfo(mb: int) -> str:
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

def fake_cpuinfo(cores: float, name: str) -> str:
    n = max(1, int(cores))
    v = "AuthenticAMD" if ("AMD" in name or "Ryzen" in name) else "GenuineIntel"
    blocks = []
    for i in range(n):
        blocks.append("\n".join([
            f"processor\t: {i}",
            f"vendor_id\t: {v}",
            "cpu family\t: 25",
            "model\t\t: 97",
            f"model name\t: {name}",
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
# CORE VPS PROVISION (LXC)
# ─────────────────────────────────────────────────────
def provision(vps_id, image, os_label, ram_mb, cpu_cores, disk_gb, cpu_name,
              host_port, root_pass) -> tuple:
    log.info(f"[{vps_id}] Provisioning LXC — RAM:{ram_mb}MB CPU:{cpu_cores} Disk:{disk_gb}GB")

    if lxc_exists(vps_id):
        log.warning(f"[{vps_id}] Removing leftover container")
        lxc_delete(vps_id)
        time.sleep(2)

    log.info(f"[{vps_id}] Creating LXC container from {image}...")
    
    create_args = [
        "init", image, vps_id,
        "--storage", LXC_STORAGE_POOL,
        f"--storage-size={disk_gb}GB",
        f"--memory={ram_mb}MB",
        f"--cpu-cores={int(cpu_cores)}",
        f"--network={LXC_NETWORK_BRIDGE}",
        "-d"
    ]
    
    if ram_mb > 512:
        create_args.append(f"--swap={int(ram_mb * 0.5)}MB")
    
    try:
        lxc_command(create_args)
    except Exception as e:
        log.warning(f"[{vps_id}] Storage size param may not be supported, retrying...")
        create_args.remove(f"--storage-size={disk_gb}GB")
        lxc_command(create_args)
        lxc_command(["config", "set", vps_id, "limits.disk.size", f"{disk_gb}GB"])
    
    log.info(f"[{vps_id}] Configuring container...")
    lxc_command(["config", "set", vps_id, "limits.cpu", str(int(cpu_cores))])
    lxc_command(["config", "set", vps_id, "security.nesting", "true"])
    lxc_command(["config", "set", vps_id, "security.privileged", "true"])
    
    log.info(f"[{vps_id}] Starting container...")
    lxc_start(vps_id)
    
    if not lxc_wait_for_network(vps_id, timeout=60):
        log.warning(f"[{vps_id}] Container started but no network IP found")
    
    time.sleep(5)
    
    container_ip = lxc_get_ip(vps_id)
    log.info(f"[{vps_id}] Container IP: {container_ip}")
    
    log.info(f"[{vps_id}] Running apt update...")
    lxc_exec(vps_id, "apt-get update -qq", check=False)
    
    log.info(f"[{vps_id}] Installing packages...")
    lxc_exec(vps_id, 
        "DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "
        "openssh-server tmate neofetch curl wget sudo procps net-tools "
        "iproute2 htop systemd systemd-sysv", check=False)
    
    log.info(f"[{vps_id}] Setting up fake /proc files...")
    lxc_exec(vps_id, "mkdir -p /etc/NETHOST", check=False)
    lxc_file_push(vps_id, fake_meminfo(ram_mb), "/etc/NETHOST/meminfo")
    lxc_file_push(vps_id, fake_cpuinfo(cpu_cores, cpu_name), "/etc/NETHOST/cpuinfo")
    
    mount_script = """#!/bin/bash
mount --bind /etc/NETHOST/meminfo /proc/meminfo 2>/dev/null
mount --bind /etc/NETHOST/cpuinfo /proc/cpuinfo 2>/dev/null
exit 0
"""
    lxc_file_push(vps_id, mount_script, "/etc/rc.local")
    lxc_exec(vps_id, "chmod +x /etc/rc.local", check=False)
    lxc_exec(vps_id, 
        "mount --bind /etc/NETHOST/meminfo /proc/meminfo 2>/dev/null; "
        "mount --bind /etc/NETHOST/cpuinfo /proc/cpuinfo 2>/dev/null", 
        check=False)
    
    ci = int(cpu_cores) if cpu_cores == int(cpu_cores) else cpu_cores
    lxc_exec(vps_id, f"hostnamectl set-hostname {vps_id} 2>/dev/null || hostname {vps_id}", check=False)
    lxc_exec(vps_id, f"echo {vps_id} > /etc/hostname", check=False)
    
    motd = f"""
  ╔══════════════════════════════════╗
  ║        🐉  NETHOST VPS           ║
  ╠══════════════════════════════════╣
  ║  VPS ID : {vps_id:<24}║
  ║  RAM    : {str(ram_mb)+' MB':<24}║
  ║  CPU    : {str(ci)+' vCore(s)':<24}║
  ║  Disk   : {str(disk_gb)+' GB':<24}║
  ║  OS     : {os_label:<24}║
  ╚══════════════════════════════════╝
"""
    lxc_file_push(vps_id, motd, "/etc/motd")
    
    log.info(f"[{vps_id}] Setting root password and enabling SSH...")
    lxc_exec(vps_id, f"echo 'root:{root_pass}' | chpasswd", check=False)
    lxc_exec(vps_id, "mkdir -p /run/sshd", check=False)
    
    ssh_config = """
sed -i 's/^#\\?PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config
sed -i 's/^#\\?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config
grep -q '^PermitRootLogin' /etc/ssh/sshd_config || echo 'PermitRootLogin yes' >> /etc/ssh/sshd_config
grep -q '^PasswordAuthentication' /etc/ssh/sshd_config || echo 'PasswordAuthentication yes' >> /etc/ssh/sshd_config
"""
    lxc_exec(vps_id, ssh_config, check=False)
    lxc_exec(vps_id, 
        "systemctl enable ssh 2>/dev/null; "
        "systemctl restart ssh 2>/dev/null || "
        "systemctl restart sshd 2>/dev/null || "
        "service ssh restart", 
        check=False)
    
    lxc_wait_for_ssh(vps_id, timeout=60)
    
    log.info(f"[{vps_id}] Setting up port forwarding: {host_port} -> {container_ip}:22")
    try:
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
        
        try:
            subprocess.run(["iptables-save"], capture_output=True)
            for save_cmd in ["iptables-persistent save", "netfilter-persistent save", "service iptables save"]:
                try:
                    subprocess.run(save_cmd.split(), capture_output=True)
                except:
                    pass
        except:
            pass
    except Exception as e:
        log.warning(f"[{vps_id}] Port forwarding setup failed: {e}")
        log.warning("You may need to run this bot as root or with sudo for iptables.")
    
    log.info(f"[{vps_id}] Starting tmate SSH session...")
    sock = "/tmp/tmate.sock"
    lxc_exec(vps_id, f"rm -f {sock}; tmate -S {sock} new-session -d", check=False)
    time.sleep(5)
    lxc_exec(vps_id, f"tmate -S {sock} wait tmate-ready", check=False)
    result = lxc_exec(vps_id, f"tmate -S {sock} display -p '#{{tmate_ssh}}'", check=False)
    ssh = result.strip() if result else ""
    log.info(f"[{vps_id}] tmate SSH ready: {ssh}")
    
    lxc_command(["config", "set", vps_id, "user.vps-id", vps_id])
    lxc_command(["config", "set", vps_id, "user.managed-by", "NETHOST"])
    
    return vps_id, ssh, container_ip

def regen_ssh(name: str) -> str:
    sock = "/tmp/tmate.sock"
    lxc_exec(name, "pkill tmate; rm -f /tmp/tmate.sock", check=False)
    time.sleep(2)
    lxc_exec(name, f"tmate -S {sock} new-session -d", check=False)
    time.sleep(5)
    lxc_exec(name, f"tmate -S {sock} wait tmate-ready", check=False)
    result = lxc_exec(name, f"tmate -S {sock} display -p '#{{tmate_ssh}}'", check=False)
    return result.strip() if result else ""

def get_stats(name: str, ram_mb=0, cores=0) -> dict:
    try:
        result = lxc_command(["info", name])
        output = result.stdout
        
        stats = {
            "cpu": 0,
            "mem_mb": 0,
            "mem_p": 0,
            "rx": 0,
            "tx": 0,
            "up": "N/A"
        }
        
        for line in output.split("\n"):
            if "CPU usage:" in line:
                try:
                    cpu_str = line.split(":")[1].strip().replace("%", "")
                    stats["cpu"] = round(float(cpu_str), 2)
                except:
                    pass
            
            if "Memory usage:" in line:
                try:
                    mem_str = line.split(":")[1].strip()
                    if "MiB" in mem_str:
                        mem_val = float(mem_str.replace("MiB", "").strip())
                        stats["mem_mb"] = round(mem_val, 1)
                        if ram_mb > 0:
                            stats["mem_p"] = round((mem_val / ram_mb) * 100, 2)
                except:
                    pass
        
        try:
            rx = lxc_exec(name, "cat /sys/class/net/eth0/statistics/rx_bytes 2>/dev/null || echo 0", check=False)
            tx = lxc_exec(name, "cat /sys/class/net/eth0/statistics/tx_bytes 2>/dev/null || echo 0", check=False)
            if rx:
                stats["rx"] = round(float(rx.strip()) / 1024 / 1024, 2)
            if tx:
                stats["tx"] = round(float(tx.strip()) / 1024 / 1024, 2)
        except:
            pass
        
        try:
            uptime = lxc_exec(name, "cat /proc/uptime | cut -d' ' -f1", check=False)
            if uptime:
                seconds = float(uptime.strip())
                hours, remainder = divmod(int(seconds), 3600)
                minutes, secs = divmod(remainder, 60)
                stats["up"] = f"{hours}h {minutes}m {secs}s"
        except:
            pass
        
        return stats
    except Exception as e:
        log.warning(f"Failed to get stats for {name}: {e}")
        return {"cpu": 0, "mem_mb": 0, "mem_p": 0, "rx": 0, "tx": 0, "up": "N/A"}

# ─────────────────────────────────────────────────────
# SHARED CREATE LOGIC (with user limit check)
# ─────────────────────────────────────────────────────
async def do_create(ix, user, ram, cpu, disk, os_key, cpu_key, days=0, node_id=None):
    # Check if user already has a VPS (limit: 1 per user)
    with get_db() as c:
        existing = c.execute(
            "SELECT COUNT(*) AS count FROM vps WHERE owner_id=? AND status NOT IN ('suspended', 'deleted')",
            (user.id,)
        ).fetchone()
        
        if existing and existing["count"] >= 1:
            return await ix.followup.send(embed=em(
                "❌ Limit Reached",
                f"{user.mention} already has **{existing['count']}** VPS instance(s).\n"
                f"Maximum allowed: **1** VPS per user.\n\n"
                f"Please remove or suspend existing VPS before creating a new one.",
                RED,
                fields=[
                    ("📋 Check your VPS", "Use `/my-vps` to see your instances", False),
                    ("🗑️ Delete VPS", "Use `/remove-vps <id>` to delete", False),
                ]
            ))
    
    image, os_label = LXC_IMAGES[os_key]
    cpu_name        = CPU_MAP[cpu_key]
    vps_id          = next_id()

    if node_id and not node_is_online(node_id):
        return await ix.followup.send(embed=em(
            "❌ Node Offline",
            f"Node **{node_id}** is not connected right now. Pick another node "
            f"or run `/node-list` to check status.",
            RED,
        ))

    exp_at   = None
    exp_note = "Never expires"
    if days > 0:
        dt       = datetime.datetime.utcnow() + datetime.timedelta(days=days)
        exp_at   = dt.isoformat()
        exp_note = f"Auto-suspends <t:{int(dt.timestamp())}:R>"

    await ix.followup.send(embed=em(
        "⏳ Provisioning VPS...",
        f"**{vps_id}** for {user.mention}\n\n"
        "```\n"
        "[1/5] Creating LXC container      ⏳\n"
        "[2/5] Configuring resources       ⏳\n"
        "[3/5] Starting container          ⏳\n"
        "[4/5] apt update + apt install    ⏳\n"
        "[5/5] Starting tmate SSH          ⏳\n"
        "```\n"
        "⏱ ~90 seconds — SSH sent to DM.",
        BLUE,
        fields=[
            ("🖥 OS",        os_label,                          True),
            ("🧠 RAM",       f"{ram} MB",                       True),
            ("💻 CPU",       f"{cpu} Core(s)",                  True),
            ("💾 Disk",      f"{disk} GB",                      True),
            ("🏷 CPU Model", cpu_name,                          False),
            ("📡 Node",      node_id or "Local (this server)",  False),
            ("⏰ Expiry",    exp_note,                          False),
        ],
    ))

    root_pass = gen_root_password()
    ssh_ip    = SERVER_IP

    try:
        if node_id:
            host_port = find_free_port_for_node(node_id)
            result = await send_job_to_node(node_id, {
                "type": "create_vps", "vps_id": vps_id, "image": image,
                "os_label": os_label, "ram_mb": ram, "cpu_cores": cpu,
                "disk_gb": disk, "cpu_name": cpu_name,
                "host_port": host_port, "root_pass": root_pass,
                "container_type": "lxc"
            })
            if not result.get("ok"):
                raise RuntimeError(result.get("error", "Unknown node error"))
            container_id = result.get("container_id", vps_id)
            ssh          = result.get("ssh", "")
            host_port    = result.get("host_port", host_port)
            container_ip = result.get("container_ip", "")
            with get_db() as c:
                row = c.execute("SELECT public_ip FROM nodes WHERE node_id=?", (node_id,)).fetchone()
                ssh_ip = row["public_ip"] if row and row["public_ip"] else SERVER_IP
        else:
            host_port = find_free_port()
            container_id, ssh, container_ip = await asyncio.get_event_loop().run_in_executor(
                None, lambda: provision(vps_id, image, os_label, ram, cpu, disk, cpu_name,
                                         host_port, root_pass)
            )
    except Exception as e:
        log.error(f"[{vps_id}] Failed: {e}")
        if not node_id and lxc_exists(vps_id):
            lxc_delete(vps_id)
        return await ix.followup.send(embed=em(
            "❌ Provisioning Failed",
            f"**{vps_id}** could not be created.\n```{str(e)[:600]}```\n"
            + (f"Run `/fix-vps {vps_id}` then try again." if not node_id else "Check the node's agent logs."),
            RED,
        ))

    with get_db() as c:
        c.execute("""
            INSERT INTO vps
              (vps_id,owner_id,container_id,os_image,os_label,
               ram_mb,cpu_cores,disk_gb,cpu_name,ssh_cmd,
               ssh_ip,ssh_port,root_pass,username,status,expires_at,node_id)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,'root','running',?,?)
        """, (vps_id, user.id, container_id, image, os_label,
              ram, cpu, disk, cpu_name, ssh,
              ssh_ip, host_port, root_pass, exp_at, node_id))

    log.info(f"Created {vps_id} for {user} by {ix.user} on node={node_id or 'local'}")

    ram_gb   = ram / 1024
    ram_disp = f"{ram_gb:g}g" if ram_gb == int(ram_gb) else f"{ram_gb:.1f}g"
    cpu_disp = f"{cpu:g}" if float(cpu) == int(cpu) else f"{cpu}"
    direct_ssh_cmd = f"ssh root@{ssh_ip} -p {host_port}"

    dm_ok = False
    try:
        fields = [
            ("Instance ID",     f"`{vps_id}`",                    True),
            ("OS",               os_label,                        True),
            ("RAM / CPU",        f"{ram_disp} / {cpu_disp} vCPU",  True),
            ("Shared IPv4",      f"`{ssh_ip}`",                    True),
            ("SSH Port (NAT)",   f"`{host_port}`",                 True),
            ("Username",         "`root`",                        True),
            ("Root Password",    f"```{root_pass}```",             False),
            ("SSH Command",      f"```{direct_ssh_cmd}```",        False),
        ]
        if exp_at: fields.append(("⏰ Expiry", exp_note, False))
        dm = await user.create_dm()
        await dm.send(embed=em(
            "⚡ Your VPS is Ready",
            "An admin deployed a VPS for you!\n"
            "⚠️ **Keep your root password private.**",
            GREEN, fields=fields,
        ))
        dm_ok = True
    except discord.Forbidden:
        log.warning(f"Cannot DM {user}")

    note = "✅ SSH sent to DM." if dm_ok else "⚠️ Could not DM — share SSH manually."
    await ix.followup.send(embed=em(
        "✅ VPS Created",
        f"**{vps_id}** is live for {user.mention}\n{note}",
        GREEN,
        fields=[
            ("🆔 VPS ID", vps_id,            True),
            ("👤 Owner",  str(user),          True),
            ("🖥 OS",     os_label,           True),
            ("🧠 RAM",    f"{ram} MB",        True),
            ("💻 CPU",    f"{cpu} Core(s)",   True),
            ("💾 Disk",   f"{disk} GB",       True),
            ("⏰ Expiry", exp_note,           False),
            ("📊 Limit",  "1 VPS per user (max)", False),
        ],
    ))

    if ix.channel:
        await ix.channel.send(embed=em(
            "🐉 VPS Provisioned",
            f"{user.mention} your **{vps_id}** is ready!\nCheck your **DMs** for the SSH command.\n"
            f"⚠️ **1 VPS limit** — you cannot create another.",
            BLUE,
            fields=[
                ("🆔 VPS ID", vps_id,          True),
                ("🖥 OS",     os_label,         True),
                ("🧠 RAM",    f"{ram} MB",      True),
                ("💻 CPU",    f"{cpu} Core(s)", True),
                ("💾 Disk",   f"{disk} GB",     True),
            ],
        ))

# ─────────────────────────────────────────────────────
# BOT
# ─────────────────────────────────────────────────────
intents         = discord.Intents.default()
intents.members = True

class NETHOST(commands.Bot):
    def __init__(self):
        super().__init__(command_prefix="!", intents=intents)

    async def setup_hook(self):
        await self.tree.sync()
        log.info("Commands synced.")
        await start_agent_server()
        if ANTI_MINING_ENABLED:
            anti_mining_scan.start()
            log.info("Anti-mining scan started.")

    async def on_ready(self):
        log.info(f"Online as {self.user}")
        if not auto_suspend.is_running():
            auto_suspend.start()
        if not update_status.is_running():
            update_status.start()
        if ANTI_MINING_ENABLED and not anti_mining_scan.is_running():
            anti_mining_scan.start()

bot = NETHOST()

# ─────────────────────────────────────────────────────
# LIVE STATUS TASK
# ─────────────────────────────────────────────────────
@tasks.loop(minutes=2)
async def update_status():
    try:
        with get_db() as c:
            count = c.execute(
                "SELECT COUNT(*) AS n FROM vps WHERE status='running'"
            ).fetchone()["n"]
        await bot.change_presence(activity=discord.Activity(
            type=discord.ActivityType.watching,
            name=f"VPS | {count} VPS Running"))
    except Exception as e:
        log.warning(f"Status update failed: {e}")

@update_status.before_loop
async def _status_before(): await bot.wait_until_ready()

# ─────────────────────────────────────────────────────
# AUTO-SUSPEND TASK
# ─────────────────────────────────────────────────────
@tasks.loop(minutes=15)
async def auto_suspend():
    now = datetime.datetime.utcnow()
    with get_db() as c:
        rows = c.execute(
            "SELECT * FROM vps WHERE expires_at IS NOT NULL AND status!='suspended'"
        ).fetchall()
    for row in rows:
        try:
            if now < datetime.datetime.fromisoformat(row["expires_at"]): continue
        except Exception: continue
        vid = row["vps_id"]
        log.info(f"[{vid}] Auto-suspending.")
        try:
            if row["container_id"] and lxc_exists(row["container_id"]):
                lxc_stop(row["container_id"])
        except Exception as e:
            log.warning(f"Auto suspend failed: {e}")
        if PTERO_ON and row["ptero_id"]:
            try: ptero_suspend(row["ptero_id"])
            except Exception as e: log.warning(f"Ptero suspend: {e}")
        with get_db() as c:
            c.execute("UPDATE vps SET status='suspended' WHERE vps_id=?", (vid,))
        try:
            u = await bot.fetch_user(row["owner_id"])
            await u.send(embed=em("⏰ VPS Suspended",
                f"Your VPS **{vid}** has expired and been suspended.\nContact admin to reactivate.",
                YELLOW))
        except Exception: pass

@auto_suspend.before_loop
async def _before(): await bot.wait_until_ready()

# ─────────────────────────────────────────────────────
# ANTI-MINING SCAN TASK
# ─────────────────────────────────────────────────────
@tasks.loop(minutes=ANTI_MINING_CHECK_INTERVAL / 60 if ANTI_MINING_CHECK_INTERVAL > 60 else 5)
async def anti_mining_scan():
    if not ANTI_MINING_ENABLED:
        return
    
    try:
        log.info("Running anti-mining scan...")
        
        with get_db() as c:
            rows = c.execute(
                "SELECT vps_id, container_id, owner_id FROM vps WHERE status='running'"
            ).fetchall()
        
        detected_count = 0
        for row in rows:
            vps_id = row["vps_id"]
            container_name = row["container_id"] or vps_id
            
            try:
                if not lxc_exists(container_name):
                    continue
                
                if not lxc_is_running(container_name):
                    continue
                
                results = detect_mining_activity(container_name)
                
                if results["detected"]:
                    detected_count += 1
                    action = handle_mining_detection(vps_id, container_name, results)
                    log.warning(f"[{vps_id}] Mining detected, action: {action}")
                    
            except Exception as e:
                log.error(f"Error scanning {vps_id} for mining: {e}")
        
        if detected_count > 0:
            log.warning(f"Anti-mining scan completed: {detected_count} containers detected")
        else:
            log.info("Anti-mining scan completed: No mining detected")
            
    except Exception as e:
        log.error(f"Anti-mining scan failed: {e}")

@anti_mining_scan.before_loop
async def _before_anti_mining():
    await bot.wait_until_ready()

# ══════════════════════════════════════════════
# USER COMMANDS
# ══════════════════════════════════════════════

@bot.tree.command(name="start", description="Start your VPS.")
@app_commands.describe(vps_id="e.g. NETHOST-vps-0001")
async def cmd_start(ix: discord.Interaction, vps_id: str):
    await ix.response.defer(ephemeral=True)
    vps_id = vps_id.lower()
    if not owns(ix.user.id, vps_id):
        return await ix.followup.send(embed=em("❌ Access Denied", "That VPS doesn't belong to you.", RED))
    with get_db() as c: row = c.execute("SELECT * FROM vps WHERE vps_id=?", (vps_id,)).fetchone()
    if not row: return await ix.followup.send(embed=em("❌ Not Found", f"**{vps_id}** not found.", RED))
    if row["status"] == "suspended":
        return await ix.followup.send(embed=em("⛔ Suspended", "Contact an admin to reactivate.", YELLOW))
    try:
        container_name = row["container_id"] or vps_id
        if lxc_exists(container_name):
            lxc_start(container_name)
        if PTERO_ON and row["ptero_id"]:
            try:
                ptero_unsuspend(row["ptero_id"])
            except Exception as e:
                log.warning(f"Ptero unsuspend failed: {e}")
        with get_db() as c: c.execute("UPDATE vps SET status='running' WHERE vps_id=?", (vps_id,))
        await ix.followup.send(embed=em("✅ Started",
            f"**{vps_id}** is running.\nUse `/regen-ssh {vps_id}` for a fresh SSH link.", GREEN))
    except Exception as e:
        await ix.followup.send(embed=em("❌ Error", str(e), RED))


@bot.tree.command(name="stop", description="Stop your VPS.")
@app_commands.describe(vps_id="e.g. NETHOST-vps-0001")
async def cmd_stop(ix: discord.Interaction, vps_id: str):
    await ix.response.defer(ephemeral=True)
    vps_id = vps_id.lower()
    if not owns(ix.user.id, vps_id):
        return await ix.followup.send(embed=em("❌ Access Denied", "That VPS doesn't belong to you.", RED))
    with get_db() as c: row = c.execute("SELECT container_id FROM vps WHERE vps_id=?", (vps_id,)).fetchone()
    if not row: return await ix.followup.send(embed=em("❌ Not Found", f"**{vps_id}** not found.", RED))
    try:
        container_name = row["container_id"] or vps_id
        if lxc_exists(container_name):
            lxc_stop(container_name)
        with get_db() as c: c.execute("UPDATE vps SET status='stopped' WHERE vps_id=?", (vps_id,))
        await ix.followup.send(embed=em("🛑 Stopped", f"**{vps_id}** stopped.", YELLOW))
    except Exception as e:
        await ix.followup.send(embed=em("❌ Error", str(e), RED))


@bot.tree.command(name="restart", description="Restart your VPS.")
@app_commands.describe(vps_id="e.g. NETHOST-vps-0001")
async def cmd_restart(ix: discord.Interaction, vps_id: str):
    await ix.response.defer(ephemeral=True)
    vps_id = vps_id.lower()
    if not owns(ix.user.id, vps_id):
        return await ix.followup.send(embed=em("❌ Access Denied", "That VPS doesn't belong to you.", RED))
    with get_db() as c: row = c.execute("SELECT container_id,status FROM vps WHERE vps_id=?", (vps_id,)).fetchone()
    if not row: return await ix.followup.send(embed=em("❌ Not Found", f"**{vps_id}** not found.", RED))
    if row["status"] == "suspended":
        return await ix.followup.send(embed=em("⛔ Suspended", "Contact an admin to reactivate.", YELLOW))
    try:
        container_name = row["container_id"] or vps_id
        if lxc_exists(container_name):
            lxc_restart(container_name)
        with get_db() as c: c.execute("UPDATE vps SET status='running' WHERE vps_id=?", (vps_id,))
        await ix.followup.send(embed=em("🔄 Restarted",
            f"**{vps_id}** restarted.\nUse `/regen-ssh {vps_id}` for a fresh SSH link.", GREEN))
    except Exception as e:
        await ix.followup.send(embed=em("❌ Error", str(e), RED))


@bot.tree.command(name="reinstall", description="Reinstall your VPS (same specs, data wiped).")
@app_commands.describe(vps_id="e.g. NETHOST-vps-0001")
async def cmd_reinstall(ix: discord.Interaction, vps_id: str):
    await ix.response.defer(ephemeral=True)
    vps_id = vps_id.lower()
    if not owns(ix.user.id, vps_id):
        return await ix.followup.send(embed=em("❌ Access Denied", "That VPS doesn't belong to you.", RED))
    with get_db() as c: row = c.execute("SELECT * FROM vps WHERE vps_id=?", (vps_id,)).fetchone()
    if not row: return await ix.followup.send(embed=em("❌ Not Found", f"**{vps_id}** not found.", RED))
    await ix.followup.send(embed=em("⏳ Reinstalling...", "~90 seconds...", YELLOW))
    try:
        container_name = row["container_id"] or vps_id
        if lxc_exists(container_name):
            lxc_delete(container_name)
            time.sleep(2)

        host_port = row["ssh_port"] or find_free_port()
        root_pass = gen_root_password()

        container_id, ssh, container_ip = await asyncio.get_event_loop().run_in_executor(
            None, lambda: provision(vps_id, row["os_image"], row["os_label"],
                                    row["ram_mb"], row["cpu_cores"], row["disk_gb"], row["cpu_name"],
                                    host_port, root_pass)
        )
        with get_db() as c:
            c.execute("""UPDATE vps SET container_id=?,ssh_cmd=?,ssh_ip=?,ssh_port=?,
                         root_pass=?,status='running',mining_flag=0 WHERE vps_id=?""",
                      (container_id, ssh, SERVER_IP, host_port, root_pass, vps_id))
        try:
            dm = await ix.user.create_dm()
            direct_ssh_cmd = f"ssh root@{SERVER_IP} -p {host_port}"
            await dm.send(embed=em("🔄 Reinstalled", f"**{vps_id}** rebuilt — data wiped.", GREEN,
                fields=[
                    ("Shared IPv4",    f"`{SERVER_IP}`",          True),
                    ("SSH Port (NAT)", f"`{host_port}`",          True),
                    ("Username",       "`root`",                  True),
                    ("Root Password",  f"```{root_pass}```",      False),
                    ("SSH Command",    f"```{direct_ssh_cmd}```", False),
                ]))
        except discord.Forbidden: pass
        await ix.followup.send(embed=em("✅ Reinstalled", f"**{vps_id}** done. Check DMs.", GREEN))
    except Exception as e:
        await ix.followup.send(embed=em("❌ Error", str(e), RED))


@bot.tree.command(name="regen-ssh", description="Get a fresh tmate SSH session.")
@app_commands.describe(vps_id="e.g. NETHOST-vps-0001")
async def cmd_regen(ix: discord.Interaction, vps_id: str):
    await ix.response.defer(ephemeral=True)
    vps_id = vps_id.lower()
    if not owns(ix.user.id, vps_id):
        return await ix.followup.send(embed=em("❌ Access Denied", "That VPS doesn't belong to you.", RED))
    with get_db() as c: row = c.execute("SELECT * FROM vps WHERE vps_id=?", (vps_id,)).fetchone()
    if not row: return await ix.followup.send(embed=em("❌ Not Found", f"**{vps_id}** not found.", RED))
    if row["status"] != "running":
        return await ix.followup.send(embed=em("⚠️ Not Running", f"Start first: `/start {vps_id}`", YELLOW))
    try:
        container_name = row["container_id"] or vps_id
        if not lxc_exists(container_name):
            return await ix.followup.send(embed=em("❌ Not Found", f"Container **{container_name}** not found.", RED))
        ssh = await asyncio.get_event_loop().run_in_executor(None, lambda: regen_ssh(container_name))
        if not ssh:
            return await ix.followup.send(embed=em("⚠️ Not Ready", "Try again in 15 seconds.", YELLOW))
        with get_db() as c: c.execute("UPDATE vps SET ssh_cmd=? WHERE vps_id=?", (ssh, vps_id))
        await ix.followup.send(embed=em(f"🔑 SSH Session — {vps_id}",
            "⚠️ Keep private — anyone with this can access your terminal.",
            GREEN, fields=[("🖥 SSH Command", f"```{ssh}```", False)]))
    except Exception as e:
        await ix.followup.send(embed=em("❌ Error", str(e), RED))


@bot.tree.command(name="vps-performance", description="Live stats for your VPS.")
@app_commands.describe(vps_id="e.g. NETHOST-vps-0001")
async def cmd_perf(ix: discord.Interaction, vps_id: str):
    await ix.response.defer(ephemeral=True)
    vps_id = vps_id.lower()
    if not owns(ix.user.id, vps_id):
        return await ix.followup.send(embed=em("❌ Access Denied", "That VPS doesn't belong to you.", RED))
    with get_db() as c: row = c.execute("SELECT * FROM vps WHERE vps_id=?", (vps_id,)).fetchone()
    if not row: return await ix.followup.send(embed=em("❌ Not Found", f"**{vps_id}** not found.", RED))
    try:
        container_name = row["container_id"] or vps_id
        if not lxc_exists(container_name):
            return await ix.followup.send(embed=em("❌ Not Found", f"Container **{container_name}** not found.", RED))
        if not lxc_is_running(container_name):
            return await ix.followup.send(embed=em("⚠️ Not Running", f"Start first: `/start {vps_id}`", YELLOW))
        s = get_stats(container_name, row["ram_mb"], row["cpu_cores"])
        
        du = "N/A"
        try:
            result = lxc_exec(container_name, "df -BM / --output=used | tail -1", check=False)
            if result:
                raw = result.strip().replace("M", "").strip()
                try:
                    du = f"{round(int(raw)/1024, 2)} GB"
                except:
                    du = raw + " MB"
        except:
            pass
            
        pf = [("🦅 Ptero ID", str(row["ptero_id"]), True)] if PTERO_ON and row["ptero_id"] else []
        mining_flag = "🚨 Mining Detected" if row["mining_flag"] else "✅ Clean"
        await ix.followup.send(embed=em("📊 VPS Performance", "", BLUE, fields=[
            ("🆔 VPS ID",    vps_id,                                               True),
            ("🖥 OS",        row["os_label"] or row["os_image"],                   True),
            ("🏷 CPU Model", row["cpu_name"],                                       True),
            ("💻 CPU",       f"{s['cpu']}% of {row['cpu_cores']} Core(s)",        True),
            ("🧠 RAM",       f"{s['mem_mb']} MB / {row['ram_mb']} MB ({s['mem_p']}%)", True),
            ("💾 Disk",      f"{du} / {row['disk_gb']} GB",                        True),
            ("⏱ Uptime",    s["up"],                                               True),
            ("🌐 Net RX",    f"{s['rx']} MB",                                      True),
            ("🌐 Net TX",    f"{s['tx']} MB",                                      True),
            ("🛡️ Mining",   mining_flag,                                           True),
            *pf,
        ]))
    except Exception as e:
        await ix.followup.send(embed=em("❌ Error", str(e), RED))


@bot.tree.command(name="my-vps", description="List all your VPS instances.")
async def cmd_my_vps(ix: discord.Interaction):
    await ix.response.defer(ephemeral=True)
    with get_db() as c:
        rows = c.execute("SELECT * FROM vps WHERE owner_id=? ORDER BY vps_id", (ix.user.id,)).fetchall()
    
    if not rows:
        return await ix.followup.send(embed=em(
            "📋 My VPS", 
            "You have no VPS instances.\n\n"
            "⚠️ **1 VPS limit** — you can have only 1 VPS at a time.",
            YELLOW
        ))
    
    fields = []
    limit_msg = ""
    for r in rows:
        line = (f"OS:`{r['os_label']}` RAM:`{r['ram_mb']}MB` "
                f"CPU:`{r['cpu_cores']}` Disk:`{r['disk_gb']}GB` Status:`{r['status']}`")
        if r["mining_flag"]:
            line += " 🚨 Mining Detected"
        if r["expires_at"]:
            try:
                ts = int(datetime.datetime.fromisoformat(r["expires_at"]).timestamp())
                line += f"\n⏰ Expires: <t:{ts}:R>"
            except Exception: pass
        fields.append((r["vps_id"], line, False))
    
    if len(rows) >= 1:
        limit_msg = f"\n\n⚠️ **Limit:** {len(rows)}/1 VPS used — you cannot create another."
    
    await ix.followup.send(embed=em(
        f"📋 My VPS ({len(rows)})", 
        f"You have {len(rows)} VPS instance(s).{limit_msg}", 
        BLUE, 
        fields=fields
    ))


@bot.tree.command(name="commands", description="Show all commands.")
async def cmd_commands(ix: discord.Interaction):
    await ix.response.defer(ephemeral=True)
    u = em("👤 User Commands", 
           "⚠️ **1 VPS limit** — you can only have 1 VPS at a time.", 
           BLUE, fields=[
        ("`/start <id>`",           "▶️  Start VPS",                      False),
        ("`/stop <id>`",            "⏹️  Stop VPS",                       False),
        ("`/restart <id>`",         "🔄  Restart VPS",                    False),
        ("`/reinstall <id>`",       "🔁  Wipe & reinstall",               False),
        ("`/regen-ssh <id>`",       "🔑  Fresh tmate SSH session",        False),
        ("`/vps-performance <id>`", "📊  Live CPU/RAM/Disk/Net stats",    False),
        ("`/my-vps`",               "📋  List your VPS instances",        False),
        ("`/redeem <code>`",        "🎟️  Redeem a VPS code",              False),
        ("`/commands`",             "📖  This help",                      False),
    ])
    a = em("🛡️ Admin Commands", "", RED, fields=[
        ("`/deploy <user>`",                                     "🎛️  1-click deploy (32GB/4CPU/80GB)", False),
        ("`/create <user> <ram> <cpu> <disk> <os> <cpu> <days>`","➕  Full param create",               False),
        ("`/admin-add-user <user>`",                             "✅  Grant access",                    False),
        ("`/admin-remove-user <user>`",                          "❌  Revoke access",                   False),
        ("`/extend-vps <id> <days>`",                            "⏰  Extend/remove expiry",            False),
        ("`/suspend-vps <id>`",                                  "⛔  Suspend VPS",                     False),
        ("`/unsuspend-vps <id>`",                                "🔓  Unsuspend VPS",                   False),
        ("`/remove-vps <id>`",                                   "🗑️  Delete VPS",                     False),
        ("`/fix-vps <id>`",                                      "🔧  Remove stuck container",          False),
        ("`/list-vps`",                                          "📋  List all VPS",                    False),
        ("`/node-stats`",                                        "🖥️  Host stats",                     False),
        ("`/check-network`",                                     "🌐  Diagnose SERVER_IP/ports",        False),
        ("`/gen-redeem <ram> <cpu> <disk> <days> <count>`",      "🎟️  Generate redeem code(s)",        False),
        ("`/redeem-stock`",                                      "📦  View unredeemed codes",           False),
        ("`/node-create <name>`",                                "📡  Register a new node",             False),
        ("`/node-config <name>`",                                "🔗  Get node install/connect cmd",    False),
        ("`/node-list`",                                         "📋  List nodes + online status",      False),
        ("`/node-delete <name>`",                                "🗑️  Delete a node",                  False),
        ("`/ptero-status`",                                      "🦅  Pterodactyl status",              False),
        ("`/scan-vps <id>`",                                     "🔍  Scan VPS for mining",             False),
        ("`/mining-stats`",                                      "📊  Anti-mining statistics",          False),
        ("`/toggle-mining <true/false>`",                        "⏹️  Enable/disable anti-mining",     False),
    ])
    r = em("📖 Reference", "", DARK, fields=[
        ("VPS ID",      "`NETHOST-vps-0001`, `NETHOST-vps-0002` ...",                 False),
        ("OS",          "`ubuntu20` `ubuntu22` `ubuntu24` `debian11` `debian12`",        False),
        ("CPU",         "`ryzen9` → AMD Ryzen 9 9950X\n`xeon` → Intel Xeon Platinum 8480+", False),
        ("SSH Access",  "tmate SSH only — sent to DM, never public",                     False),
        ("systemctl",   "Full systemd — `systemctl`, services, cron all work",           False),
        ("Pterodactyl", "Syncs when `PTERO_URL` + `PTERO_API_KEY` set in .env",          False),
        ("⚠️ Limit",    "**1 VPS per user** — delete existing VPS to create new one",    False),
        ("🚫 Mining",   "**Anti-mining protection** — mining = suspension",              False),
    ])
    await ix.followup.send(embeds=[u, a, r])

# ══════════════════════════════════════════════
# ADMIN COMMANDS
# ══════════════════════════════════════════════

@bot.tree.command(name="admin-add-user", description="[Admin] Grant hosting access.")
@app_commands.describe(user="User to grant access")
async def cmd_add(ix: discord.Interaction, user: discord.Member):
    await ix.response.defer(ephemeral=True)
    if not is_admin(ix): return await ix.followup.send(embed=em("⛔ Forbidden", "Admin only.", RED))
    with get_db() as c:
        c.execute("INSERT OR IGNORE INTO allowed_users (user_id,added_by) VALUES (?,?)", (user.id, ix.user.id))
    await ix.followup.send(embed=em("✅ Added", f"{user.mention} granted access.", GREEN))


@bot.tree.command(name="admin-remove-user", description="[Admin] Revoke hosting access.")
@app_commands.describe(user="User to revoke")
async def cmd_rm(ix: discord.Interaction, user: discord.Member):
    await ix.response.defer(ephemeral=True)
    if not is_admin(ix): return await ix.followup.send(embed=em("⛔ Forbidden", "Admin only.", RED))
    with get_db() as c: c.execute("DELETE FROM allowed_users WHERE user_id=?", (user.id,))
    await ix.followup.send(embed=em("🗑 Removed", f"{user.mention} access revoked.", YELLOW))


async def node_autocomplete(ix: discord.Interaction, current: str):
    with get_db() as c:
        rows = c.execute("SELECT node_id, status FROM nodes").fetchall()
    choices = [app_commands.Choice(name="Local (this server)", value="local")]
    for r in rows:
        label = f"{r['node_id']} ({'🟢 online' if r['status']=='online' else '🔴 offline'})"
        choices.append(app_commands.Choice(name=label, value=r["node_id"]))
    if current:
        choices = [ch for ch in choices if current.lower() in ch.name.lower()]
    return choices[:25]

async def existing_node_autocomplete(ix: discord.Interaction, current: str):
    with get_db() as c:
        rows = c.execute("SELECT node_id, status FROM nodes").fetchall()
    choices = [
        app_commands.Choice(name=f"{r['node_id']} ({'🟢 online' if r['status']=='online' else '🔴 offline'})",
                             value=r["node_id"])
        for r in rows
    ]
    if current:
        choices = [ch for ch in choices if current.lower() in ch.name.lower()]
    return choices[:25]


@bot.tree.command(name="create", description="[Admin] Create VPS with full parameters.")
@app_commands.describe(user="Target user", ram="RAM in MB", cpu="CPU cores",
    disk="Disk in GB", os="OS", cpu_name="CPU model", suspend_in_days="Days until auto-suspend (0=never)",
    node="Which node to deploy on (leave blank for local)")
@app_commands.choices(
    os=[
        app_commands.Choice(name="Ubuntu 20.04", value="ubuntu20"),
        app_commands.Choice(name="Ubuntu 22.04", value="ubuntu22"),
        app_commands.Choice(name="Ubuntu 24.04", value="ubuntu24"),
        app_commands.Choice(name="Debian 11",    value="debian11"),
        app_commands.Choice(name="Debian 12",    value="debian12"),
    ],
    cpu_name=[
        app_commands.Choice(name="AMD Ryzen 9 9950X",         value="ryzen9"),
        app_commands.Choice(name="Intel Xeon Platinum 8480+", value="xeon"),
    ],
)
@app_commands.autocomplete(node=node_autocomplete)
async def cmd_create(ix: discord.Interaction, user: discord.Member, ram: int, cpu: float,
    disk: int, os: app_commands.Choice[str], cpu_name: app_commands.Choice[str],
    suspend_in_days: int = 0, node: str = "local"):
    await ix.response.defer(ephemeral=True)
    if not is_admin(ix): return await ix.followup.send(embed=em("⛔ Forbidden", "Admin only.", RED))
    target_node = None if not node or node == "local" else node
    await do_create(ix, user, ram, cpu, disk, os.value, cpu_name.value, suspend_in_days, target_node)


@bot.tree.command(name="extend-vps", description="[Admin] Extend or remove expiry.")
@app_commands.describe(vps_id="VPS ID", days="Days from now (0 = never)")
async def cmd_extend(ix: discord.Interaction, vps_id: str, days: int):
    await ix.response.defer(ephemeral=True)
    if not is_admin(ix): return await ix.followup.send(embed=em("⛔ Forbidden", "Admin only.", RED))
    vps_id = vps_id.lower()
    with get_db() as c: row = c.execute("SELECT * FROM vps WHERE vps_id=?", (vps_id,)).fetchone()
    if not row: return await ix.followup.send(embed=em("❌ Not Found", f"**{vps_id}** not found.", RED))
    if days <= 0:
        with get_db() as c: c.execute("UPDATE vps SET expires_at=NULL WHERE vps_id=?", (vps_id,))
        return await ix.followup.send(embed=em("✅ Expiry Removed", f"**{vps_id}** never auto-suspends.", GREEN))
    dt = datetime.datetime.utcnow() + datetime.timedelta(days=days)
    with get_db() as c: c.execute("UPDATE vps SET expires_at=? WHERE vps_id=?", (dt.isoformat(), vps_id))
    ts = int(dt.timestamp())
    await ix.followup.send(embed=em("✅ Expiry Set", f"**{vps_id}** auto-suspends <t:{ts}:R>.", GREEN))
    try:
        u = await bot.fetch_user(row["owner_id"])
        await u.send(embed=em("⏰ Expiry Updated", f"Your VPS **{vps_id}** auto-suspends <t:{ts}:R>.", BLUE))
    except Exception: pass


@bot.tree.command(name="suspend-vps", description="[Admin] Suspend a VPS.")
@app_commands.describe(vps_id="VPS ID")
async def cmd_suspend(ix: discord.Interaction, vps_id: str):
    await ix.response.defer(ephemeral=True)
    if not is_admin(ix): return await ix.followup.send(embed=em("⛔ Forbidden", "Admin only.", RED))
    vps_id = vps_id.lower()
    with get_db() as c: row = c.execute("SELECT * FROM vps WHERE vps_id=?", (vps_id,)).fetchone()
    if not row: return await ix.followup.send(embed=em("❌ Not Found", f"**{vps_id}** not found.", RED))
    try:
        container_name = row["container_id"] or vps_id
        if lxc_exists(container_name):
            lxc_stop(container_name)
    except Exception as e:
        log.warning(f"LXC suspend failed: {e}")
    if PTERO_ON and row["ptero_id"]:
        try: ptero_suspend(row["ptero_id"])
        except Exception as e: log.warning(f"Ptero suspend: {e}")
    with get_db() as c: c.execute("UPDATE vps SET status='suspended' WHERE vps_id=?", (vps_id,))
    await ix.followup.send(embed=em("⛔ Suspended", f"**{vps_id}** suspended.", YELLOW))


@bot.tree.command(name="unsuspend-vps", description="[Admin] Reactivate a VPS.")
@app_commands.describe(vps_id="VPS ID")
async def cmd_unsuspend(ix: discord.Interaction, vps_id: str):
    await ix.response.defer(ephemeral=True)
    if not is_admin(ix): return await ix.followup.send(embed=em("⛔ Forbidden", "Admin only.", RED))
    vps_id = vps_id.lower()
    with get_db() as c: row = c.execute("SELECT * FROM vps WHERE vps_id=?", (vps_id,)).fetchone()
    if not row: return await ix.followup.send(embed=em("❌ Not Found", f"**{vps_id}** not found.", RED))
    try:
        container_name = row["container_id"] or vps_id
        if lxc_exists(container_name):
            lxc_start(container_name)
        if PTERO_ON and row["ptero_id"]:
            try: ptero_unsuspend(row["ptero_id"])
            except Exception as e: log.warning(f"Ptero unsuspend: {e}")
        with get_db() as c: c.execute("UPDATE vps SET status='running' WHERE vps_id=?", (vps_id,))
        await ix.followup.send(embed=em("✅ Unsuspended",
            f"**{vps_id}** is active. User can run `/regen-ssh {vps_id}`.", GREEN))
    except Exception as e:
        await ix.followup.send(embed=em("❌ Error", str(e), RED))


@bot.tree.command(name="remove-vps", description="[Admin] Permanently delete a VPS.")
@app_commands.describe(vps_id="VPS ID")
async def cmd_remove(ix: discord.Interaction, vps_id: str):
    await ix.response.defer(ephemeral=True)
    if not is_admin(ix): return await ix.followup.send(embed=em("⛔ Forbidden", "Admin only.", RED))
    vps_id = vps_id.lower()
    with get_db() as c: row = c.execute("SELECT * FROM vps WHERE vps_id=?", (vps_id,)).fetchone()
    if not row: return await ix.followup.send(embed=em("❌ Not Found", f"**{vps_id}** not found.", RED))
    
    with get_db() as c:
        user_count = c.execute(
            "SELECT COUNT(*) AS count FROM vps WHERE owner_id=? AND status NOT IN ('deleted') AND vps_id != ?",
            (row["owner_id"], vps_id)
        ).fetchone()
    
    try:
        container_name = row["container_id"] or vps_id
        if lxc_exists(container_name):
            lxc_delete(container_name)
    except Exception as e:
        log.warning(f"LXC delete failed: {e}")
    if PTERO_ON and row["ptero_id"]:
        try: ptero_remove(row["ptero_id"])
        except Exception as e: log.warning(f"Ptero delete: {e}")
    with get_db() as c: c.execute("DELETE FROM vps WHERE vps_id=?", (vps_id,))
    
    if user_count and user_count["count"] == 0:
        try:
            u = await bot.fetch_user(row["owner_id"])
            await u.send(embed=em(
                "🗑️ VPS Deleted",
                f"Your VPS **{vps_id}** has been deleted by an admin.\n"
                f"You can now create a new VPS (1 VPS limit).",
                YELLOW
            ))
        except Exception: pass
    
    await ix.followup.send(embed=em("🗑 Deleted", f"**{vps_id}** permanently deleted.", YELLOW))


@bot.tree.command(name="fix-vps", description="[Admin] Force-remove a stuck container.")
@app_commands.describe(vps_id="VPS ID to fix")
async def cmd_fix(ix: discord.Interaction, vps_id: str):
    await ix.response.defer(ephemeral=True)
    if not is_admin(ix): return await ix.followup.send(embed=em("⛔ Forbidden", "Admin only.", RED))
    vps_id  = vps_id.lower()
    removed = False
    try:
        container_name = vps_id
        if lxc_exists(container_name):
            lxc_delete(container_name)
            removed = True
            log.info(f"{ix.user} fixed stuck container {vps_id}")
    except Exception as e:
        return await ix.followup.send(embed=em("❌ Error", str(e), RED))
    with get_db() as c:
        if c.execute("SELECT 1 FROM vps WHERE vps_id=?", (vps_id,)).fetchone():
            c.execute("UPDATE vps SET status='stopped' WHERE vps_id=?", (vps_id,))
    msg = (f"Removed stuck container for **{vps_id}**.\nNow run `/reinstall {vps_id}` or `/create` again."
           if removed else f"No stuck container found for **{vps_id}** — already clean.")
    await ix.followup.send(embed=em("✅ Fixed" if removed else "ℹ️ Clean", msg,
                                    GREEN if removed else BLUE))


@bot.tree.command(name="list-vps", description="[Admin] List all VPS on the node.")
async def cmd_list(ix: discord.Interaction):
    await ix.response.defer(ephemeral=True)
    if not is_admin(ix): return await ix.followup.send(embed=em("⛔ Forbidden", "Admin only.", RED))
    with get_db() as c: rows = c.execute("SELECT * FROM vps ORDER BY vps_id").fetchall()
    if not rows: return await ix.followup.send(embed=em("📋 All VPS", "None found.", YELLOW))
    fields = []
    for r in rows:
        line = (f"<@{r['owner_id']}> OS:`{r['os_label']}` RAM:`{r['ram_mb']}MB` "
                f"CPU:`{r['cpu_cores']}` Disk:`{r['disk_gb']}GB` Status:`{r['status']}`")
        if r["mining_flag"]:
            line += " 🚨 MINING DETECTED"
        if PTERO_ON and r["ptero_id"]: line += f" 🦅`{r['ptero_id']}`"
        if r["expires_at"]:
            try:
                ts = int(datetime.datetime.fromisoformat(r["expires_at"]).timestamp())
                line += f" Expires:<t:{ts}:R>"
            except Exception: pass
        fields.append((r["vps_id"], line, False))
    for i in range(0, len(fields), 25):
        await ix.followup.send(embed=em(f"📋 All VPS ({len(rows)}) — Page {i//25+1}", "", BLUE,
                                        fields=fields[i:i+25]))


@bot.tree.command(name="node-stats", description="[Admin] Host node resource usage.")
async def cmd_node(ix: discord.Interaction):
    await ix.response.defer(ephemeral=True)
    if not is_admin(ix): return await ix.followup.send(embed=em("⛔ Forbidden", "Admin only.", RED))
    cpu = psutil.cpu_percent(interval=1)
    mem = psutil.virtual_memory()
    dsk = psutil.disk_usage("/")
    try:
        result = lxc_command(["list", "--format", "csv"], check=False)
        running = sum(1 for line in result.stdout.split("\n") if line and "RUNNING" in line)
        total = len([line for line in result.stdout.split("\n") if line])
    except Exception:
        running = total = 0
    pf = []
    if PTERO_ON:
        s = ptero_check()
        pf = [("🦅 Pterodactyl",
               f"✅ {s.get('nodes',0)} node(s)" if s["ok"] else f"❌ {s.get('error','Error')}", False)]
    await ix.followup.send(embed=em("🖥️ Node Stats", "", BLUE, fields=[
        ("🖥 Host CPU",    f"{cpu}%",                                                                        True),
        ("🧠 Host RAM",    f"{round(mem.used/1024**3,2)}/{round(mem.total/1024**3,2)} GB ({mem.percent}%)", True),
        ("💾 Host Disk",   f"{gb(dsk.used)}/{gb(dsk.total)} GB ({dsk.percent}%)",                           True),
        ("📦 Running",     str(running),                                                                     True),
        ("📦 Total",       str(total),                                                                       True),
        *pf,
    ]))


@bot.tree.command(name="check-network", description="[Admin] Diagnose SERVER_IP + SSH port setup.")
async def cmd_check_network(ix: discord.Interaction):
    await ix.response.defer(ephemeral=True)
    if not is_admin(ix): return await ix.followup.send(embed=em("⛔ Forbidden", "Admin only.", RED))

    lines = []
    ok_all = True

    try:
        lxc_command(["version"], check=False)
        lines.append("✅ LXC is installed and reachable")
    except Exception as e:
        ok_all = False
        lines.append(f"❌ LXC NOT reachable — {str(e)[:150]}")

    real_ip = None
    try:
        real_ip = requests.get("https://api.ipify.org", timeout=5).text.strip()
        if real_ip == SERVER_IP:
            lines.append(f"✅ SERVER_IP matches this machine's public IP (`{SERVER_IP}`)")
        else:
            ok_all = False
            lines.append(
                f"❌ SERVER_IP (`{SERVER_IP}`) does NOT match this machine's "
                f"actual public IP (`{real_ip}`) — update your `.env`"
            )
    except Exception as e:
        lines.append(f"⚠️ Could not verify public IP (no internet from this host?) — {str(e)[:120]}")

    sample_port = SSH_PORT_START
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("0.0.0.0", sample_port))
        lines.append(f"✅ Port `{sample_port}` is bindable locally (range looks usable)")
    except Exception as e:
        ok_all = False
        lines.append(f"❌ Port `{sample_port}` failed to bind locally — {str(e)[:120]}")

    lines.append(
        "\n⚠️ This command can only check the **local** machine. It "
        "**cannot** confirm your cloud firewall / security group allows "
        f"inbound TCP on `{SSH_PORT_START}-{SSH_PORT_END}` — verify that "
        "separately in your provider's dashboard, then test from another "
        "machine with:\n```nc -zv " + (real_ip or SERVER_IP) + f" {sample_port}```"
    )

    await ix.followup.send(embed=em(
        "✅ Network Check Passed" if ok_all else "⚠️ Network Check Found Issues",
        "\n".join(lines),
        GREEN if ok_all else YELLOW,
    ))


# ══════════════════════════════════════════════
# REDEEM CODE SYSTEM
# ══════════════════════════════════════════════
@bot.tree.command(name="gen-redeem", description="[Admin] Generate VPS redeem code(s).")
@app_commands.describe(
    ram="RAM in MB for the VPS this code grants",
    cpu="CPU cores for the VPS this code grants",
    disk="Disk in GB for the VPS this code grants",
    valid_days="Auto-suspend after this many days once redeemed (0=never)",
    count="How many codes to generate at once (max 25)",
)
async def cmd_gen_redeem(ix: discord.Interaction, ram: int, cpu: float, disk: int,
                          valid_days: int = 0, count: int = 1):
    await ix.response.defer(ephemeral=True)
    if not is_admin(ix): return await ix.followup.send(embed=em("⛔ Forbidden", "Admin only.", RED))
    if count < 1 or count > 25:
        return await ix.followup.send(embed=em("❌ Invalid", "`count` must be between 1 and 25.", RED))

    codes = []
    with get_db() as c:
        for _ in range(count):
            code = gen_redeem_code()
            c.execute(
                "INSERT INTO redeem_codes (code,ram_mb,cpu_cores,disk_gb,valid_days,created_by) VALUES (?,?,?,?,?,?)",
                (code, ram, cpu, disk, valid_days, ix.user.id),
            )
            codes.append(code)

    block = "\n".join(codes)
    await ix.followup.send(embed=em(
        f"🎟️ {count} Redeem Code(s) Generated",
        f"Each code grants: **{ram}MB RAM / {cpu} vCPU / {disk}GB Disk** "
        f"({'never expires' if valid_days == 0 else f'{valid_days}-day auto-suspend'})\n"
        f"```\n{block}\n```\n"
        "Give these to members — each works **once**, with `/redeem <code>`.",
        GREEN,
    ))


@bot.tree.command(name="redeem", description="Redeem a VPS code.")
@app_commands.describe(code="Your redeem code")
async def cmd_redeem(ix: discord.Interaction, code: str):
    await ix.response.defer(ephemeral=True)
    code = code.strip().upper()

    with get_db() as c:
        existing = c.execute(
            "SELECT COUNT(*) AS count FROM vps WHERE owner_id=? AND status NOT IN ('suspended', 'deleted')",
            (ix.user.id,)
        ).fetchone()
        
        if existing and existing["count"] >= 1:
            return await ix.followup.send(embed=em(
                "❌ Limit Reached",
                f"You already have **{existing['count']}** VPS instance(s).\n"
                f"Maximum allowed: **1** VPS per user.\n\n"
                f"Please remove or suspend your existing VPS before redeeming a new code.",
                RED,
                fields=[
                    ("📋 Check your VPS", "Use `/my-vps` to see your instances", False),
                    ("🗑️ Delete VPS", "Use `/remove-vps <id>` to delete", False),
                ]
            ))

    with get_db() as c:
        row = c.execute(
            "DELETE FROM redeem_codes WHERE code=? RETURNING ram_mb, cpu_cores, disk_gb, valid_days",
            (code,),
        ).fetchone()

    if not row:
        return await ix.followup.send(embed=em(
            "❌ Invalid Code",
            "This code doesn't exist or has already been redeemed.", RED))

    await do_create(
        ix, ix.user, row["ram_mb"], row["cpu_cores"], row["disk_gb"],
        "ubuntu24", "ryzen9", row["valid_days"], None,
    )


@bot.tree.command(name="redeem-stock", description="[Admin] View unredeemed codes.")
async def cmd_redeem_stock(ix: discord.Interaction):
    await ix.response.defer(ephemeral=True)
    if not is_admin(ix): return await ix.followup.send(embed=em("⛔ Forbidden", "Admin only.", RED))
    with get_db() as c:
        rows = c.execute("SELECT * FROM redeem_codes ORDER BY created_at DESC").fetchall()
    if not rows:
        return await ix.followup.send(embed=em("🎟️ Redeem Stock", "No unredeemed codes right now.", BLUE))
    lines = []
    for r in rows:
        exp = "never expires" if r["valid_days"] == 0 else f"{r['valid_days']}d"
        lines.append(f"`{r['code']}` → {r['ram_mb']}MB/{r['cpu_cores']}vCPU/{r['disk_gb']}GB ({exp})")
    text = "\n".join(lines[:40])
    if len(rows) > 40:
        text += f"\n… and {len(rows)-40} more."
    await ix.followup.send(embed=em(f"🎟️ Redeem Stock ({len(rows)})", text, BLUE))


# ══════════════════════════════════════════════
# ANTI-MINING ADMIN COMMANDS
# ══════════════════════════════════════════════

@bot.tree.command(name="scan-vps", description="[Admin] Scan a VPS for mining activity.")
@app_commands.describe(vps_id="VPS ID to scan")
async def cmd_scan_vps(ix: discord.Interaction, vps_id: str):
    await ix.response.defer(ephemeral=True)
    if not is_admin(ix): 
        return await ix.followup.send(embed=em("⛔ Forbidden", "Admin only.", RED))
    
    vps_id = vps_id.lower()
    with get_db() as c:
        row = c.execute("SELECT * FROM vps WHERE vps_id=?", (vps_id,)).fetchone()
        if not row:
            return await ix.followup.send(embed=em("❌ Not Found", f"**{vps_id}** not found.", RED))
    
    container_name = row["container_id"] or vps_id
    
    if not lxc_exists(container_name):
        return await ix.followup.send(embed=em("❌ Not Found", f"Container **{container_name}** not found.", RED))
    
    if not lxc_is_running(container_name):
        return await ix.followup.send(embed=em("⚠️ Not Running", f"**{vps_id}** is not running.", YELLOW))
    
    await ix.followup.send(embed=em("🔍 Scanning VPS", f"Scanning **{vps_id}** for mining activity...", YELLOW))
    
    try:
        results = await asyncio.get_event_loop().run_in_executor(
            None, lambda: detect_mining_activity(container_name)
        )
        
        if results["detected"]:
            action = handle_mining_detection(vps_id, container_name, results)
            fields = [
                ("🔴 Detected", "Yes", True),
                ("CPU Usage", f"{results['cpu_usage']}%", True),
                ("Memory Usage", f"{results['mem_usage']}%", True),
                ("Action Taken", action, False),
                ("Reasons", "\n".join(results["reasons"][:5]), False),
            ]
            if results["mining_processes_found"]:
                fields.append(("Suspicious Processes", 
                              "\n".join(results["mining_processes_found"][:5]), False))
            
            await ix.edit_original_response(embed=em(
                "🚨 Mining Detected!",
                f"**{vps_id}** is mining cryptocurrency.",
                RED,
                fields=fields
            ))
        else:
            # Clear mining flag if it was set
            with get_db() as c:
                c.execute("UPDATE vps SET mining_flag=0 WHERE vps_id=?", (vps_id,))
            
            await ix.edit_original_response(embed=em(
                "✅ Clean",
                f"**{vps_id}** shows no signs of mining activity.\n"
                f"CPU Usage: {results['cpu_usage']}%\n"
                f"Memory Usage: {results['mem_usage']}%",
                GREEN
            ))
    except Exception as e:
        await ix.edit_original_response(embed=em("❌ Error", str(e), RED))


@bot.tree.command(name="mining-stats", description="[Admin] View anti-mining statistics.")
async def cmd_mining_stats(ix: discord.Interaction):
    await ix.response.defer(ephemeral=True)
    if not is_admin(ix):
        return await ix.followup.send(embed=em("⛔ Forbidden", "Admin only.", RED))
    
    with get_db() as c:
        total = c.execute("SELECT COUNT(*) AS n FROM vps").fetchone()["n"]
        running = c.execute("SELECT COUNT(*) AS n FROM vps WHERE status='running'").fetchone()["n"]
        suspended = c.execute("SELECT COUNT(*) AS n FROM vps WHERE status='suspended'").fetchone()["n"]
        mining_detected = c.execute("SELECT COUNT(*) AS n FROM vps WHERE mining_flag=1").fetchone()["n"]
        mining_logs = c.execute("SELECT COUNT(*) AS n FROM mining_logs").fetchone()["n"]
        unresolved = c.execute("SELECT COUNT(*) AS n FROM mining_logs WHERE resolved=0").fetchone()["n"]
    
    await ix.followup.send(embed=em(
        "📊 Anti-Mining Statistics",
        f"**Status:** {'🟢 Enabled' if ANTI_MINING_ENABLED else '🔴 Disabled'}\n\n"
        f"**VPS Statistics:**\n"
        f"• Total VPS: {total}\n"
        f"• Running VPS: {running}\n"
        f"• Suspended VPS: {suspended}\n"
        f"• Mining Detected: {mining_detected}\n\n"
        f"**Mining Logs:**\n"
        f"• Total Logs: {mining_logs}\n"
        f"• Unresolved: {unresolved}\n\n"
        f"**Configuration:**\n"
        f"• CPU Threshold: {ANTI_MINING_CPU_THRESHOLD}%\n"
        f"• Memory Threshold: {ANTI_MINING_MEMORY_THRESHOLD}%\n"
        f"• Check Interval: {ANTI_MINING_CHECK_INTERVAL // 60} minutes\n"
        f"• Auto-Suspend: {'✅' if ANTI_MINING_SUSPEND_ON_DETECT else '❌'}\n"
        f"• Admin Notifications: {'✅' if ANTI_MINING_NOTIFY_ADMIN else '❌'}\n\n"
        f"**⚠️ Note:** Suspended VPS may also be due to expiry.",
        BLUE
    ))


@bot.tree.command(name="toggle-mining", description="[Admin] Enable or disable anti-mining protection.")
@app_commands.describe(enabled="Enable or disable anti-mining")
async def cmd_toggle_mining(ix: discord.Interaction, enabled: bool):
    await ix.response.defer(ephemeral=True)
    if not is_admin(ix):
        return await ix.followup.send(embed=em("⛔ Forbidden", "Admin only.", RED))
    
    global ANTI_MINING_ENABLED
    ANTI_MINING_ENABLED = enabled
    
    if enabled:
        if not anti_mining_scan.is_running():
            anti_mining_scan.start()
        await ix.followup.send(embed=em("✅ Anti-Mining Enabled", "Protection is now active.", GREEN))
    else:
        if anti_mining_scan.is_running():
            anti_mining_scan.stop()
        await ix.followup.send(embed=em("⏹️ Anti-Mining Disabled", "Protection is now inactive.", YELLOW))


@bot.tree.command(name="mining-logs", description="[Admin] View recent mining detection logs.")
async def cmd_mining_logs(ix: discord.Interaction):
    await ix.response.defer(ephemeral=True)
    if not is_admin(ix):
        return await ix.followup.send(embed=em("⛔ Forbidden", "Admin only.", RED))
    
    with get_db() as c:
        rows = c.execute("""
            SELECT * FROM mining_logs 
            ORDER BY detected_at DESC 
            LIMIT 20
        """).fetchall()
    
    if not rows:
        return await ix.followup.send(embed=em("📋 Mining Logs", "No mining detections logged.", BLUE))
    
    fields = []
    for r in rows:
        line = (f"**VPS:** {r['vps_id']}\n"
                f"**CPU:** {r['cpu_usage']}% | **MEM:** {r['mem_usage']}%\n"
                f"**Action:** {r['action_taken']}\n"
                f"**Status:** {'✅ Resolved' if r['resolved'] else '⚠️ Unresolved'}")
        fields.append((f"<t:{int(datetime.datetime.fromisoformat(r['detected_at']).timestamp())}:R>", line, False))
    
    await ix.followup.send(embed=em(f"📋 Mining Logs ({len(rows)})", "", BLUE, fields=fields))


@bot.tree.command(name="resolve-mining", description="[Admin] Mark a mining detection as resolved.")
@app_commands.describe(log_id="The log ID to mark as resolved")
async def cmd_resolve_mining(ix: discord.Interaction, log_id: int):
    await ix.response.defer(ephemeral=True)
    if not is_admin(ix):
        return await ix.followup.send(embed=em("⛔ Forbidden", "Admin only.", RED))
    
    with get_db() as c:
        row = c.execute("SELECT * FROM mining_logs WHERE id=?", (log_id,)).fetchone()
        if not row:
            return await ix.followup.send(embed=em("❌ Not Found", f"Log ID **{log_id}** not found.", RED))
        
        c.execute("UPDATE mining_logs SET resolved=1 WHERE id=?", (log_id,))
    
    await ix.followup.send(embed=em(
        "✅ Resolved",
        f"Mining log **{log_id}** for VPS **{row['vps_id']}** marked as resolved.",
        GREEN
    ))


# ══════════════════════════════════════════════
# NODE MANAGEMENT
# ══════════════════════════════════════════════
@bot.tree.command(name="node-create", description="[Admin] Register a new node.")
@app_commands.describe(name="Unique name for this node, e.g. Node1")
async def cmd_node_create(ix: discord.Interaction, name: str):
    await ix.response.defer(ephemeral=True)
    if not is_admin(ix): return await ix.followup.send(embed=em("⛔ Forbidden", "Admin only.", RED))
    name = name.strip()
    if not name or "|" in name:
        return await ix.followup.send(embed=em("❌ Invalid", "Name can't be empty or contain `|`.", RED))
    token = secrets.token_urlsafe(24)
    try:
        with get_db() as c:
            c.execute("INSERT INTO nodes (node_id, token, created_by) VALUES (?,?,?)",
                      (name, token, ix.user.id))
    except sqlite3.IntegrityError:
        return await ix.followup.send(embed=em("❌ Already Exists", f"A node named **{name}** already exists.", RED))
    await ix.followup.send(embed=em(
        "✅ Node Registered",
        f"Node **{name}** created (currently 🔴 offline).\n"
        f"Run `/node-config name:{name}` to get its install + connect command.",
        GREEN,
    ))


@bot.tree.command(name="node-config", description="[Admin] Get the install/connect command for a node.")
@app_commands.describe(name="Node to configure")
@app_commands.autocomplete(name=existing_node_autocomplete)
async def cmd_node_config(ix: discord.Interaction, name: str):
    await ix.response.defer(ephemeral=True)
    if not is_admin(ix): return await ix.followup.send(embed=em("⛔ Forbidden", "Admin only.", RED))
    with get_db() as c:
        row = c.execute("SELECT * FROM nodes WHERE node_id=?", (name,)).fetchone()
    if not row:
        return await ix.followup.send(embed=em("❌ Not Found", f"No node named **{name}**.", RED))

    install_cmd = (
        "curl -o node_agent.py "
        "https://raw.githubusercontent.com/atifqmi-max/vpsbot-v4/main/node_agent.py "
        "&& python3 node_agent.py"
    )
    connect_str = f"{row['node_id']}|{row['token']}|{SERVER_IP}|{AGENT_PORT}"

    await ix.followup.send(embed=em(
        f"🔗 Connect Node — {name}",
        "**Step 1.** On the new server, run this to install the agent:\n"
        f"```bash\n{install_cmd}\n```\n"
        "**Step 2.** From the menu that appears, choose **1) Install VPS Bot** "
        "first (one-time, sets up LXC).\n\n"
        "**Step 3.** Run the script again, choose **3) Connect NODE**, and paste this "
        "when it asks for the connect string:\n"
        f"```\n{connect_str}\n```\n"
        "As soon as it connects you'll see it go 🟢 online in `/node-list`.",
        BLUE,
    ))


@bot.tree.command(name="node-list", description="[Admin] List all nodes and their status.")
async def cmd_node_list(ix: discord.Interaction):
    await ix.response.defer(ephemeral=True)
    if not is_admin(ix): return await ix.followup.send(embed=em("⛔ Forbidden", "Admin only.", RED))
    with get_db() as c:
        rows = c.execute("SELECT * FROM nodes ORDER BY node_id").fetchall()
        vps_counts = {r["node_id"]: r["n"] for r in c.execute(
            "SELECT node_id, COUNT(*) AS n FROM vps WHERE node_id IS NOT NULL GROUP BY node_id"
        ).fetchall()}
        local_count = c.execute(
            "SELECT COUNT(*) AS n FROM vps WHERE node_id IS NULL"
        ).fetchone()["n"]

    lines = [f"🏠 **Local (this server)** — {local_count} VPS"]
    for r in rows:
        dot = "🟢 online" if node_is_online(r["node_id"]) else "🔴 offline"
        lines.append(
            f"**{r['node_id']}** — {dot} — {vps_counts.get(r['node_id'], 0)} VPS"
            + (f" — `{r['public_ip']}`" if r["public_ip"] else "")
        )
    await ix.followup.send(embed=em("📡 Nodes", "\n".join(lines), BLUE))


@bot.tree.command(name="node-delete", description="[Admin] Delete a node.")
@app_commands.describe(name="Node to delete")
@app_commands.autocomplete(name=existing_node_autocomplete)
async def cmd_node_delete(ix: discord.Interaction, name: str):
    await ix.response.defer(ephemeral=True)
    if not is_admin(ix): return await ix.followup.send(embed=em("⛔ Forbidden", "Admin only.", RED))
    with get_db() as c:
        row = c.execute("SELECT * FROM nodes WHERE node_id=?", (name,)).fetchone()
        if not row:
            return await ix.followup.send(embed=em("❌ Not Found", f"No node named **{name}**.", RED))
        still_used = c.execute(
            "SELECT COUNT(*) AS n FROM vps WHERE node_id=? AND status!='deleted'", (name,)
        ).fetchone()["n"]
        if still_used:
            return await ix.followup.send(embed=em(
                "❌ Node In Use",
                f"**{name}** still has {still_used} VPS on it. Remove or migrate them first "
                f"with `/remove-vps`.", RED))
        c.execute("DELETE FROM nodes WHERE node_id=?", (name,))
    ws = NODE_CONNECTIONS.pop(name, None)
    if ws:
        try: await ws.close()
        except Exception: pass
    await ix.followup.send(embed=em("🗑 Node Deleted", f"**{name}** has been removed.", YELLOW))


@bot.tree.command(name="ptero-status", description="[Admin] Pterodactyl panel status.")
async def cmd_ptero(ix: discord.Interaction):
    await ix.response.defer(ephemeral=True)
    if not is_admin(ix): return await ix.followup.send(embed=em("⛔ Forbidden", "Admin only.", RED))
    if not PTERO_ON:
        return await ix.followup.send(embed=em("🦅 Not Configured",
            "Add `PTERO_URL` and `PTERO_API_KEY` to .env", YELLOW))
    s = ptero_check()
    if s["ok"]:
        try:
            nodes = ptero_get("nodes")
            nl = "\n".join(
                f"• **{n['attributes']['name']}** — `{n['attributes']['fqdn']}`"
                for n in nodes.get("data", [])
            ) or "No nodes."
        except Exception: nl = "Could not fetch nodes."
        await ix.followup.send(embed=em("🦅 Pterodactyl — Connected",
            f"Panel: `{PTERO_URL}`", GREEN, fields=[("Nodes", nl, False)]))
    else:
        await ix.followup.send(embed=em("🦅 Pterodactyl — Error",
            f"Panel: `{PTERO_URL}`\n```{s.get('error','Unknown')}```", RED))

# ══════════════════════════════════════════════
# 1-CLICK DEPLOY
# ══════════════════════════════════════════════

class DeployModal(discord.ui.Modal, title="🐉 NETHOST — Deploy VPS"):
    ram  = discord.ui.TextInput(
        label="RAM (MB)", 
        placeholder="32768",
        default="32768",
        min_length=1, 
        max_length=7
    )
    cpu  = discord.ui.TextInput(
        label="CPU Cores", 
        placeholder="4",    
        default="4",   
        min_length=1, 
        max_length=5
    )
    disk = discord.ui.TextInput(
        label="Disk (GB)", 
        placeholder="80",   
        default="80",  
        min_length=1, 
        max_length=5
    )
    days = discord.ui.TextInput(
        label="Auto-Suspend After Days (0=never)", 
        placeholder="0", 
        default="0", 
        min_length=1, 
        max_length=4
    )

    def __init__(self, target: discord.Member, os_key: str, cpu_key: str, node_id: str = None):
        super().__init__()
        self.target  = target
        self.os_key  = os_key
        self.cpu_key = cpu_key
        self.node_id = node_id

    async def on_submit(self, ix: discord.Interaction):
        await ix.response.defer(ephemeral=True)
        try:
            ram  = int(self.ram.value.strip())
            cpu  = float(self.cpu.value.strip())
            disk = int(self.disk.value.strip())
            days = int(self.days.value.strip())
        except ValueError:
            return await ix.followup.send(embed=em("❌ Invalid", "All fields must be numbers.", RED))
        
        if ram < 1024:
            return await ix.followup.send(embed=em("❌ Invalid", "RAM must be at least 1024 MB (1 GB).", RED))
        if cpu < 0.5:
            return await ix.followup.send(embed=em("❌ Invalid", "CPU must be at least 0.5 cores.", RED))
        if disk < 5:
            return await ix.followup.send(embed=em("❌ Invalid", "Disk must be at least 5 GB.", RED))
            
        await do_create(ix, self.target, ram, cpu, disk, self.os_key, self.cpu_key, days, self.node_id)


class OSView(discord.ui.View):
    def __init__(self, target: discord.Member):
        super().__init__(timeout=120)
        self.target = target

    async def pick(self, ix: discord.Interaction, key: str):
        if not is_admin(ix):
            return await ix.response.send_message(embed=em("⛔ Forbidden", "Admin only.", RED), ephemeral=True)
        _, label = LXC_IMAGES[key]
        await ix.response.edit_message(
            embed=em(
                "🐉 Deploy — Step 2/4", 
                f"**OS:** {label}\n\n"
                f"**Default Specs:**\n"
                f"• RAM: 32 GB (32768 MB)\n"
                f"• CPU: 4 Cores\n"
                f"• Disk: 80 GB\n\n"
                f"Choose **CPU** model:",
                BLUE
            ),
            view=CPUView(self.target, key),
        )

    @discord.ui.button(label="Ubuntu 20.04", style=discord.ButtonStyle.secondary, emoji="🐧", row=0)
    async def u20(self, ix, b): await self.pick(ix, "ubuntu20")
    @discord.ui.button(label="Ubuntu 22.04", style=discord.ButtonStyle.secondary, emoji="🐧", row=0)
    async def u22(self, ix, b): await self.pick(ix, "ubuntu22")
    @discord.ui.button(label="Ubuntu 24.04", style=discord.ButtonStyle.primary,   emoji="🐧", row=0)
    async def u24(self, ix, b): await self.pick(ix, "ubuntu24")
    @discord.ui.button(label="Debian 11",    style=discord.ButtonStyle.secondary, emoji="🌀", row=1)
    async def d11(self, ix, b): await self.pick(ix, "debian11")
    @discord.ui.button(label="Debian 12",    style=discord.ButtonStyle.primary,   emoji="🌀", row=1)
    async def d12(self, ix, b): await self.pick(ix, "debian12")
    @discord.ui.button(label="Cancel",       style=discord.ButtonStyle.danger,    emoji="✖️", row=1)
    async def cancel(self, ix: discord.Interaction, b):
        await ix.response.edit_message(embed=em("❌ Cancelled", "Deployment cancelled.", RED), view=None)


class CPUView(discord.ui.View):
    def __init__(self, target: discord.Member, os_key: str):
        super().__init__(timeout=120)
        self.target = target
        self.os_key = os_key

    async def pick(self, ix: discord.Interaction, key: str):
        if not is_admin(ix):
            return await ix.response.send_message(embed=em("⛔ Forbidden", "Admin only.", RED), ephemeral=True)
        await ix.response.edit_message(
            embed=em(
                "🐉 Deploy — Step 3/4", 
                f"**CPU Model:** {CPU_MAP[key]}\n\n"
                f"**Default Specs:**\n"
                f"• RAM: 32 GB (32768 MB)\n"
                f"• CPU: 4 Cores\n"
                f"• Disk: 80 GB\n\n"
                f"Choose which **node** to deploy this VPS on:",
                BLUE
            ),
            view=NodeView(self.target, self.os_key, key),
        )

    @discord.ui.button(label="AMD Ryzen 9 9950X",        style=discord.ButtonStyle.danger,   emoji="🔴", row=0)
    async def ryzen(self, ix, b): await self.pick(ix, "ryzen9")
    @discord.ui.button(label="Intel Xeon Platinum 8480+", style=discord.ButtonStyle.primary,  emoji="🔵", row=0)
    async def xeon(self, ix, b):  await self.pick(ix, "xeon")
    @discord.ui.button(label="◀ Back",  style=discord.ButtonStyle.secondary, row=1)
    async def back(self, ix: discord.Interaction, b):
        await ix.response.edit_message(
            embed=em("🐉 Deploy — Step 1/4",
                     f"Deploying for **{self.target.display_name}**\n\n"
                     f"**Default Specs:**\n"
                     f"• RAM: 32 GB (32768 MB)\n"
                     f"• CPU: 4 Cores\n"
                     f"• Disk: 80 GB\n\n"
                     f"Choose **OS**:", 
                     BLUE),
            view=OSView(self.target),
        )
    @discord.ui.button(label="Cancel", style=discord.ButtonStyle.danger, emoji="✖️", row=1)
    async def cancel(self, ix: discord.Interaction, b):
        await ix.response.edit_message(embed=em("❌ Cancelled", "Deployment cancelled.", RED), view=None)


class NodeSelect(discord.ui.Select):
    def __init__(self, target: discord.Member, os_key: str, cpu_key: str):
        self.target, self.os_key, self.cpu_key = target, os_key, cpu_key
        with get_db() as c:
            rows = c.execute("SELECT node_id, status FROM nodes").fetchall()
        options = [discord.SelectOption(label="Local (this server)", value="local", emoji="🏠", default=True)]
        for r in rows:
            options.append(discord.SelectOption(
                label=r["node_id"],
                value=r["node_id"],
                emoji="🟢" if r["status"] == "online" else "🔴",
                description="Online" if r["status"] == "online" else "Offline — cannot deploy here",
            ))
        super().__init__(placeholder="Select a node...", options=options[:25])

    async def callback(self, ix: discord.Interaction):
        if not is_admin(ix):
            return await ix.response.send_message(embed=em("⛔ Forbidden", "Admin only.", RED), ephemeral=True)
        chosen = self.values[0]
        node_id = None if chosen == "local" else chosen
        if node_id and not node_is_online(node_id):
            return await ix.response.send_message(
                embed=em("❌ Node Offline", f"**{node_id}** is offline right now. Pick another node.", RED),
                ephemeral=True)
        await ix.response.send_modal(DeployModal(self.target, self.os_key, self.cpu_key, node_id))


class NodeView(discord.ui.View):
    def __init__(self, target: discord.Member, os_key: str, cpu_key: str):
        super().__init__(timeout=120)
        self.add_item(NodeSelect(target, os_key, cpu_key))

    @discord.ui.button(label="◀ Back", style=discord.ButtonStyle.secondary, row=1)
    async def back(self, ix: discord.Interaction, b):
        os_key = self.children[0].os_key
        target = self.children[0].target
        await ix.response.edit_message(
            embed=em("🐉 Deploy — Step 2/4", 
                     f"**Default Specs:**\n"
                     f"• RAM: 32 GB (32768 MB)\n"
                     f"• CPU: 4 Cores\n"
                     f"• Disk: 80 GB\n\n"
                     f"Choose **CPU**:", 
                     BLUE),
            view=CPUView(target, os_key),
        )
    @discord.ui.button(label="Cancel", style=discord.ButtonStyle.danger, emoji="✖️", row=1)
    async def cancel(self, ix: discord.Interaction, b):
        await ix.response.edit_message(embed=em("❌ Cancelled", "Deployment cancelled.", RED), view=None)


@bot.tree.command(name="deploy", description="[Admin] 1-click VPS deploy with 32GB RAM, 4 CPU, 80GB Disk defaults.")
@app_commands.describe(user="User to deploy VPS for")
async def cmd_deploy(ix: discord.Interaction, user: discord.Member):
    if not is_admin(ix):
        return await ix.response.send_message(embed=em("⛔ Forbidden", "Admin only.", RED), ephemeral=True)
    
    await ix.response.send_message(
        embed=em(
            "🐉 Deploy — Step 1/4",
            f"Deploying for **{user.display_name}** ({user.mention})\n\n"
            f"**Default Specs:**\n"
            f"• RAM: 32 GB (32768 MB)\n"
            f"• CPU: 4 Cores\n"
            f"• Disk: 80 GB\n\n"
            f"⚠️ **1 VPS limit** — user can only have 1 VPS at a time.\n\n"
            f"Choose **OS**:",
            BLUE
        ),
        view=OSView(user), 
        ephemeral=True,
    )

# ─────────────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────────────
if __name__ == "__main__":
    if not DISCORD_TOKEN:
        log.critical("DISCORD_TOKEN not set in .env!")
        raise SystemExit(1)
    if not PTERO_ON:
        log.warning("Pterodactyl not configured — running without panel integration.")
    else:
        log.info(f"Pterodactyl enabled — {PTERO_URL}")
    
    try:
        subprocess.run(["lxc", "version"], capture_output=True, check=True)
        log.info("LXC is installed and ready.")
    except:
        log.critical("LXC is not installed! Please install LXC first:")
        log.critical("  sudo apt-get install lxc lxc-templates")
        raise SystemExit(1)
    
    init_db()
    log.info("Starting NETHOST VPS Manager (LXC) with Anti-Mining...")
    bot.run(DISCORD_TOKEN, log_handler=None)

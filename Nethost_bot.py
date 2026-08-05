"""
╔═══════════════════════════════════════════════════════╗
║           NETHOST VPS Manager Bot                  ║
║  Server: 180GB RAM | 94 Core CPU | Docker + systemd  ║
║  • Docker-in-Docker VPS containers                   ║
║  • Full systemctl support                            ║
║  • Direct root SSH (IP:port + password)              ║
║  • tmate SSH as backup access                        ║
║  • Fake neofetch specs                               ║
║  • Pterodactyl Panel + Wings                         ║
║  • 1-click deploy                                    ║
╚═══════════════════════════════════════════════════════╝
"""

import os
import secrets, io, time, socket, random, string, secrets, uuid, tarfile, asyncio, logging, sqlite3, datetime
import discord, docker, psutil, requests, aiohttp
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
# Set this in your .env, e.g. SERVER_IP=13.200.235.136
SERVER_IP      = os.getenv("SERVER_IP", "127.0.0.1")
SSH_PORT_START = int(os.getenv("SSH_PORT_START", "20000"))
SSH_PORT_END   = int(os.getenv("SSH_PORT_END", "29999"))

# Port the built-in node-agent WebSocket server listens on.
# Remote nodes connect OUTBOUND to ws://SERVER_IP:AGENT_PORT/agent/ws
# Open this port in your firewall (same as the SSH port range).
AGENT_PORT = int(os.getenv("AGENT_PORT", "8788"))

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
# OS + CPU
# ─────────────────────────────────────────────────────
# Using jrei/systemd images — pre-built for systemd inside Docker
# These support systemctl, services, cron out of the box
OS_MAP = {
    "ubuntu20": ("jrei/systemd-ubuntu:20.04", "Ubuntu 20.04"),
    "ubuntu22": ("jrei/systemd-ubuntu:22.04", "Ubuntu 22.04"),
    "ubuntu24": ("jrei/systemd-ubuntu:24.04", "Ubuntu 24.04"),
    "debian11":  ("jrei/systemd-debian:11",   "Debian 11"),
    "debian12":  ("jrei/systemd-debian:12",   "Debian 12"),
}
CPU_MAP = {
    "ryzen9": "AMD Ryzen 9 9950X 16-Core Processor",
    "xeon":   "Intel(R) Xeon(R) Platinum 8480+ @ 3.80GHz",
}

DB_FILE = "NETHOST.db"

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
        """)
        # Backfill columns for DBs created before this update
        cols = {row["name"] for row in c.execute("PRAGMA table_info(vps)").fetchall()}
        for col, ddl in [
            ("ssh_ip",    "ALTER TABLE vps ADD COLUMN ssh_ip TEXT DEFAULT ''"),
            ("ssh_port",  "ALTER TABLE vps ADD COLUMN ssh_port INTEGER DEFAULT NULL"),
            ("root_pass", "ALTER TABLE vps ADD COLUMN root_pass TEXT DEFAULT ''"),
            ("username",  "ALTER TABLE vps ADD COLUMN username TEXT DEFAULT 'root'"),
            ("node_id",   "ALTER TABLE vps ADD COLUMN node_id TEXT DEFAULT NULL"),
        ]:
            if col not in cols:
                c.execute(ddl)
    log.info("Database ready.")

# ─────────────────────────────────────────────────────
# PORT + PASSWORD HELPERS
# ─────────────────────────────────────────────────────
def _port_in_use_locally(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.3)
        return s.connect_ex(("127.0.0.1", port)) == 0

def find_free_port() -> int:
    """Pick a host port not already assigned to another VPS and not in use."""
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
    """Like find_free_port(), but for a remote node — we can't locally
    bind-test a port on another machine, so we only avoid collisions
    with ports we've already handed out on that same node."""
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
def get_docker():
    try:
        client = docker.from_env()
        client.ping()
        return client
    except FileNotFoundError:
        raise RuntimeError(
            "Docker socket not found!\n"
            "Run: `sudo systemctl start docker`"
        )
    except docker.errors.DockerException as e:
        raise RuntimeError(f"Docker error: {e}\nRun: `sudo systemctl start docker`")

def is_admin(ix: discord.Interaction) -> bool:
    with get_db() as c:
        row = c.execute(
            "SELECT user_id FROM admins WHERE user_id=?",
            (ix.user.id,)
        ).fetchone()

    return row is not None

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
    init_db()
    log.info("Starting NETHOST VPS Manager...")
    bot.run(DISCORD_TOKEN, log_handler=None)



@bot.tree.command(name="deploy", description="Deploy your free VPS (1 per user).")
@app_commands.describe(os="Choose your operating system")
@app_commands.choices(os=[
    app_commands.Choice(name="Ubuntu", value="ubuntu"),
    app_commands.Choice(name="Debian", value="debian"),
    app_commands.Choice(name="Alpine", value="alpine"),
    app_commands.Choice(name="CentOS", value="centos"),
])
async def cmd_deploy(ix: discord.Interaction, os: app_commands.Choice[str]):
    await ix.response.defer(ephemeral=True)

    with get_db() as c:
        existing = c.execute(
            "SELECT vps_id FROM vps WHERE owner_id=?",
            (ix.user.id,)
        ).fetchone()

    if existing:
        return await ix.followup.send(
            embed=em(
                "⚠️ Already Has VPS",
                f"You already own a VPS: `{existing['vps_id']}`",
                YELLOW
            )
        )

    ram = 32
    cpu = 4
    disk = 80
    os_name = os.value
    days = 30

    try:
        vps_id = gen_vps_id()

        container = create_vps_container(vps_id, ram, cpu, disk, os_name)

        expires = (datetime.utcnow() + timedelta(days=days)).isoformat()

        with get_db() as c:
            c.execute(
                """INSERT INTO vps
                (vps_id, owner_id, container_id, ptero_id, ram, cpu, disk, os_name, status, expires_at, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'running', ?, ?)
                """,
                (
                    vps_id,
                    ix.user.id,
                    container.id,
                    None,
                    ram,
                    cpu,
                    disk,
                    os_name,
                    expires,
                    datetime.utcnow().isoformat()
                )
            )
            c.commit()

        await ix.followup.send(
            embed=em(
                "🚀 VPS Deployed",
                f"**Owner:** {ix.user.mention}\n"
                f"**VPS ID:** `{vps_id}`\n"
                f"**OS:** `{os_name}`\n"
                f"**RAM:** `32 GB`\n"
                f"**CPU:** `4 vCore`\n"
                f"**Disk:** `80 GB`\n"
                f"**Expires:** <t:{int(datetime.fromisoformat(expires).timestamp())}:R>",
                GREEN
            )
        )

    except Exception as e:
        log.exception("Deploy failed")
        await ix.followup.send(
            embed=em("❌ Deploy Failed", f"```{e}```", RED)
        )


@bot.tree.command(name="regen-ssh", description="Regenerate SSH password for your VPS.")
@app_commands.describe(vps_id="Your VPS ID")
async def cmd_regen_ssh(ix: discord.Interaction, vps_id: str):
    await ix.response.defer(ephemeral=True)

    vps_id = vps_id.lower()

    # Get VPS
    with get_db() as c:
        row = c.execute(
            "SELECT * FROM vps WHERE vps_id=?",
            (vps_id,)
        ).fetchone()

    if not row:
        return await ix.followup.send(
            embed=em("❌ VPS Not Found", "That VPS does not exist.", RED)
        )

    # Allow owner OR admin
    if row["owner_id"] != ix.user.id and not is_admin(ix):
        return await ix.followup.send(
            embed=em("❌ Access Denied", "That VPS doesn't belong to you.", RED)
        )

    try:
        new_pass = secrets.token_urlsafe(12)

        container = get_docker().containers.get(row["container_id"])

        # Change root password
        container.exec_run(
            f"bash -c \"echo 'root:{new_pass}' | chpasswd\""
        )

        # Save new password
        with get_db() as c:
            c.execute(
                "UPDATE vps SET ssh_password=? WHERE vps_id=?",
                (new_pass, vps_id)
            )
            c.commit()

        await ix.followup.send(
            embed=em(
                "🔑 SSH Password Regenerated",
                f"**VPS:** `{vps_id}`\n"
                f"**New SSH Password:** `{new_pass}`",
                GREEN
            )
        )

    except Exception as e:
        log.exception("SSH regen failed")
        await ix.followup.send(
            embed=em("❌ Regen Failed", f"```{e}```", RED)
        )

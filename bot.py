# bot.py - VulnsBot con NVD (NIST) + Emojis solo en Discord
import os, json, asyncio, logging
from pathlib import Path
from datetime import datetime
import aiohttp
from aiohttp import web
import discord
from discord.ext import commands, tasks
from dotenv import load_dotenv

load_dotenv()
TOKEN = os.getenv("DISCORD_TOKEN")
CHANNEL_ID = int(os.getenv("CHANNEL_ID", "0"))
POLL_INTERVAL = int(os.getenv("POLL_INTERVAL", "120"))
MIN_CVSS = float(os.getenv("MIN_CVSS", "5.0"))
NVD_API_KEY = os.getenv("NVD_API_KEY")
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
HOST = os.getenv("HOST", "0.0.0.0")
PORT = int(os.getenv("PORT", "8000"))

logging.basicConfig(level=LOG_LEVEL, format="%(asctime)s - %(levelname)s - %(message)s")
log = logging.getLogger("VulnsBot")

SEEN_FILE = Path("seen_cves.json")

def load_seen():
    if SEEN_FILE.exists():
        try:
            return set(json.loads(SEEN_FILE.read_text()))
        except Exception:
            return set()
    return set()

def save_seen(data):
    SEEN_FILE.write_text(json.dumps(list(data)))

seen = load_seen()

intents = discord.Intents.default()
intents.message_content = True
bot = commands.Bot(command_prefix="!", intents=intents)

async def fetch_latest_cves():
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {"resultsPerPage": 20}
    headers = {"User-Agent": "VulnsBot/2.0"}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY
        log.info("Usando API Key de NVD")

    for attempt in range(3):
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, params=params, headers=headers, timeout=30) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        vulns = data.get("vulnerabilities", [])
                        log.info(f"NVD respondió: {len(vulns)} CVEs obtenidas")
                        return convert_nvd_format(vulns)
                    else:
                        log.warning(f"HTTP {resp.status} desde NVD, intento {attempt+1}/3")
                        await asyncio.sleep(5 * (attempt + 1))
        except Exception as e:
            log.error(f"Error consultando NVD (intento {attempt + 1}/3): {e}")
            await asyncio.sleep(5)
    return []

def convert_nvd_format(vulns):
    converted = []
    for v in vulns:
        cve = v.get("cve", {})
        metrics = cve.get("metrics", {})
        cvss = 0
        vector = "N/A"
        if "cvssMetricV31" in metrics and metrics["cvssMetricV31"]:
            cvss_data = metrics["cvssMetricV31"][0].get("cvssData", {})
            cvss = cvss_data.get("baseScore", 0)
            vector = cvss_data.get("vectorString", "N/A")
        elif "cvssMetricV30" in metrics and metrics["cvssMetricV30"]:
            cvss_data = metrics["cvssMetricV30"][0].get("cvssData", {})
            cvss = cvss_data.get("baseScore", 0)
            vector = cvss_data.get("vectorString", "N/A")
        elif "cvssMetricV2" in metrics and metrics["cvssMetricV2"]:
            cvss = metrics["cvssMetricV2"][0].get("cvssData", {}).get("baseScore", 0)

        summary = next(
            (d.get("value") for d in cve.get("descriptions", []) if d.get("lang") == "en"),
            "Sin descripción disponible"
        )

        refs = cve.get("references", [])
        ref_links = [r.get("url") for r in refs[:3] if r.get("url")]

        converted.append({
            "id": cve.get("id"),
            "summary": summary,
            "cvss3": cvss,
            "cvss_vector": vector,
            "Published": cve.get("published", ""),
            "references": ref_links
        })
    return converted

def make_embed(cve):
    cve_id = cve.get("id", "CVE-DESCONOCIDA")
    cvss = float(cve.get("cvss3") or 0)
    summary = cve.get("summary", "Sin descripción disponible")

    # 🔥 Emojis solo en Discord (no en terminal)
    if cvss >= 9.0:
        emoji, severity, color = "💀", "CRITICAL", 0xDC143C
    elif cvss >= 7.0:
        emoji, severity, color = "⚠️", "HIGH", 0xFF6B35
    elif cvss >= 4.0:
        emoji, severity, color = "🟡", "MEDIUM", 0xFFB200
    else:
        emoji, severity, color = "🟢", "LOW", 0x2ECC71

    embed = discord.Embed(
        title=f"{emoji} {cve_id} • {severity}",
        description=f"```{summary[:1900]}```",
        url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        color=color,
        timestamp=datetime.utcnow(),
    )

    embed.add_field(name="Severidad", value=f"**{severity}**\n`{cvss}/10.0`", inline=True)
    if vector := cve.get("cvss_vector"):
        embed.add_field(name="Vector CVSS", value=f"`{vector}`", inline=True)
    if pub := cve.get("Published"):
        embed.add_field(name="Publicado", value=f"`{pub[:10]}`", inline=True)
    if refs := cve.get("references"):
        links = "\n".join([f"[Referencia {i+1}]({url})" for i, url in enumerate(refs[:2])])
        embed.add_field(name="Referencias", value=links, inline=False)

    # Mensaje de cierre decorativo
    embed.set_footer(text=f"Fuente: NIST NVD • {emoji} {severity}")
    return embed

@tasks.loop(seconds=POLL_INTERVAL)
async def poll_cves():
    await bot.wait_until_ready()
    channel = bot.get_channel(CHANNEL_ID)
    if not channel:
        log.warning("Canal no encontrado, revisa el CHANNEL_ID.")
        return

    log.info("Consultando NVD por nuevas CVEs...")
    data = await fetch_latest_cves()
    if not data:
        log.warning("No se recibieron CVEs nuevas.")
        return

    new_cves = [cve for cve in data if cve.get("id") not in seen]
    if not new_cves:
        log.info("No hay nuevas CVEs desde la última consulta.")
        return

    for cve in reversed(new_cves):
        cve_id = cve.get("id")
        if not cve_id:
            continue
        seen.add(cve_id)
        cvss = float(cve.get("cvss3") or 0)
        if cvss >= MIN_CVSS:
            try:
                await channel.send(embed=make_embed(cve))
                log.info(f"Publicado: {cve_id} (CVSS {cvss})")
                await asyncio.sleep(2)
            except Exception as e:
                log.error(f"Error enviando CVE {cve_id}: {e}")

    save_seen(seen)
    log.info(f"{len(new_cves)} CVEs procesadas y guardadas")

@bot.event
async def on_ready():
    log.info(f"Conectado como {bot.user}")
    if not poll_cves.is_running():
        poll_cves.start()
        log.info("Monitoreo automático iniciado.")

async def health(request):
    return web.json_response({
        "status": "ok",
        "bot_name": str(bot.user),
        "cves_tracked": len(seen),
        "source": "NIST NVD",
        "interval": POLL_INTERVAL
    })

async def run_health_server():
    app = web.Application()
    app.router.add_get("/health", health)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, HOST, PORT)
    await site.start()
    log.info(f"Healthcheck en http://{HOST}:{PORT}/health")

async def main():
    await run_health_server()
    await bot.start(TOKEN)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        log.info("Bot detenido manualmente.")
    except Exception as e:
        log.error(f"Error fatal: {e}")

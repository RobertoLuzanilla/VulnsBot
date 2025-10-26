# VulnsBot

VulnsBot es un bot de Discord que monitorea vulnerabilidades (CVEs) en tiempo real utilizando la base de datos oficial del **NVD (National Vulnerability Database)**.
Publica las vulnerabilidades nuevas en un canal de Discord con información detallada, incluyendo su severidad (CVSS), vector de ataque y enlaces de referencia.

![Ejemplo_del_bot(/Ejemplo.png)]

---

## Características principales

* Consulta automática de vulnerabilidades recientes desde la API de NVD.
* Clasificación por nivel de severidad (Critical, High, Medium, Low).
* Comando para buscar CVEs específicas por palabra clave.
* Filtro configurable por puntaje CVSS mínimo.
* Sistema que evita publicar CVEs repetidas.
* Healthcheck HTTP para verificar el estado del bot.

---

## Requisitos

* Python 3.10 o superior.
* Una cuenta de Discord y acceso al **Portal de Desarrolladores de Discord**.
* Una API Key válida de [NVD (NIST)](https://nvd.nist.gov/developers/vulnerabilities).
* Librerías instaladas desde `requirements.txt`.

Instalación de dependencias:

```bash
pip install -r requirements.txt
```

---

## Configuración del bot en Discord

1. Ingresa al [Portal de Desarrolladores de Discord](https://discord.com/developers/applications).
2. Haz clic en **"New Application"** y ponle el nombre `VulnsBot` (o el que prefieras).
3. En el panel izquierdo, entra a **Bot → Add Bot**.
4. Copia el **token** del bot (este se colocará en tu archivo `.env`).
5. En la misma sección, activa las siguientes opciones:

   * **MESSAGE CONTENT INTENT**
   * **SERVER MEMBERS INTENT** (opcional, pero recomendable)
6. En **OAuth2 → URL Generator**, marca:

   * `bot`
   * En “Bot Permissions”, selecciona:

     * `Read Messages / View Channels`
     * `Send Messages`
     * `Embed Links`
     * `Read Message History`
7. Copia la URL generada, pégala en tu navegador e invita el bot a tu servidor.

Después de esto, tu bot estará listo para conectarse.

---

## Configuración del entorno

Crea un archivo `.env` en la raíz del proyecto con el siguiente contenido:

```bash
DISCORD_TOKEN=tu_token_de_discord
CHANNEL_ID=123456789012345678
NVD_API_KEY=tu_api_key_de_nvd
POLL_INTERVAL=120
MIN_CVSS=5.0
HOST=0.0.0.0
PORT=8000
LOG_LEVEL=INFO
```

---

## Ejecución

Ejecuta el bot con:

```bash
python bot.py
```

El bot se conectará automáticamente al canal especificado y comenzará a monitorear nuevas vulnerabilidades del NVD.

---

## Comandos disponibles

| Comando             | Descripción                                                                                               |
| ------------------- | --------------------------------------------------------------------------------------------------------- |
| `!buscar <palabra>` | Busca CVEs que coincidan con la palabra clave especificada.                                               |
| `!stats`            | Muestra estadísticas básicas del bot, como CVEs rastreadas, intervalo de actualización y fuente de datos. |

---

## Estructura del proyecto

```
vulnsbot/
│
├── bot.py
├── .env.example
├── .gitignore
├── README.md
├── requirements.txt
└── seen_cves.json
```

---

## Licencia

Este proyecto está disponible bajo la licencia **MIT**.
Puedes usarlo, modificarlo o distribuirlo libremente, siempre que se mantenga la atribución al autor original.



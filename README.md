# ytdlptgbot

> ⚠️ **AI-Generated Code Notice**: This project was generated using AI assistance. While it has been reviewed for functionality, please exercise caution and review the code thoroughly before deploying in production environments.

A Telegram bot that automatically downloads media from various platforms using yt-dlp and sends it back to the chat. Supports popular platforms like YouTube, Instagram, TikTok, Facebook, and many more.

## 🚀 Features

- 🔒 Secure access control with whitelist for users and groups
- 📥 Support for multiple platforms (YouTube, Instagram, Twitter, TikTok, etc.)
- 📊 Real-time download progress with emoji status updates
- 🔄 Automatic yt-dlp updates
- 💾 Persistent session storage
- 🐳 Docker support
- ⚙️ Flexible configuration through environment variables
- 🔐 Strict input validation and sanitization
- 🧹 Automatic cleanup of temporary files
- ⏱️ Configurable timeouts and retries
- 🛑 Rate limiting to prevent abuse
- 📝 Comprehensive logging system

## 📋 Requirements

- Docker and Docker Compose
- Python 3.11+
- FFmpeg
- Telegram Bot Token (from @BotFather)

## 🚀 Quick Start

1. Clone the repository:
```bash
git clone https://github.com/yourusername/ytdlptg.git
cd ytdlptg
```

2. Copy the example files:
```bash
cp docker-compose.example.yml docker-compose.yml
cp .env.example .env
```

3. Edit the `.env` file with your values:
```env
# Required values - Get these from https://my.telegram.org
TELEGRAM_API_ID=your_api_id
TELEGRAM_API_HASH=your_api_hash

# Required values - Get this from @BotFather
BOT_TOKEN=your_bot_token

# Required values - Your Telegram user ID and group IDs
ALLOWED_USERIDS=123456789,987654321  # Comma-separated list of user IDs
ADMIN_USERIDS=123456789              # Comma-separated list of admin user IDs
ALLOWED_GROUPIDS=-1001234567890      # Comma-separated list of group IDs
```

4. Configure WireGuard:
   - Create a `wireguard` directory
   - Copy the example configuration:
     ```bash
     cp wireguard/wireproxy.conf.example wireguard/wireproxy.conf
     ```
   - Edit `wireguard/wireproxy.conf`:
     - Replace the [Interface] and [Peer] sections with your actual WireGuard configuration
     - Keep the [Socks5] section as is
   - ⚠️ **Important**: Make sure to keep the `[Socks5]` section in your wireproxy.conf file, as it's required for the proxy to work. The bot uses `socks5://wireproxy:1080` as the proxy address.

5. Start the bot:
```bash
docker compose up -d --build
```

That's it! The bot should now be running. You can check the logs with:
```bash
docker compose logs -f
```

## ⚙️ Environment Variables

### Basic Configuration
| Variable | Default | Description |
|----------|---------|-------------|
| `API_ID` | 6 | Telegram API ID (Android default) |
| `API_HASH` | eb06d4abfb49dc3eeb1aeb98ae0f581e | Telegram API Hash (Android default) |
| `BOT_TOKEN` | - | Telegram Bot Token (required) |
| `ALLOWED_USERIDS` | - | Comma-separated list of authorized user IDs (required) |
| `ADMIN_USERIDS` | - | Comma-separated list of admin user IDs |
| `ALLOWED_GROUPIDS` | - | Comma-separated list of authorized group IDs |
| `MAX_CONCURRENT_DOWNLOADS` | 3 | Maximum number of concurrent downloads |
| `MAX_FILE_SIZE` | 2147483648 | Maximum file size in bytes (default 2GB) |
| `SUPPORTED_SITES` | - | Comma-separated list of supported sites (if empty, uses all) |

### Download Settings
| Variable | Default | Description |
|----------|---------|-------------|
| `MAX_URL_LENGTH` | 2048 | Maximum allowed URL length |
| `MAX_FILENAME_LENGTH` | 255 | Maximum allowed filename length |
| `DOWNLOAD_TIMEOUT` | 300 | Maximum download time in seconds (5 minutes) |
| `SOCKET_TIMEOUT` | 30 | Socket timeout in seconds |
| `MAX_RETRIES` | 3 | Maximum number of download retries |
| `ALLOWED_EXTENSIONS` | mp4,webm,mkv,mp3,m4a,jpg,jpeg,png,gif | Comma-separated list of allowed file extensions |
| `STRICT_URL_VALIDATION` | true | Enable strict URL validation |
| `SANITIZE_FILENAMES` | true | Enable filename sanitization |

### Rate Limiting Settings
| Variable | Default | Description |
|----------|---------|-------------|
| `RATE_LIMIT_ENABLED` | true | Enable rate limiting |
| `RATE_LIMIT_PERIOD` | 3600 | Time period for rate limiting in seconds (1 hour) |
| `RATE_LIMIT_MAX_REQUESTS` | 10 | Maximum requests per period for normal users |
| `RATE_LIMIT_ADMIN_PERIOD` | 3600 | Time period for admin rate limiting in seconds |
| `RATE_LIMIT_ADMIN_MAX_REQUESTS` | 50 | Maximum requests per period for admin users |
| `RATE_LIMIT_COOLDOWN` | 300 | Cooldown period in seconds after limit exceeded (5 minutes) |

### Logging Settings
| Variable | Default | Description |
|----------|---------|-------------|
| `LOG_LEVEL` | INFO | Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL) |
| `LOG_FORMAT` | %(asctime)s - %(name)s - %(levelname)s - %(message)s | Log message format |

The bot uses Docker's built-in logging system. Logs are sent to stdout/stderr and can be viewed using Docker's logging commands. This approach:
- Integrates with Docker's logging drivers
- Allows easy log aggregation
- Supports log rotation
- Enables log forwarding to external systems
- Provides consistent logging across containers

## 📝 Configuration Examples

### Basic Configuration
```env
BOT_TOKEN=123456789:ABCdefGHIjklMNOpqrsTUVwxyz
ALLOWED_USERIDS=123456789,987654321
```

### Full Configuration with Security and Rate Limiting
```env
API_ID=6
API_HASH=eb06d4abfb49dc3eeb1aeb98ae0f581e
BOT_TOKEN=123456789:ABCdefGHIjklMNOpqrsTUVwxyz
ALLOWED_USERIDS=123456789,987654321
ADMIN_USERIDS=123456789
ALLOWED_GROUPIDS=-1001234567890
MAX_CONCURRENT_DOWNLOADS=3
MAX_FILE_SIZE=2147483648
SUPPORTED_SITES=youtube,instagram,tiktok,facebook

# Download Settings
MAX_URL_LENGTH=2048
MAX_FILENAME_LENGTH=255
DOWNLOAD_TIMEOUT=300
SOCKET_TIMEOUT=30
MAX_RETRIES=3
ALLOWED_EXTENSIONS=mp4,webm,mkv,mp3,m4a,jpg,jpeg,png,gif
STRICT_URL_VALIDATION=true
SANITIZE_FILENAMES=true

# Rate Limiting Settings
RATE_LIMIT_ENABLED=true
RATE_LIMIT_PERIOD=3600
RATE_LIMIT_MAX_REQUESTS=10
RATE_LIMIT_ADMIN_PERIOD=3600
RATE_LIMIT_ADMIN_MAX_REQUESTS=50
RATE_LIMIT_COOLDOWN=300
```

## 🎯 Usage

1. Start the bot with `/start`
2. Send a link from a supported platform
3. The bot will download and send the media to the chat 🤯
4. Send memes to your frindz

### Available Commands

- `/start` - Start the bot and show information
- `/help` - Show help message (is the same duh)

## 🔒 """Security""" Features

Plz don't trust slop AI, it's just a bot for memes

### Multi-layer Security Implementation
1. **Input Validation Layer**
   - URL format and length validation
   - Strict domain checking
   - Character sanitization
   - Extension validation

2. **Download Security Layer**
   - Secure temporary directory creation
   - File size verification
   - Safe yt-dlp configuration
   - No shell execution
   - Timeout and retry limits

3. **File Handling Layer**
   - Filename sanitization
   - Extension whitelisting
   - Path traversal prevention
   - Secure file operations

4. **Resource Management Layer**
   - Automatic cleanup of temporary files
   - Secure file deletion

5. **Access Control Layer**
   - User whitelisting
   - Group restrictions
   - Admin privileges
   - Rate limiting
   - Concurrent download limits

### Rate Limiting
- Configurable limits for normal users and admins
- Automatic cooldown period after limit exceeded
- Per-user request tracking
- Informative messages about remaining time
- Admin users have higher limits

### Additional Security Measures
- No shell command execution
- Secure temporary file handling
- Automatic cleanup of sensitive data
- Strict input validation
- Resource usage limits
- Comprehensive error handling
- Detailed security logging

## 🐳 Docker Deployment

### Resource Limits
The container has the following resource limits:
```yaml
services:
  bot:
    mem_limit: 2g
    mem_reservation: 512m
    cpus: 2
```

### Maintenance

#### Update
```bash
# Pull latest changes
git pull

# Rebuild and restart
docker compose up -d --build
```

#### Update yt-dlp
Updating yt-dlp might break functionality as some sites might stop working or change their behavior. Only update if you're experiencing issues with specific sites.

```bash
# Update to latest yt-dlp version
./update_ytdlp.sh

# Rebuild container
docker compose up -d --build
```

#### Cleanup
```bash
# Stop and remove containers
docker compose down

# Clean unused images
docker system prune
```

## 📚 Supported Platforms

The bot supports all platforms supported by yt-dlp, including:

- YouTube
- Instagram
- Twitter
- TikTok
- Facebook
- Reddit
- Pinterest
- Tumblr
- VK
- OK.ru
- Dailymotion
- Vimeo
- SoundCloud
- Twitch
- Bilibili
- LinkedIn
- And many more!

## ⚠️ Notes

- The bot requires at least one authorized user or group
- Maximum file size is limited to 2GB (Telegram limit)
- Files are automatically deleted after sending
- All """security""" features are enabled by default
- Rate limiting is enabled by default to prevent abuse

## 🐛 Bug Reports

If you find a bug:
- First, try to debug it yourself - the code is open source!
- Open an Issue with detailed steps to reproduce
- Include logs and error messages
- Better yet, propose a fix with a Pull Request!

Remember: This is open source software. If you find a bug, you can help fix it!


import os
import logging
import asyncio
import yt_dlp
from telegram import Update
from telegram.ext import Application, CommandHandler, MessageHandler, filters, ContextTypes
from dotenv import load_dotenv
import re
from datetime import datetime, timedelta
from asyncio import Semaphore
import shutil
import tempfile
from urllib.parse import urlparse, urlunparse
import secrets
from typing import Optional, Tuple, List, Dict
import magic
from collections import defaultdict
import traceback
import sys

# Configure logging
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO if not os.getenv('ENABLE_DEBUG_LOGGING', 'false').lower() == 'true' else logging.DEBUG,
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

logging.getLogger('httpx').setLevel(logging.WARNING)
logging.getLogger('telegram').setLevel(logging.WARNING)
logging.getLogger('telegram.ext').setLevel(logging.WARNING)
logging.getLogger('aiohttp').setLevel(logging.WARNING)
logging.getLogger('asyncio').setLevel(logging.WARNING)

# Load environment variables
load_dotenv()

# Security constants
MAX_URL_LENGTH = int(os.getenv('MAX_URL_LENGTH', '2048'))
MAX_FILENAME_LENGTH = int(os.getenv('MAX_FILENAME_LENGTH', '255'))
DOWNLOAD_TIMEOUT = int(os.getenv('DOWNLOAD_TIMEOUT', '300'))  # 5 minutes
SOCKET_TIMEOUT = int(os.getenv('SOCKET_TIMEOUT', '30'))
MAX_RETRIES = int(os.getenv('MAX_RETRIES', '3'))
ALLOWED_EXTENSIONS = set(os.getenv('ALLOWED_EXTENSIONS', 'mp4,webm,mkv,mp3,m4a,jpg,jpeg,png,gif').split(','))
STRICT_URL_VALIDATION = os.getenv('STRICT_URL_VALIDATION', 'true').lower() == 'true'
SANITIZE_FILENAMES = os.getenv('SANITIZE_FILENAMES', 'true').lower() == 'true'
YTDLP_PROXY = os.getenv('YTDLP_PROXY', 'socks5://wireproxy:1080')

# Rate limiting settings
RATE_LIMIT_ENABLED = os.getenv('RATE_LIMIT_ENABLED', 'true').lower() == 'true'
RATE_LIMIT_PERIOD = int(os.getenv('RATE_LIMIT_PERIOD', '3600'))  # 1 hour
RATE_LIMIT_MAX_REQUESTS = int(os.getenv('RATE_LIMIT_MAX_REQUESTS', '10'))
RATE_LIMIT_ADMIN_PERIOD = int(os.getenv('RATE_LIMIT_ADMIN_PERIOD', '3600'))  # 1 hour
RATE_LIMIT_ADMIN_MAX_REQUESTS = int(os.getenv('RATE_LIMIT_ADMIN_MAX_REQUESTS', '50'))
RATE_LIMIT_COOLDOWN = int(os.getenv('RATE_LIMIT_COOLDOWN', '300'))  # 5 minutes

# Telegram configuration
BOT_TOKEN = os.getenv('BOT_TOKEN')
ALLOWED_USERIDS = set(map(int, os.getenv('ALLOWED_USERIDS', '').split(','))) if os.getenv('ALLOWED_USERIDS') else set()
ADMIN_USERIDS = set(map(int, os.getenv('ADMIN_USERIDS', '').split(','))) if os.getenv('ADMIN_USERIDS') else set()
ALLOWED_GROUPIDS = set(map(int, os.getenv('ALLOWED_GROUPIDS', '').split(','))) if os.getenv('ALLOWED_GROUPIDS') else set()
TELEGRAM_API_URL = os.getenv('TELEGRAM_API_URL', 'http://telegram-bot-api:8081')

# Constants
MAX_CONCURRENT_DOWNLOADS = int(os.getenv('MAX_CONCURRENT_DOWNLOADS', '3'))
MAX_FILE_SIZE = int(os.getenv('MAX_FILE_SIZE', '2147483648'))
DOWNLOAD_TIMEOUT = int(os.getenv('DOWNLOAD_TIMEOUT', '300'))  # 5 minutes
UPLOAD_TIMEOUT = int(os.getenv('UPLOAD_TIMEOUT', '1800'))  # 30 minutes
MAX_UPLOAD_RETRIES = int(os.getenv('MAX_UPLOAD_RETRIES', '3'))
DOWNLOAD_SEMAPHORE = Semaphore(MAX_CONCURRENT_DOWNLOADS)

# URL pattern for matching supported sites
URL_PATTERN = r'https?://(?:www\.)?(?:youtube\.com|youtu\.be|instagram\.com|twitter\.com|tiktok\.com|facebook\.com|reddit\.com|pinterest\.com|tumblr\.com|vk\.com|ok\.ru|dailymotion\.com|vimeo\.com|soundcloud\.com|twitch\.tv|bilibili\.com|linkedin\.com)/[^\s]*'

# Supported sites list
SUPPORTED_SITES = {
    'youtube', 'youtu.be', 'instagram', 'twitter', 'tiktok', 'facebook',
    'reddit', 'pinterest', 'tumblr', 'vk', 'ok.ru', 'dailymotion',
    'vimeo', 'soundcloud', 'twitch', 'bilibili', 'linkedin'
}

# Rate limiting storage
user_requests: Dict[int, List[datetime]] = defaultdict(list)
user_cooldowns: Dict[int, datetime] = {}

class SecurityError(Exception):
    """Base class for security-related exceptions."""
    pass

class URLValidationError(SecurityError):
    """Raised when URL validation fails."""
    pass

class FileValidationError(SecurityError):
    """Raised when file validation fails."""
    pass

class SecurityLayer:
    """Base class for security layers."""
    pass

class InputValidationLayer(SecurityLayer):
    """Handles input validation and sanitization."""
    
    @staticmethod
    def sanitize_url(url: str) -> str:
        """Sanitize and validate URL."""
        if len(url) > MAX_URL_LENGTH:
            raise URLValidationError(f"URL length exceeds maximum allowed length of {MAX_URL_LENGTH}")
        
        # Basic URL parsing
        try:
            parsed = urlparse(url)
            if not all([parsed.scheme, parsed.netloc]):
                raise URLValidationError("Invalid URL format")
            
            # Reconstruct URL with only allowed components
            sanitized = urlunparse((
                parsed.scheme,
                parsed.netloc,
                parsed.path,
                '',
                '',
                ''
            ))
            
            # Additional validation if strict mode is enabled
            if STRICT_URL_VALIDATION:
                if not re.match(r'^https?://', sanitized):
                    raise URLValidationError("URL must use HTTP/HTTPS protocol")
                
                # Check for potentially dangerous characters
                if any(c in sanitized for c in [';', '|', '&', '>', '<', '`', '$']):
                    raise URLValidationError("URL contains potentially dangerous characters")
            
            return sanitized
            
        except Exception as e:
            raise URLValidationError(f"URL validation failed: {str(e)}")

class FileSecurityLayer(SecurityLayer):
    """Handles file-related security measures."""
    
    @staticmethod
    def sanitize_filename(filename: str) -> str:
        """Sanitize filename to prevent path traversal and other attacks."""
        if not SANITIZE_FILENAMES:
            return filename
            
        # Remove any path components
        filename = os.path.basename(filename)
        
        # Remove any non-alphanumeric characters except for safe ones
        filename = re.sub(r'[^a-zA-Z0-9._-]', '', filename)
        
        # Truncate to maximum length
        if len(filename) > MAX_FILENAME_LENGTH:
            name, ext = os.path.splitext(filename)
            filename = name[:MAX_FILENAME_LENGTH-len(ext)] + ext
        
        return filename
    
    @staticmethod
    def is_safe_extension(filename: str) -> bool:
        """Check if file extension is in allowed list."""
        ext = os.path.splitext(filename)[1].lower().lstrip('.')
        return ext in ALLOWED_EXTENSIONS
    
    @staticmethod
    def create_secure_temp_dir() -> str:
        """Create a secure temporary directory with random name."""
        temp_dir = os.path.join(tempfile.gettempdir(), f'ytdl_{secrets.token_hex(16)}')
        os.makedirs(temp_dir, exist_ok=True)
        return temp_dir
    
    @staticmethod
    async def verify_file_type(file_path: str) -> bool:
        """Verify file type using python-magic."""
        try:
            mime = magic.Magic(mime=True)
            file_type = mime.from_file(file_path)
            
            # Map of allowed MIME types
            allowed_mimes = {
                'video/mp4': '.mp4',
                'video/webm': '.webm',
                'video/x-matroska': '.mkv',
                'audio/mpeg': '.mp3',
                'audio/mp4': '.m4a',
                'image/jpeg': '.jpg',
                'image/png': '.png',
                'image/gif': '.gif'
            }
            
            return file_type in allowed_mimes
        except Exception as e:
            logger.error(f"Error verifying file type: {e}")
            return False

class DownloadSecurityLayer(SecurityLayer):
    """Handles download-related security measures."""
    
    @staticmethod
    def get_safe_ydl_opts(temp_dir: str) -> dict:
        """Get safe yt-dlp options."""
        return {
            'format': f'bestvideo[ext=mp4][filesize<{MAX_FILE_SIZE}]+bestaudio[ext=m4a]/bestvideo[ext=mp4]+bestaudio/best[ext=mp4]/best[filesize<{MAX_FILE_SIZE}]',  # Best quality with size limit and MP4 preference
            'outtmpl': os.path.join(temp_dir, '%(title)s.%(ext)s'),
            'quiet': True,
            'no_warnings': True,
            'socket_timeout': SOCKET_TIMEOUT,
            'retries': MAX_RETRIES,
            'nocheckcertificate': False,
            'ignoreerrors': False,
            'no_color': True,
            'geo_bypass': False,
            'geo_verification_proxy': None,
            'source_address': None,
            'noplaylist': True,  # Prevent downloading entire playlists
            'playlist_items': '1',  # If it's a playlist, download only the first video
            'merge_output_format': 'mp4',  # Force MP4 output
            'postprocessors': [{
                'key': 'FFmpegVideoConvertor',
                'preferedformat': 'mp4',
            }],
            'ffmpeg_location': '/usr/bin/ffmpeg',  # Use full path to ffmpeg
            'http_headers': {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
            },
            'proxy': YTDLP_PROXY  # Use proxy from environment variable
        }
    
    @staticmethod
    async def check_file_size(url: str) -> Tuple[bool, int]:
        """Check if the file size is within limits."""
        try:
            ydl_opts = {
                'quiet': True,
                'no_warnings': True,
                'format': 'best',
            }
            with yt_dlp.YoutubeDL(ydl_opts) as ydl:
                info = ydl.extract_info(url, download=False)
                if 'filesize' in info:
                    file_size = info['filesize']
                    if file_size is not None and file_size > MAX_FILE_SIZE:
                        return False, info['filesize']
                elif 'filesize_approx' in info:
                    file_size_approx = info['filesize_approx']
                    if file_size_approx is not None and file_size_approx > MAX_FILE_SIZE:
                        return False, info['filesize_approx']
            return True, 0
        except Exception as e:
            logger.error(f"Error checking file size: {e}")
            return True, 0

class ResourceManagementLayer(SecurityLayer):
    """Handles resource management and cleanup."""
    
    @staticmethod
    async def cleanup_temp_dir(temp_dir: str):
        """Safely clean up temporary directory."""
        if temp_dir and os.path.exists(temp_dir):
            try:
                shutil.rmtree(temp_dir)
            except Exception as e:
                logger.error(f"Error cleaning up temporary directory: {e}")

class SecurityManager:
    """Manages all security layers."""
    
    def __init__(self):
        self.input_layer = InputValidationLayer()
        self.file_layer = FileSecurityLayer()
        self.download_layer = DownloadSecurityLayer()
        self.resource_layer = ResourceManagementLayer()
    
    async def validate_and_sanitize_url(self, url: str) -> str:
        """Validate and sanitize URL."""
        return self.input_layer.sanitize_url(url)
    
    async def prepare_download(self, url: str) -> Tuple[str, dict]:
        """Prepare for download with security checks."""
        # Validate URL
        sanitized_url = await self.validate_and_sanitize_url(url)
        
        # Check file size
        size_ok, file_size = await self.download_layer.check_file_size(sanitized_url)
        if not size_ok:
            raise FileValidationError(f"File too large ({file_size / (1024 * 1024 * 1024):.1f}GB)")
        
        # Create secure temp directory
        temp_dir = self.file_layer.create_secure_temp_dir()
        
        # Get safe yt-dlp options
        ydl_opts = self.download_layer.get_safe_ydl_opts(temp_dir)
        
        return temp_dir, ydl_opts
    
    async def validate_downloaded_file(self, file_path: str) -> bool:
        """Validate downloaded file."""
        # Check extension
        if not self.file_layer.is_safe_extension(file_path):
            raise FileValidationError("Unsupported file type")
        
        # Verify file type
        if not await self.file_layer.verify_file_type(file_path):
            raise FileValidationError("Invalid file type")
        
        return True

# Create security manager
security_manager = SecurityManager()

class RateLimitError(Exception):
    """Raised when rate limit is exceeded."""
    pass

def is_authorized(update: Update) -> bool:
    """Check if the user or group is authorized to use the bot."""
    user_id = update.effective_user.id
    chat_id = update.effective_chat.id
    
    # Check if user is in admin list
    if user_id in ADMIN_USERIDS:
        return True
    
    # Check if user is in allowed users list
    if user_id in ALLOWED_USERIDS:
        return True
    
    # Check if chat is in allowed groups list
    if chat_id in ALLOWED_GROUPIDS:
        return True
    
    return False

def is_admin(user_id: int) -> bool:
    """Check if the user is an admin."""
    return user_id in ADMIN_USERIDS

async def check_rate_limit(user_id: int) -> None:
    """Check if user has exceeded rate limits."""
    if not RATE_LIMIT_ENABLED:
        return
        
    now = datetime.now()
    
    # Check cooldown
    if user_id in user_cooldowns:
        cooldown_end = user_cooldowns[user_id]
        if now < cooldown_end:
            remaining = (cooldown_end - now).total_seconds()
            raise RateLimitError(f"⏳ Please wait {int(remaining)} seconds before making another request.")
    
    # Get user's request history
    requests = user_requests[user_id]
    
    # Remove old requests
    if is_admin(user_id):
        period = RATE_LIMIT_ADMIN_PERIOD
        max_requests = RATE_LIMIT_ADMIN_MAX_REQUESTS
    else:
        period = RATE_LIMIT_PERIOD
        max_requests = RATE_LIMIT_MAX_REQUESTS
    
    cutoff = now - timedelta(seconds=period)
    requests = [req for req in requests if req > cutoff]
    user_requests[user_id] = requests
    
    # Check if limit exceeded
    if len(requests) >= max_requests:
        # Set cooldown
        user_cooldowns[user_id] = now + timedelta(seconds=RATE_LIMIT_COOLDOWN)
        raise RateLimitError(f"⚠️ Rate limit exceeded. Please wait {RATE_LIMIT_COOLDOWN} seconds before making more requests.")
    
    # Add new request
    requests.append(now)

def format_bytes(byte_count: Optional[int]) -> str:
    """Format bytes into readable string (KB, MB, GB)."""
    if byte_count is None or byte_count < 0:
        return '0.00B'
    power = 1024
    n = 0
    power_labels = {0: '', 1: 'KB', 2: 'MB', 3: 'GB', 4: 'TB'}
    # Ensure byte_count is treated as a float for division
    f_byte_count = float(byte_count)
    while f_byte_count >= power and n < len(power_labels) - 1:
        f_byte_count /= power
        n += 1
    return f"{f_byte_count:.2f}{power_labels[n]}"

def format_duration(seconds: Optional[float]) -> str:
    """Format seconds into HH:MM:SS.
    
    Args:
        seconds: Duration in seconds (can be float or None)
        
    Returns:
        Formatted duration string or 'N/A'
    """
    if seconds is None or seconds <= 0:
        return 'N/A'
    seconds = int(seconds)
    hours = seconds // 3600
    minutes = (seconds % 3600) // 60
    seconds = seconds % 60
    if hours > 0:
        return f'{hours:02d}:{minutes:02d}:{seconds:02d}'
    return f'{minutes:02d}:{seconds:02d}'

class ProgressFile:
    def __init__(self, file_path: str, progress_message, total_size: int):
        self.file = open(file_path, 'rb')
        self.progress_message = progress_message
        self.total_size = total_size
        self.uploaded = 0
        self.last_update = datetime.now()
        self.update_interval = timedelta(seconds=3)  # Update every 3 seconds
        self.last_status_text = None

    def read(self, size=-1):
        chunk = self.file.read(size)
        if chunk:
            self.uploaded += len(chunk)
            now = datetime.now()
            if now - self.last_update >= self.update_interval:
                percentage = (self.uploaded / self.total_size) * 100
                status_text = (
                    f"📤 Uploading to Telegram...\n\n"
                    f"📊 Progress: {percentage:.1f}%\n"
                    f"📦 Uploaded: {format_bytes(self.uploaded)} of {format_bytes(self.total_size)}"
                )
                if status_text != self.last_status_text:
                    try:
                        asyncio.create_task(self.progress_message.edit_text(status_text))
                        self.last_status_text = status_text
                        self.last_update = now
                    except Exception as e:
                        if "Message is not modified" not in str(e):
                            logger.error(f"Error updating progress message: {e}")
        return chunk

    def seek(self, offset, whence=0):
        return self.file.seek(offset, whence)

    def tell(self):
        return self.file.tell()

    def close(self):
        return self.file.close()

async def stream_file(file_path: str, progress_message, total_size: int, chunk_size: int = 1024 * 1024):  # 1MB chunks
    """Stream file in chunks to avoid loading entire file in memory."""
    uploaded = 0
    last_update = datetime.now()
    update_interval = timedelta(seconds=3)  # Update every 3 seconds
    last_status_text = None

    with open(file_path, 'rb') as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            
            uploaded += len(chunk)
            now = datetime.now()
            if now - last_update >= update_interval:
                percentage = (uploaded / total_size) * 100
                status_text = (
                    f"📤 Uploading to Telegram...\n\n"
                    f"📊 Progress: {percentage:.1f}%\n"
                    f"📦 Uploaded: {format_bytes(uploaded)} of {format_bytes(total_size)}"
                )
                if status_text != last_status_text:
                    try:
                        await progress_message.edit_text(status_text)
                        last_status_text = status_text
                        last_update = now
                    except Exception as e:
                        if "Message is not modified" not in str(e):
                            logger.error(f"Error updating progress message: {e}")
            
            yield chunk

async def monitor_upload_progress(file_path: str, progress_message, total_size: int):
    """Monitor upload progress by checking file size changes."""
    uploaded = 0
    last_update = datetime.now()
    update_interval = timedelta(seconds=3)  # Update every 3 seconds
    last_status_text = None  # Track last status text to avoid duplicate updates
    
    while uploaded < total_size:
        try:
            # Get current file size
            current_size = os.path.getsize(file_path)
            if current_size > uploaded:
                uploaded = current_size
                now = datetime.now()
                if now - last_update >= update_interval:
                    percentage = (uploaded / total_size) * 100
                    status_text = (
                        f"📤 Uploading to Telegram...\n\n"
                        f"📊 Progress: {percentage:.1f}%\n"
                        f"📦 Uploaded: {format_bytes(uploaded)} of {format_bytes(total_size)}"
                    )
                    # Only update if status text has changed
                    if status_text != last_status_text:
                        try:
                            await progress_message.edit_text(status_text)
                            last_status_text = status_text
                            last_update = now
                        except Exception as e:
                            if "Message is not modified" not in str(e):
                                logger.error(f"Error updating progress message: {e}")
            await asyncio.sleep(0.1)  # Small delay to prevent high CPU usage
        except Exception as e:
            logger.error(f"Error monitoring upload progress: {e}")
            break

async def download_media(url: str, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Download media from URL and send it to the chat."""
    progress_message = None
    temp_dir = None
    user_id = update.effective_user.id
    chat_id = update.effective_chat.id
    
    logger.info(f"[DOWNLOAD_MEDIA] Starting download_media function for user {user_id} in chat {chat_id}")
    
    # Initialize variables to prevent unbound errors
    file_size_formatted = 'N/A'
    file_duration_formatted = 'N/A'
    download_time = timedelta(0)
    upload_time = timedelta(0)
    total_time = timedelta(0)
    file_format = 'N/A'
    quality = 'N/A'
    extension = 'N/A'
    resolution = 'N/A'
    download_success = False

    try:
        # Prepare download with security checks
        logger.info("[DOWNLOAD_MEDIA] Preparing download with security checks")
        temp_dir, ydl_opts = await security_manager.prepare_download(url)
        logger.info(f"[DOWNLOAD_MEDIA] Created temp directory: {temp_dir}")
        
        # Create progress message
        logger.info("[DOWNLOAD_MEDIA] Creating initial progress message")
        progress_message = await update.message.reply_text("🔄 Starting download...")
        logger.info(f"[DOWNLOAD_MEDIA] Starting download for user {user_id} in chat {chat_id}: {url}")
        
        # Acquire semaphore for concurrent download limit with timeout
        logger.info("[DOWNLOAD_MEDIA] Waiting for download semaphore")
        download_start_time = datetime.now()
        try:
            async with asyncio.timeout(DOWNLOAD_TIMEOUT):
                async with DOWNLOAD_SEMAPHORE:
                    logger.info("[DOWNLOAD_MEDIA] Acquired download semaphore")
                    
                    # Create a queue for progress updates
                    progress_queue = asyncio.Queue()
                    
                    # Initialize progress tracking variables
                    progress_state = {
                        'last_status_text': None,
                        'last_edit_time': datetime.now(),
                        'last_log_time': datetime.now(),
                        'edit_interval': timedelta(seconds=5),  # Increased from 3 to 5 seconds
                        'log_interval': timedelta(seconds=2),   # Increased from 1 to 2 seconds
                        'last_percent': 0,
                        'min_percent_change': 1.0  # Only update if progress changed by at least 1%
                    }

                    # Create an event loop for the progress hook
                    loop = asyncio.get_event_loop()
                    
                    def progress_hook(d):
                        try:
                            # Get total bytes if available
                            total_bytes = d.get('_total_bytes', 0)
                            total_bytes_estimate = d.get('_total_bytes_estimate', 0)
                            
                            # Use the first non-zero value
                            if total_bytes == 0 and total_bytes_estimate > 0:
                                d['_total_bytes'] = total_bytes_estimate
                            
                            # Use call_soon_threadsafe instead of run_coroutine_threadsafe
                            loop.call_soon_threadsafe(progress_queue.put_nowait, d)
                        except Exception as e:
                            logger.error(f"Error in progress hook: {e}")

                    async def process_progress():
                        while True:
                            try:
                                d = await progress_queue.get()
                                now = datetime.now()
                                
                                if d['status'] == 'downloading':
                                    total_bytes_str = d.get('_total_bytes_str', d.get('_total_bytes_estimate_str', 'N/A'))
                                    downloaded_bytes_str = d.get('_downloaded_bytes_str', 'N/A')
                                    speed = d.get('_speed_str', 'N/A')
                                    percent = d.get('_percent', 0)
                                    
                                    # Only update if enough time has passed and progress has changed significantly
                                    if (now - progress_state['last_edit_time'] > progress_state['edit_interval'] and 
                                        abs(percent - progress_state['last_percent']) >= progress_state['min_percent_change']):
                                        
                                        percent_str = d.get('_percent_str', 'N/A')
                                        status_text = (
                                            f"⏬ Downloading...\n\n"
                                            f"📊 Progress: {percent_str} ({downloaded_bytes_str} of {total_bytes_str})\n"
                                            f"🚀 Speed: {speed}"
                                        )

                                        if status_text != progress_state['last_status_text']:
                                            progress_state['last_status_text'] = status_text
                                            progress_state['last_percent'] = percent
                                            logger.debug(f"[PROGRESS_HOOK] Updating progress message: {status_text}")
                                            try:
                                                await progress_message.edit_text(status_text)
                                                progress_state['last_edit_time'] = now
                                            except Exception as e:
                                                if "flood" in str(e).lower():
                                                    # If we hit a flood wait, increase the interval
                                                    progress_state['edit_interval'] = timedelta(seconds=10)
                                                    logger.warning("Hit flood wait, increasing update interval")
                                                else:
                                                    logger.error(f"Error updating progress message: {e}")

                                    # Log less frequently
                                    if now - progress_state['last_log_time'] > progress_state['log_interval']:
                                        logger.info(f"[PROGRESS_HOOK] Download Progress: {percent}% ({downloaded_bytes_str} of {total_bytes_str})")
                                        progress_state['last_log_time'] = now
                                        
                                elif d['status'] == 'finished':
                                    status_text = "✅ Download completed! Processing..."
                                    if status_text != progress_state['last_status_text']:
                                        progress_state['last_status_text'] = status_text
                                        logger.debug("[PROGRESS_HOOK] Sending completion message")
                                        try:
                                            await progress_message.edit_text(status_text)
                                        except Exception as e:
                                            logger.error(f"Error sending completion message: {e}")
                                    logger.info(f"[PROGRESS_HOOK] Download completed for user {user_id} in chat {chat_id}")
                                    break
                                
                                progress_queue.task_done()
                            except Exception as e:
                                logger.error(f"Error processing progress update: {e}")
                                break

                    ydl_opts['progress_hooks'] = [progress_hook]

                    # Start progress processing task
                    progress_task = asyncio.create_task(process_progress())

                    try:
                        logger.info("[DOWNLOAD_MEDIA] Starting yt-dlp download")
                        with yt_dlp.YoutubeDL(ydl_opts) as ydl:
                            # First get info without downloading
                            logger.info("[DOWNLOAD_MEDIA] Getting video info")
                            info = await asyncio.to_thread(ydl.extract_info, url, download=False)
                            if info is None:
                                raise FileValidationError("Failed to extract video info")
                            
                            # Prepare the filename before downloading
                            downloaded_file = ydl.prepare_filename(info)
                            if not downloaded_file:
                                raise FileValidationError("Failed to prepare filename")
                            
                            # Now download with the info we have
                            logger.info("[DOWNLOAD_MEDIA] Starting download")
                            await context.bot.send_chat_action(chat_id=chat_id, action="upload_video")
                            await asyncio.to_thread(ydl.download, [url])
                            
                            # If the file doesn't exist, try to find it in the temp directory
                            if not os.path.exists(downloaded_file):
                                # Look for files in the temp directory
                                temp_files = [f for f in os.listdir(temp_dir) if os.path.isfile(os.path.join(temp_dir, f))]
                                if temp_files:
                                    downloaded_file = os.path.join(temp_dir, temp_files[0])
                                    logger.info(f"[DOWNLOAD_MEDIA] Found downloaded file in temp directory: {downloaded_file}")
                                else:
                                    raise FileValidationError(f"Downloaded file not found at {downloaded_file}")
                            
                            if os.path.getsize(downloaded_file) == 0:
                                raise FileValidationError("Downloaded file is empty")

                            download_success = True
                            download_end_time = datetime.now()
                            download_time = download_end_time - download_start_time
                            logger.info(f"[DOWNLOAD_MEDIA] Download completed in {download_time}")
                            logger.debug(f"[DOWNLOAD_MEDIA] Downloaded file path: {downloaded_file}")
                            logger.debug(f"[DOWNLOAD_MEDIA] File size: {os.path.getsize(downloaded_file)} bytes")

                    except Exception as e:
                        logger.error(f"[DOWNLOAD_MEDIA] Error during download: {str(e)}\n{traceback.format_exc()}")
                        if not download_success:
                            raise FileValidationError(f"Download failed: {str(e)}") from e
                        else:
                            logger.warning(f"[DOWNLOAD_MEDIA] Error after successful download: {str(e)}")
                            # Continue with the file we have since download was successful

                    # Validate downloaded file
                    if downloaded_file:
                        logger.info(f"[DOWNLOAD_MEDIA] Starting file validation for: {downloaded_file}")
                        # Execute file validation in a separate thread
                        is_file_valid = await security_manager.validate_downloaded_file(downloaded_file)
                        if not is_file_valid:
                            logger.error("[DOWNLOAD_MEDIA] File validation failed")
                            raise FileValidationError("File validation failed")
                        logger.info("[DOWNLOAD_MEDIA] File validation successful")

                        # Verify file exists and is readable before uploading
                        logger.info(f"[DOWNLOAD_MEDIA] Checking file existence and permissions for: {downloaded_file}")
                        # Execute existence and permissions checks in a separate thread
                        file_exists = await asyncio.to_thread(os.path.exists, downloaded_file)
                        if not file_exists:
                            logger.error(f"[DOWNLOAD_MEDIA] File not found at path: {downloaded_file}")
                            raise FileNotFoundError(f"Downloaded file not found at expected path: {downloaded_file}")
                        
                        has_read_access = await asyncio.to_thread(os.access, downloaded_file, os.R_OK)
                        if not has_read_access:
                            logger.error(f"[DOWNLOAD_MEDIA] No read access to file: {downloaded_file}")
                            raise PermissionError(f"Bot does not have read access to downloaded file: {downloaded_file}")
                        logger.info("[DOWNLOAD_MEDIA] File existence and permissions check passed")
                        
                        logger.info(f"[DOWNLOAD_MEDIA] Download and initial processing completed. Preparing for upload: {os.path.basename(downloaded_file)}")

                        # Update progress message to indicate upload is starting
                        logger.info("[DOWNLOAD_MEDIA] Updating progress message for upload start")
                        await progress_message.edit_text("📤 Uploading to Telegram...")
                        logger.info(f"[DOWNLOAD_MEDIA] Starting upload for user {user_id} in chat {chat_id}: {os.path.basename(downloaded_file)}")

                        # Upload the file with timeout
                        upload_start_time = datetime.now()
                        logger.info(f"[DOWNLOAD_MEDIA] Upload start time: {upload_start_time}")
                        
                        # Get file size in a separate thread
                        file_size_bytes = await asyncio.to_thread(os.path.getsize, downloaded_file)
                        logger.info(f"[DOWNLOAD_MEDIA] File size for upload: {format_bytes(file_size_bytes)}")
                        
                        try:
                            async with asyncio.timeout(UPLOAD_TIMEOUT):
                                logger.info("[DOWNLOAD_MEDIA] Sending file to Telegram")
                                
                                # Check if file is a video
                                mime = magic.Magic(mime=True)
                                file_type = mime.from_file(downloaded_file)
                                
                                # Start upload progress monitoring in background
                                monitor_task = asyncio.create_task(
                                    monitor_upload_progress(downloaded_file, progress_message, file_size_bytes)
                                )
                                
                                # Retry logic for upload
                                for attempt in range(MAX_UPLOAD_RETRIES):
                                    try:
                                        if file_type.startswith('video/'):
                                            logger.info(f"[DOWNLOAD_MEDIA] Sending as video (attempt {attempt + 1}/{MAX_UPLOAD_RETRIES})")
                                            await context.bot.send_chat_action(chat_id=chat_id, action="upload_video")
                                            try:
                                                await progress_message.edit_text("📤 Uploading video to Telegram...")
                                            except Exception as e:
                                                if "Message is not modified" not in str(e):
                                                    logger.error(f"Error updating progress message: {e}")
                                            
                                            # Use ProgressFile for video upload
                                            progress_file = ProgressFile(downloaded_file, progress_message, file_size_bytes)
                                            await context.bot.send_video(
                                                chat_id=chat_id,
                                                video=progress_file,
                                                filename=os.path.basename(downloaded_file),
                                                supports_streaming=True,
                                                read_timeout=UPLOAD_TIMEOUT,
                                                write_timeout=UPLOAD_TIMEOUT,
                                                connect_timeout=UPLOAD_TIMEOUT,
                                                pool_timeout=UPLOAD_TIMEOUT
                                            )
                                            progress_file.close()
                                        else:
                                            logger.info(f"[DOWNLOAD_MEDIA] Sending as document (attempt {attempt + 1}/{MAX_UPLOAD_RETRIES})")
                                            await context.bot.send_chat_action(chat_id=chat_id, action="upload_document")
                                            try:
                                                await progress_message.edit_text("📤 Uploading document to Telegram...")
                                            except Exception as e:
                                                if "Message is not modified" not in str(e):
                                                    logger.error(f"Error updating progress message: {e}")
                                            
                                            # Use ProgressFile for document upload
                                            progress_file = ProgressFile(downloaded_file, progress_message, file_size_bytes)
                                            await context.bot.send_document(
                                                chat_id=chat_id,
                                                document=progress_file,
                                                filename=os.path.basename(downloaded_file),
                                                read_timeout=UPLOAD_TIMEOUT,
                                                write_timeout=UPLOAD_TIMEOUT,
                                                connect_timeout=UPLOAD_TIMEOUT,
                                                pool_timeout=UPLOAD_TIMEOUT
                                            )
                                            progress_file.close()
                                        break  # If successful, break the retry loop
                                    except Exception as e:
                                        if attempt == MAX_UPLOAD_RETRIES - 1:  # Last attempt
                                            raise  # Re-raise the last exception
                                        logger.warning(f"[DOWNLOAD_MEDIA] Upload attempt {attempt + 1} failed: {e}")
                                        await asyncio.sleep(2 ** attempt)  # Exponential backoff
                                
                                # Cancel the monitor task after upload completes
                                monitor_task.cancel()
                                try:
                                    await monitor_task
                                except asyncio.CancelledError:
                                    pass
                            
                            logger.info(f"[DOWNLOAD_MEDIA] Upload completed for user {user_id} in chat {chat_id}")

                            # Update progress message to indicate completion
                            upload_end_time = datetime.now()
                            upload_time = upload_end_time - upload_start_time
                            logger.info(f"[DOWNLOAD_MEDIA] Upload completed in {upload_time}")

                            # Calculate total time
                            total_time = upload_end_time - download_start_time
                            logger.info(f"[DOWNLOAD_MEDIA] Total operation time: {total_time}")

                            # Extract more metadata if info is available
                            if info:
                                logger.debug("[DOWNLOAD_MEDIA] Extracting additional metadata")
                                file_format = info.get('format', 'N/A')
                                quality = info.get('format_note', 'N/A')
                                extension = info.get('ext', 'N/A')
                                resolution = info.get('resolution', 'N/A')
                                duration = info.get('duration', 0)
                                file_duration_formatted = format_duration(duration)
                                logger.info(f"[DOWNLOAD_MEDIA] Metadata - Format: {file_format}, Quality: {quality}, Extension: {extension}, Resolution: {resolution}, Duration: {file_duration_formatted}")

                            # Create the final message text with more details
                            final_message_text = (
                                f"✅ Done!\n\n"
                                f"📏 Size: {format_bytes(file_size_bytes)}\n"
                                f"⏳ Duration: {file_duration_formatted}\n"
                                f"⏱️ Download Time: {str(download_time).split('.')[0]}.{str(download_time).split('.')[1][:1]}s\n"
                                f"⏱️ Upload Time: {str(upload_time).split('.')[0]}.{str(upload_time).split('.')[1][:1]}s\n"
                                f"⏱️ Total Time: {str(total_time).split('.')[0]}.{str(total_time).split('.')[1][:1]}s\n"
                                f"📂 Format: {file_format} ({extension})\n"
                                f"💡 Quality: {quality}\n"
                                f"🖼️ Resolution: {resolution}"
                            )

                            logger.info("[DOWNLOAD_MEDIA] Sending final completion message")
                            await progress_message.edit_text(final_message_text)
                            logger.info(f"[DOWNLOAD_MEDIA] File successfully sent to user {user_id} in chat {chat_id}")
                        except asyncio.TimeoutError:
                            logger.error("[DOWNLOAD_MEDIA] Upload timed out")
                            await progress_message.edit_text("❌ Upload timed out. Please try again.")
                            raise
                        except Exception as e:
                            logger.error(f"[DOWNLOAD_MEDIA] Error during upload: {str(e)}\n{traceback.format_exc()}")
                            await progress_message.edit_text(f"❌ Upload failed: {str(e)}")
                            raise
                    else:
                        raise FileValidationError("No file was downloaded")

        except asyncio.TimeoutError:
            logger.error("[DOWNLOAD_MEDIA] Download timed out")
            await progress_message.edit_text("❌ Download timed out. Please try again.")
            raise
        except Exception as e:
            logger.error(f"[DOWNLOAD_MEDIA] Error during download process: {str(e)}\n{traceback.format_exc()}")
            await progress_message.edit_text(f"❌ Download failed: {str(e)}")
            raise

    except SecurityError as e:
        error_message = f"❌ Security Error: {str(e)}"
        logger.error(f"[DOWNLOAD_MEDIA] Security error for user {user_id} in chat {chat_id}: {error_message}\n{traceback.format_exc()}")
        if progress_message:
            await progress_message.edit_text(error_message)
        else:
            await update.message.reply_text(error_message)
    
    except Exception as e:
        is_admin = update.effective_user.id in ADMIN_USERIDS
        error_msg = f"Error: {str(e)}"
        logger.error(f"[DOWNLOAD_MEDIA] Error for user {update.effective_user.id}: {error_msg}\n{traceback.format_exc()}")

        if is_admin:
            traceback_text = traceback.format_exc()
            max_length = 4096 - len(error_msg) - 10
            if len(traceback_text) > max_length:
                traceback_text = traceback_text[:max_length-3] + "..."
            error_msg += f"\n\nTraceback:\n{traceback_text}"
        else:
            error_msg += "\n\nPlease try again later or contact an administrator if the problem persists."
        
        if len(error_msg) > 4096:
            error_msg = error_msg[:4093] + "..."

        await update.message.reply_text(error_msg)

    finally:
        # Clean up temporary directory
        if temp_dir:
            logger.info(f"[DOWNLOAD_MEDIA] Cleaning up temporary directory: {temp_dir}")
            await security_manager.resource_layer.cleanup_temp_dir(temp_dir)
            logger.info(f"[DOWNLOAD_MEDIA] Cleaned up temporary directory for user {user_id} in chat {chat_id}")

# New function to process and upload the downloaded file
async def process_and_upload_file(
    downloaded_file: Optional[str],
    info: Optional[dict],
    update: Update,
    context: ContextTypes.DEFAULT_TYPE,
    progress_message,
    temp_dir: str,
    download_start_time: datetime
):
    user_id = update.effective_user.id
    chat_id = update.effective_chat.id
    
    # Initialize variables to prevent unbound errors
    file_size_formatted = 'N/A'
    file_duration_formatted = 'N/A'
    download_time = datetime.now() - download_start_time # Calculate download time based on start
    upload_time = timedelta(0)
    total_time = timedelta(0)
    file_format = 'N/A'
    quality = 'N/A'
    extension = 'N/A'
    resolution = 'N/A'
    
    logger.info(f"[PROCESS_UPLOAD] Starting process_and_upload_file for user {user_id} in chat {chat_id}")

    try:
        # Validate downloaded file
        logger.info(f"[PROCESS_UPLOAD] Starting file validation for: {downloaded_file}")
        # Execute file validation in a separate thread
        is_file_valid = await asyncio.to_thread(security_manager.validate_downloaded_file, downloaded_file)
        if not downloaded_file or not is_file_valid:
            logger.error("[PROCESS_UPLOAD] File validation failed")
            raise FileValidationError("File validation failed")
        logger.info("[PROCESS_UPLOAD] File validation successful")

        # Verify file exists and is readable before uploading
        logger.info(f"[PROCESS_UPLOAD] Checking file existence and permissions for: {downloaded_file}")
        # Execute existence and permissions checks in a separate thread
        file_exists = await asyncio.to_thread(os.path.exists, downloaded_file)
        if not file_exists:
            logger.error(f"[PROCESS_UPLOAD] File not found at path: {downloaded_file}")
            raise FileNotFoundError(f"Downloaded file not found at expected path: {downloaded_file}")
        
        has_read_access = await asyncio.to_thread(os.access, downloaded_file, os.R_OK)
        if not has_read_access:
            logger.error(f"[PROCESS_UPLOAD] No read access to file: {downloaded_file}")
            raise PermissionError(f"Bot does not have read access to downloaded file: {downloaded_file}")
        logger.info("[PROCESS_UPLOAD] File existence and permissions check passed")
        
        logger.info(f"[PROCESS_UPLOAD] Download and initial processing completed. Preparing for upload: {os.path.basename(downloaded_file)}")

        # Update progress message to indicate upload is starting
        logger.info("[PROCESS_UPLOAD] Updating progress message for upload start")
        await progress_message.edit_text("📤 Uploading to Telegram...")
        logger.info(f"[PROCESS_UPLOAD] Starting upload for user {user_id} in chat {chat_id}: {os.path.basename(downloaded_file)}")

        # Upload the file with timeout
        upload_start_time = datetime.now()
        logger.info(f"[PROCESS_UPLOAD] Upload start time: {upload_start_time}")
        
        # Get file size in a separate thread
        file_size_bytes = await asyncio.to_thread(os.path.getsize, downloaded_file)
        logger.info(f"[PROCESS_UPLOAD] File size for upload: {format_bytes(file_size_bytes)}")
        
        try:
            async with asyncio.timeout(UPLOAD_TIMEOUT):
                logger.info("[PROCESS_UPLOAD] Sending file to Telegram")
                
                # Check if file is a video
                mime = magic.Magic(mime=True)
                file_type = mime.from_file(downloaded_file)
                
                if file_type.startswith('video/'):
                    logger.info("[PROCESS_UPLOAD] Sending as video")
                    await context.bot.send_chat_action(chat_id=chat_id, action="upload_video")
                    await context.bot.send_video(
                        chat_id=chat_id,
                        video=stream_file(downloaded_file, progress_message, file_size_bytes),
                        filename=os.path.basename(downloaded_file),
                        supports_streaming=True
                    )
                else:
                    logger.info("[PROCESS_UPLOAD] Sending as document")
                    await context.bot.send_chat_action(chat_id=chat_id, action="upload_document")
                    await context.bot.send_document(
                        chat_id=chat_id,
                        document=stream_file(downloaded_file, progress_message, file_size_bytes),
                        filename=os.path.basename(downloaded_file)
                    )
            
            logger.info(f"[PROCESS_UPLOAD] Upload completed for user {user_id} in chat {chat_id}")

            # Update progress message to indicate completion
            upload_end_time = datetime.now()
            upload_time = upload_end_time - upload_start_time
            logger.info(f"[PROCESS_UPLOAD] Upload completed in {upload_time}")

            # Calculate total time
            total_time = upload_end_time - download_start_time
            logger.info(f"[PROCESS_UPLOAD] Total operation time: {total_time}")

            # Extract more metadata if info is available
            if info:
                logger.debug("[PROCESS_UPLOAD] Extracting additional metadata")
                file_format = info.get('format', 'N/A')
                quality = info.get('format_note', 'N/A')
                extension = info.get('ext', 'N/A')
                resolution = info.get('resolution', 'N/A')
                duration = info.get('duration', 0)
                file_duration_formatted = format_duration(duration)
                logger.info(f"[PROCESS_UPLOAD] Metadata - Format: {file_format}, Quality: {quality}, Extension: {extension}, Resolution: {resolution}, Duration: {file_duration_formatted}")

            # Create the final message text with more details
            final_message_text = (
                f"✅ Done!\n\n"
                f"📏 Size: {format_bytes(file_size_bytes)}\n"
                f"⏳ Duration: {file_duration_formatted}\n"
                f"⏱️ Download Time: {str(download_time).split('.')[0]}.{str(download_time).split('.')[1][:1]}s\n"
                f"⏱️ Upload Time: {str(upload_time).split('.')[0]}.{str(upload_time).split('.')[1][:1]}s\n"
                f"⏱️ Total Time: {str(total_time).split('.')[0]}.{str(total_time).split('.')[1][:1]}s\n"
                f"📂 Format: {file_format} ({extension})\n"
                f"💡 Quality: {quality}\n"
                f"🖼️ Resolution: {resolution}"
            )

            logger.info("[PROCESS_UPLOAD] Sending final completion message")
            await progress_message.edit_text(final_message_text)
            logger.info(f"[PROCESS_UPLOAD] File successfully sent to user {user_id} in chat {chat_id}")
        except asyncio.TimeoutError:
            logger.error("[PROCESS_UPLOAD] Upload timed out")
            await progress_message.edit_text("❌ Upload timed out. Please try again.")
            raise
        except Exception as e:
            logger.error(f"[PROCESS_UPLOAD] Error during upload: {str(e)}\n{traceback.format_exc()}")
            await progress_message.edit_text(f"❌ Upload failed: {str(e)}")
            raise

    except SecurityError as e:
        error_message = f"❌ Security Error: {str(e)}"
        logger.error(f"[PROCESS_UPLOAD] Security error for user {user_id} in chat {chat_id}: {error_message}\n{traceback.format_exc()}")
        if progress_message:
            await progress_message.edit_text(error_message)
        else:
            await update.message.reply_text(error_message)
    
    except Exception as e:
        is_admin = update.effective_user.id in ADMIN_USERIDS
        error_msg = f"Error: {str(e)}"
        logger.error(f"[PROCESS_UPLOAD] Error for user {update.effective_user.id}: {error_msg}\n{traceback.format_exc()}")

        if is_admin:
            traceback_text = traceback.format_exc()
            max_length = 4096 - len(error_msg) - 10
            if len(traceback_text) > max_length:
                traceback_text = traceback_text[:max_length-3] + "..."
            error_msg += f"\n\nTraceback:\n{traceback_text}"
        else:
            error_msg += "\n\nPlease try again later or contact an administrator if the problem persists."
        
        if len(error_msg) > 4096:
            error_msg = error_msg[:4093] + "..."

        await update.message.reply_text(error_msg)

    finally:
        # Clean up temporary directory
        if temp_dir:
            logger.info(f"[PROCESS_UPLOAD] Cleaning up temporary directory: {temp_dir}")
            await security_manager.resource_layer.cleanup_temp_dir(temp_dir)
            logger.info(f"[PROCESS_UPLOAD] Cleaned up temporary directory for user {user_id} in chat {chat_id}")

async def handle_url(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle incoming messages with URLs."""
    user_id = update.effective_user.id
    chat_id = update.effective_chat.id
    url = update.message.text.strip()
    
    logger.info(f"User {user_id} in chat {chat_id} requested download of URL: {url}")
    
    if not is_authorized(update):
        logger.warning(f"Unauthorized access attempt by user {user_id} in chat {chat_id}")
        await update.message.reply_text("⛔ You are not authorized to use this bot.")
        return

    try:
        # Check rate limit
        await check_rate_limit(update.effective_user.id)
        # Start download in background task
        asyncio.create_task(download_media(url, update, context))
        
    except RateLimitError as e:
        logger.warning(f"Rate limit exceeded for user {user_id} in chat {chat_id}")
        await update.message.reply_text(str(e))
    except Exception as e:
        await handle_error(update, e)

async def start_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /start command."""
    user_id = update.effective_user.id
    chat_id = update.effective_chat.id
    
    logger.info(f"User {user_id} in chat {chat_id} issued /start command")
    
    if not is_authorized(update):
        logger.warning(f"Unauthorized access attempt by user {user_id} in chat {chat_id}")
        await update.message.reply_text("⛔ You are not authorized to use this bot.")
        return

    try:
        # Check rate limit
        await check_rate_limit(update.effective_user.id)
        
        # Create list of supported sites for display
        sorted_sites = sorted(SUPPORTED_SITES)
        if len(sorted_sites) > 20:
            # Show only first 20 sites and count of remaining
            supported_sites_list = "\n".join([f"• {site.capitalize()}" for site in sorted_sites[:20]])
            remaining_count = len(sorted_sites) - 20
            supported_sites_list += f"\n• ... and {remaining_count} more sites"
        else:
            supported_sites_list = "\n".join([f"• {site.capitalize()}" for site in sorted_sites])

        welcome_message = (
            "👋 Welcome to ytdlptgbot!\n\n"
            "📝 Just send me a link from any supported platform, and I'll download and send you the media.\n\n"
            "✅ Supported platforms:\n"
            f"{supported_sites_list}\n\n"
            f"⚠️ Note: Only authorized users can use this bot.\n"
            f"⚠️ Maximum file size: {MAX_FILE_SIZE / (1024 * 1024 * 1024):.1f}GB\n"
            f"⚠️ Maximum concurrent downloads: {MAX_CONCURRENT_DOWNLOADS}\n"
            f"⚠️ Rate limit: {RATE_LIMIT_MAX_REQUESTS} requests per {RATE_LIMIT_PERIOD/3600} hour(s)\n\n"
            "🔗 GitHub: https://github.com/davtur19/ytdlptgbot"
        )
        await update.message.reply_text(welcome_message)
        
    except RateLimitError as e:
        logger.warning(f"Rate limit exceeded for user {user_id} in chat {chat_id}")
        await update.message.reply_text(str(e))
    except Exception as e:
        await handle_error(update, e)

async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /help command."""
    user_id = update.effective_user.id
    chat_id = update.effective_chat.id
    
    logger.info(f"User {user_id} in chat {chat_id} issued /help command")
    
    if not is_authorized(update):
        logger.warning(f"Unauthorized access attempt by user {user_id} in chat {chat_id}")
        await update.message.reply_text("⛔ You are not authorized to use this bot.")
        return

    try:
        # Check rate limit
        await check_rate_limit(update.effective_user.id)
        
        # Create list of supported sites for display
        sorted_sites = sorted(SUPPORTED_SITES)
        if len(sorted_sites) > 20:
            # Show only first 20 sites and count of remaining
            supported_sites_list = "\n".join([f"• {site.capitalize()}" for site in sorted_sites[:20]])
            remaining_count = len(sorted_sites) - 20
            supported_sites_list += f"\n• ... and {remaining_count} more sites"
        else:
            supported_sites_list = "\n".join([f"• {site.capitalize()}" for site in sorted_sites])

        help_message = (
            "📚 Bot Commands:\n\n"
            "/start - Start the bot\n"
            "/help - Show this help message\n\n"
            "💡 Usage:\n"
            "Simply send a link from any supported platform, and I'll download and send you the media.\n\n"
            "✅ Supported platforms:\n"
            f"{supported_sites_list}\n\n"
            f"⚠️ Note: Only authorized users can use this bot.\n"
            f"⚠️ Maximum file size: {MAX_FILE_SIZE / (1024 * 1024 * 1024):.1f}GB\n"
            f"⚠️ Maximum concurrent downloads: {MAX_CONCURRENT_DOWNLOADS}\n"
            f"⚠️ Rate limit: {RATE_LIMIT_MAX_REQUESTS} requests per {RATE_LIMIT_PERIOD/3600} hour(s)"
        )
        await update.message.reply_text(help_message)
        
    except RateLimitError as e:
        logger.warning(f"Rate limit exceeded for user {user_id} in chat {chat_id}")
        await update.message.reply_text(str(e))
    except Exception as e:
        await handle_error(update, e)

async def handle_error(update: Update, error: Exception):
    """Handle errors in a consistent way."""
    is_admin = update.effective_user.id in ADMIN_USERIDS
    error_msg = f"Error: {str(error)}"
    logger.error(f"Error for user {update.effective_user.id}: {error_msg}\n{traceback.format_exc()}")

    if is_admin:
        traceback_text = traceback.format_exc()
        max_length = 4096 - len(error_msg) - 10
        if len(traceback_text) > max_length:
            traceback_text = traceback_text[:max_length-3] + "..."
        error_msg += f"\n\nTraceback:\n{traceback_text}"
    else:
        error_msg += "\n\nPlease try again later or contact an administrator if the problem persists."
    
    if len(error_msg) > 4096:
        error_msg = error_msg[:4093] + "..."

    await update.message.reply_text(error_msg)

async def unauthorized_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle messages from unauthorized users."""
    if not is_authorized(update):
        logger.warning(f"Unauthorized message from user {update.effective_user.id} in chat {update.effective_chat.id}")
        # Don't respond to avoid revealing bot presence to unauthorized users

def main() -> None:
    """Start the bot using polling."""
    # Check required environment variables
    if not BOT_TOKEN:
        logger.error("BOT_TOKEN environment variable is required!")
        sys.exit(1)

    # Check if any users are authorized
    if not ALLOWED_USERIDS and not ALLOWED_GROUPIDS:
        logger.error("No authorized users or groups configured! Please set ALLOWED_USERIDS or ALLOWED_GROUPIDS environment variables.")
        sys.exit(1)

    # Log configuration
    logger.info("Starting bot with configuration:")
    logger.info(f"BOT_TOKEN: {BOT_TOKEN[:4]}...{BOT_TOKEN[-4:]}")
    logger.info(f"ALLOWED_USERIDS: {ALLOWED_USERIDS}")
    logger.info(f"ADMIN_USERIDS: {ADMIN_USERIDS}")
    logger.info(f"ALLOWED_GROUPIDS: {ALLOWED_GROUPIDS}")
    logger.info(f"MAX_CONCURRENT_DOWNLOADS: {MAX_CONCURRENT_DOWNLOADS}")
    logger.info(f"MAX_FILE_SIZE: {MAX_FILE_SIZE / (1024 * 1024 * 1024):.1f}GB")
    logger.info(f"SUPPORTED_SITES: {', '.join(sorted(SUPPORTED_SITES))}")
    logger.info(f"TELEGRAM_API_URL: {TELEGRAM_API_URL}")
    
    # Log security settings
    logger.info("Security settings:")
    logger.info(f"MAX_URL_LENGTH: {MAX_URL_LENGTH}")
    logger.info(f"MAX_FILENAME_LENGTH: {MAX_FILENAME_LENGTH}")
    logger.info(f"DOWNLOAD_TIMEOUT: {DOWNLOAD_TIMEOUT}")
    logger.info(f"SOCKET_TIMEOUT: {SOCKET_TIMEOUT}")
    logger.info(f"MAX_RETRIES: {MAX_RETRIES}")
    logger.info(f"ALLOWED_EXTENSIONS: {', '.join(ALLOWED_EXTENSIONS)}")
    logger.info(f"STRICT_URL_VALIDATION: {STRICT_URL_VALIDATION}")
    logger.info(f"SANITIZE_FILENAMES: {SANITIZE_FILENAMES}")
    
    # Log rate limiting settings
    logger.info("Rate limiting settings:")
    logger.info(f"RATE_LIMIT_ENABLED: {RATE_LIMIT_ENABLED}")
    logger.info(f"RATE_LIMIT_PERIOD: {RATE_LIMIT_PERIOD}")
    logger.info(f"RATE_LIMIT_MAX_REQUESTS: {RATE_LIMIT_MAX_REQUESTS}")
    logger.info(f"RATE_LIMIT_ADMIN_PERIOD: {RATE_LIMIT_ADMIN_PERIOD}")
    logger.info(f"RATE_LIMIT_ADMIN_MAX_REQUESTS: {RATE_LIMIT_ADMIN_MAX_REQUESTS}")
    logger.info(f"RATE_LIMIT_COOLDOWN: {RATE_LIMIT_COOLDOWN}")

    # Create necessary directories
    os.makedirs('sessions', exist_ok=True)
    os.makedirs('downloads', exist_ok=True)

    # Create the Application and pass it your bot's token.
    application = Application.builder().token(BOT_TOKEN).base_url(TELEGRAM_API_URL).build()

    # Add handlers
    application.add_handler(CommandHandler("start", start_command))
    application.add_handler(CommandHandler("help", help_command))
    application.add_handler(MessageHandler(filters.Regex(URL_PATTERN), handle_url))
    
    # Add handlers for unauthorized messages
    application.add_handler(MessageHandler(filters.COMMAND, unauthorized_message))  # For any other command
    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, unauthorized_message))  # For text messages

    # Set bot commands using post_init
    async def post_init(application: Application) -> None:
        await application.bot.set_my_commands([
            ("start", "Start the bot"),
            ("help", "Show help message")
        ])
        logger.info("Bot commands set successfully")

    # Run the bot until the user presses Ctrl-C
    logger.info("Bot started...")
    application.post_init = post_init
    application.run_polling(allowed_updates=Update.ALL_TYPES)

if __name__ == '__main__':
    main() 
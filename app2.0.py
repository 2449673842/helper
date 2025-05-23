from flask import Flask, request, jsonify, send_from_directory, after_this_request
from flask_cors import CORS
import os
import re
import requests
import time
import shutil  # For rmtree (remove directory tree)
import zipfile  # For creating ZIP files
import uuid  # For generating unique IDs
import json  # For loading/saving download_records.json
import hashlib  # For generating task IDs based on content
from bs4 import BeautifulSoup  # For Sci-Hub parsing
from urllib.parse import urljoin, quote_plus, urlparse  # For URL manipulation
import xml.etree.ElementTree as ET
import base64  # <--- 新增：用于解码Base64图像数据
# import time # Already imported
from datetime import datetime  # <-- ADDED for SQLAlchemy User model
from flask_sqlalchemy import SQLAlchemy  # <-- ADDED for database
from werkzeug.security import generate_password_hash, check_password_hash  # <-- ADDED for password hashing

app = Flask(__name__)
CORS(app)  # Enable CORS for all routes

# --- SQLAlchemy Configuration ---
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


# --- User Model Definition ---
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f'<User {self.username}>'


# --- Configuration & Global Variables ---
# For Unpaywall and CrossRef APIs, providing an email is polite and helps them track usage.
MY_EMAIL_FOR_APIS = "YOUR_EMAIL@example.com"  # !!! PLEASE REPLACE WITH YOUR ACTUAL EMAIL !!!

SCI_HUB_DOMAINS = [
    "https://sci-hub.se", "https://sci-hub.st", "https://sci-hub.ru",
    "https://sci-hub.wf", "https://sci-hub.shop"
]
REQUEST_SESSION = requests.Session()
REQUEST_SESSION.headers.update({
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.69 Safari/537.36 LitFinderBot/1.0"
})

# Directories for backend file operations (relative to app.py)
# 全局变量
BATCH_TEMP_ROOT_DIR = "batch_processing_temp"
ZIPPED_FILES_DIR = "zipped_downloads"
DOWNLOAD_RECORDS_FILE = "download_records.json"
ARTICLE_DATA_ROOT_DIR = "literature_screenshots_data"  # 存储截图和元数据的根目录名

# Ensure necessary directories exist at startup
if not os.path.exists(BATCH_TEMP_ROOT_DIR):
    os.makedirs(BATCH_TEMP_ROOT_DIR)
if not os.path.exists(ZIPPED_FILES_DIR):
    os.makedirs(ZIPPED_FILES_DIR)
# 确保这个新目录在应用启动时被创建
if not os.path.exists(ARTICLE_DATA_ROOT_DIR):
    os.makedirs(ARTICLE_DATA_ROOT_DIR)
    print(f"Directory '{ARTICLE_DATA_ROOT_DIR}' created for storing screenshots.")


# --- Helper Functions ---

def sanitize_filename(filename_base, extension=".pdf"):
    if not filename_base: filename_base = "untitled_document"
    filename_base = re.sub(r'[/\\]', '_', filename_base)
    filename_base = re.sub(r'[<>:"|?*]', '_', filename_base)
    filename_base = re.sub(r'[\s_]+', '_', filename_base)
    filename_base = filename_base.strip('_.')
    max_len_base = 100
    if len(filename_base) > max_len_base:
        filename_base = filename_base[:max_len_base]
        last_underscore = filename_base.rfind('_')
        if last_underscore > max_len_base / 2: filename_base = filename_base[:last_underscore]
    if not filename_base: filename_base = "document"
    return filename_base + extension


def sanitize_directory_name(name_str):
    if not name_str:
        name_str = "untitled_article"
    name_str = str(name_str)  # 确保是字符串
    # 移除或替换不适合作为文件夹名称的字符
    name_str = re.sub(r'[<>:"/\\|?*]', '_', name_str)  # 移除Windows和Linux的非法字符
    name_str = re.sub(r'\s+', '_', name_str)  # 空格替换为下划线
    name_str = name_str.strip('._ ')  # 移除首尾的特殊字符

    # 限制长度 (文件夹名通常也有长度限制)
    max_len = 100  # 可以根据需要调整
    if len(name_str) > max_len:
        name_str = name_str[:max_len]
        # 尝试在截断处找到最后一个下划线，以避免单词被切断
        last_underscore = name_str.rfind('_')
        if last_underscore > max_len / 2:  # 确保截断点不是太靠前
            name_str = name_str[:last_underscore]

    if not name_str:  # 如果净化后为空
        name_str = "article_data"
    return name_str


def download_pdf_to_server(pdf_url, desired_title, target_directory):
    if not pdf_url or not desired_title:
        print(f"ERROR: PDF URL or desired title is empty. URL: {pdf_url}, Title: {desired_title}")
        return None

    # Ensure target_directory exists (moved from batch_process_and_zip_route for reusability if needed)
    if not os.path.exists(target_directory):
        try:
            os.makedirs(target_directory)
            print(f"Directory '{target_directory}' created.")
        except OSError as e:
            print(f"ERROR: Could not create directory '{target_directory}': {e}")
            return None

    filename = sanitize_filename(desired_title)
    file_path = os.path.join(target_directory, filename)

    try:
        print(f"Attempting download: {pdf_url} -> {file_path}")
        response = REQUEST_SESSION.get(pdf_url, stream=True, timeout=60, allow_redirects=True)
        response.raise_for_status()
        content_type = response.headers.get('Content-Type', '').lower()
        if 'application/pdf' not in content_type:
            print(
                f"WARNING: Content-Type for {pdf_url} is '{content_type}', not 'application/pdf'. Proceeding with download.")

        with open(file_path, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                if chunk: f.write(chunk)
        print(f"SUCCESS: File downloaded and saved to: {file_path}")
        return file_path
    except requests.exceptions.Timeout:
        print(f"ERROR: Timeout while downloading {pdf_url}")
    except requests.exceptions.HTTPError as e:
        print(f"ERROR: HTTP error while downloading {pdf_url}: {e}")
    except requests.exceptions.RequestException as e:
        print(f"ERROR: Network error while downloading {pdf_url}: {e}")
    except IOError as e:
        print(f"ERROR: IO error while writing file {file_path}: {e}")
    except Exception as e:
        print(f"ERROR: Unknown error during download of {pdf_url}: {e}")

    # Cleanup if download failed and file was partially created
    if os.path.exists(file_path):
        try:
            os.remove(file_path)
        except OSError:
            pass
    return None


def find_pdf_link_via_scihub(doi, domain):
    try:
        sci_hub_url = f"{domain.rstrip('/')}/{doi}"
        print(f"Trying Sci-Hub: {sci_hub_url}")
        response = REQUEST_SESSION.get(sci_hub_url, timeout=20, allow_redirects=True)
        response.raise_for_status()
        soup = BeautifulSoup(response.content, 'html.parser')

        # Try various selectors based on observed Sci-Hub structures
        # Prioritize direct PDF links or embed/iframe sources
        selectors = [
            '#pdf',  # Often an embed or iframe
            'iframe#viewer',
            'embed#viewer',
            'div#viewer iframe',
            'div#viewer embed',
            'div.buttons > ul > li > a[onclick*=".pdf"]',  # Buttons with direct PDF links in onclick
            'div.download-buttons a[href*=".pdf"]',  # Direct download links
            'a#download',  # Common download button ID
            'button[onclick*="location.href=location.origin"]'  # Less direct, might need more parsing
        ]

        pdf_url = None
        for selector in selectors:
            element = soup.select_one(selector)
            if element:
                if element.get('src'): pdf_url = element.get('src'); break
                if element.get('href') and ('.pdf' in element.get('href').lower() or 'sci-hub' in element.get(
                        'href').lower()): pdf_url = element.get('href'); break  # Prioritize .pdf or Sci-Hub links
                if 'onclick' in element.attrs:
                    onclick_val = element['onclick']
                    match = re.search(r"location\.href=['\"]([^'\"]+\.pdf[^'\"]*)['\"]", onclick_val)
                    if match: pdf_url = match.group(1); break

        if pdf_url:
            if pdf_url.startswith('//'): pdf_url = "https:" + pdf_url
            # Sci-Hub links can be relative or on different subdomains
            if not pdf_url.startswith('http'): pdf_url = urljoin(response.url, pdf_url)

            # Further check if the resolved URL seems like a PDF
            if ".pdf" in pdf_url.lower() or "application/pdf" in REQUEST_SESSION.head(pdf_url, timeout=5,
                                                                                      allow_redirects=True).headers.get(
                "Content-Type", "").lower():
                print(f"Found potential PDF link via Sci-Hub ({domain}): {pdf_url}")
                return pdf_url
            else:
                print(f"Sci-Hub link found ({pdf_url}) but doesn't seem to be a direct PDF or has wrong Content-Type.")

        if "application/pdf" in response.headers.get("Content-Type", "").lower():
            print(f"Page itself is a PDF (Sci-Hub - {domain}): {response.url}")
            return response.url

    except requests.exceptions.Timeout:
        print(f"Timeout accessing Sci-Hub {domain} for DOI {doi}")
    except requests.exceptions.RequestException as e:
        print(f"Error accessing Sci-Hub {domain} for DOI {doi}: {e}")
    except Exception as e:
        print(f"Error parsing Sci-Hub response from {domain} for DOI {doi}: {e}")
    return None


def find_pdf_on_unpaywall_by_doi(doi):
    if not doi or not MY_EMAIL_FOR_APIS:
        if not MY_EMAIL_FOR_APIS: print("WARNING: MY_EMAIL_FOR_APIS not set for Unpaywall.")
        return None
    print(f"Attempting Unpaywall for DOI: '{doi}'")
    try:
        api_url = f"https://api.unpaywall.org/v2/{quote_plus(doi)}?email={MY_EMAIL_FOR_APIS}"
        response = REQUEST_SESSION.get(api_url, timeout=15)
        response.raise_for_status()
        data = response.json()
        if data and data.get('best_oa_location') and data['best_oa_location'].get('url_for_pdf'):
            pdf_url = data['best_oa_location']['url_for_pdf']
            print(f"Found OA PDF via Unpaywall: {pdf_url}")
            return pdf_url
        elif data and data.get('is_oa'):
            print(f"Unpaywall: DOI {doi} is OA, but no direct best_oa_location.url_for_pdf found.")
        else:
            print(f"Unpaywall: No OA version found for DOI {doi}.")
    except Exception as e:
        print(f"Error with Unpaywall API for DOI {doi}: {e}")
    return None


def find_pdf_on_arxiv_by_title(title):
    if not title: return None
    print(f"Attempting arXiv by title: '{title}'")
    try:
        title_normalized = title.replace('\u00A0', ' ').strip()  # Replace non-breaking space
        encoded_title = quote_plus(title_normalized)
        api_url = f'http://export.arxiv.org/api/query?search_query=ti:"{encoded_title}"&start=0&max_results=1'
        print(f"arXiv API URL: {api_url}")
        response = REQUEST_SESSION.get(api_url, timeout=15)
        response.raise_for_status()
        xml_data = response.content
        root = ET.fromstring(xml_data)
        atom_ns = '{http://www.w3.org/2005/Atom}'
        for entry in root.findall(f'{atom_ns}entry'):
            for link_tag in entry.findall(f'{atom_ns}link'):
                if link_tag.get('title') == 'pdf' and link_tag.get('href'):
                    pdf_link = link_tag.get('href')
                    print(f"Found arXiv PDF link (title='pdf'): {pdf_link}")
                    return pdf_link  # This is usually the direct PDF link
            # If no title='pdf', try to construct from abs page link
            id_tag_text = None
            id_tag = entry.find(f'{atom_ns}id')  # Primary ID, usually like 'http://arxiv.org/abs/xxxx.xxxxxvN'
            if id_tag is not None and id_tag.text:
                id_tag_text = id_tag.text

            # Fallback to alternate link if ID tag is not a direct abs link
            if not (id_tag_text and '/abs/' in id_tag_text):
                for link_tag in entry.findall(f'{atom_ns}link'):
                    if link_tag.get('rel') == 'alternate' and link_tag.get('type') == 'text/html':
                        id_tag_text = link_tag.get('href')  # This is the HTML abstract page
                        break

            if id_tag_text and '/abs/' in id_tag_text:
                parsed_url = urlparse(id_tag_text)
                arxiv_id_part = parsed_url.path.replace('/abs/', '', 1)
                if arxiv_id_part:
                    constructed_pdf_link = f"https://arxiv.org/pdf/{arxiv_id_part}"
                    # arXiv often serves PDF directly even without .pdf extension if it has version
                    # To be safer, we can append .pdf if not present and no version number
                    if not re.search(r'v\d+$', arxiv_id_part) and not constructed_pdf_link.endswith('.pdf'):
                        constructed_pdf_link += ".pdf"
                    print(f"Constructed arXiv PDF link from abs page: {constructed_pdf_link}")
                    return constructed_pdf_link
        print("No suitable PDF link found in arXiv API response.")
    except Exception as e:
        print(f"Error with arXiv API for title '{title}': {e}")
    return None


def find_pdf_link(doi=None, title=None):
    pdf_url = None
    print(f"DEBUG: find_pdf_link called - DOI: '{doi}', Title: '{title}'")
    if doi:
        print(f"DEBUG: Attempting Sci-Hub for DOI: '{doi}'")
        for domain in SCI_HUB_DOMAINS:
            sci_hub_pdf = find_pdf_link_via_scihub(doi, domain)
            if sci_hub_pdf: pdf_url = sci_hub_pdf; print(f"DEBUG: Found via Sci-Hub: {pdf_url}"); break
    if not pdf_url and doi:
        print(f"DEBUG: Sci-Hub failed. Attempting Unpaywall for DOI: '{doi}'")
        unpaywall_pdf = find_pdf_on_unpaywall_by_doi(doi)
        if unpaywall_pdf: pdf_url = unpaywall_pdf; print(f"DEBUG: Found via Unpaywall: {pdf_url}")
    if not pdf_url and title:
        print(f"DEBUG: Previous methods failed. Attempting arXiv for Title: '{title}'")
        arxiv_pdf = find_pdf_on_arxiv_by_title(title)
        if arxiv_pdf: pdf_url = arxiv_pdf; print(f"DEBUG: Found via arXiv: {pdf_url}")

    if not pdf_url: print(f"DEBUG: Exhausted strategies. No PDF link found for DOI: '{doi}', Title: '{title}'")
    return pdf_url


def load_download_records():
    if os.path.exists(DOWNLOAD_RECORDS_FILE):
        try:
            with open(DOWNLOAD_RECORDS_FILE, 'r', encoding='utf-8') as f:
                records = json.load(f)
            return records if isinstance(records, dict) else {}
        except Exception as e:
            print(f"ERROR loading {DOWNLOAD_RECORDS_FILE}: {e}")
    return {}


def save_download_records(records):
    try:
        with open(DOWNLOAD_RECORDS_FILE, 'w', encoding='utf-8') as f:
            json.dump(records, f, ensure_ascii=False, indent=4)
        print(f"Download records saved to '{DOWNLOAD_RECORDS_FILE}'")
    except Exception as e:
        print(f"ERROR saving {DOWNLOAD_RECORDS_FILE}: {e}")


def generate_task_id(articles_data_list):
    if not articles_data_list: return None
    key_strings = []
    # Sort by a consistent key, e.g., pdfLink then title, to make hash deterministic
    sorted_articles = sorted(articles_data_list,
                             key=lambda x: (x.get('pdfLink', '').lower(), x.get('title', '').lower()))
    for article in sorted_articles:
        link = article.get('pdfLink', '') or ''
        title = article.get('title', '') or ''
        key_strings.append(f"{link}|{title}")
    combined_string = "||".join(key_strings)
    task_id = hashlib.md5(combined_string.encode('utf-8')).hexdigest()
    print(f"Generated Task ID: {task_id} for {len(articles_data_list)} articles.")
    return task_id


# --- Flask Routes ---

@app.route('/api/auth/register', methods=['POST'])
def register_user():
    data = request.get_json()
    if not data:
        return jsonify({"message": "Request body must be JSON"}), 400

    username = data.get('username')
    password = data.get('password')
    email = data.get('email')  # Optional

    if not username or not password:
        return jsonify({"message": "Username and password are required"}), 400

    if User.query.filter_by(username=username).first():
        return jsonify({"message": "Username already exists"}), 400

    if email and User.query.filter_by(email=email).first():
        return jsonify({"message": "Email already exists"}), 400

    new_user = User(username=username, email=email)
    new_user.set_password(password)  # Hashes the password

    try:
        db.session.add(new_user)
        db.session.commit()
        # In a real app, you might want to log the user in here or send a confirmation email
        return jsonify({"message": "User registered successfully"}), 201  # 201 Created
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error during registration for {username}: {str(e)}")
        return jsonify({"message": "Registration failed due to a server error"}), 500


@app.route('/api/auth/login', methods=['POST'])
def login_user():
    data = request.get_json()
    if not data:
        return jsonify({"message": "Request body must be JSON"}), 400

    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({"message": "Username and password are required"}), 400

    user = User.query.filter_by(username=username).first()

    if user and user.check_password(password):
        # Placeholder for session/token generation (e.g., using Flask-Login or JWT)
        # For now, just return a success message.
        # login_user(user) # Example if Flask-Login was fully set up
        # access_token = create_access_token(identity=username) # Example if JWT was set up
        app.logger.info(f"User {username} logged in successfully.")
        return jsonify({"message": "Login successful"}), 200  # Potentially return access_token here later
    else:
        app.logger.warning(f"Failed login attempt for username: {username}")
        return jsonify({"message": "Invalid username or password"}), 401  # Unauthorized


@app.route('/api/auth/logout', methods=['POST'])
def logout_user():
    # Placeholder for session/token invalidation (e.g., using Flask-Login or JWT denylist)
    # For Flask-Login, this would be:
    # from flask_login import logout_user
    # logout_user()
    # For JWT, client typically just discards the token. Server might add to denylist if needed.

    username = None  # Replace with actual username if available from session/token
    # if 'current_user' in globals() and current_user.is_authenticated: # Example for Flask-Login
    #    username = current_user.username

    app.logger.info(f"User {username if username else '[unknown]'} logged out.")  # Log attempt
    return jsonify({"message": "Logout successful"}), 200


@app.route('/api/auth/status', methods=['GET'])
def auth_status():
    # Placeholder for actual session/token checking logic.
    # When Flask-Login or JWT is implemented, this will change significantly.
    # For example, with Flask-Login:
    # from flask_login import current_user
    # if current_user.is_authenticated:
    #     return jsonify({
    #         "logged_in": True,
    #         "user": {
    #             "id": current_user.id,
    #             "username": current_user.username,
    #             "email": current_user.email
    #             # Add other fields as needed, but avoid sending sensitive info like password_hash
    #         }
    #     }), 200
    # else:
    #     return jsonify({"logged_in": False}), 200

    # For now, returning a default "not implemented" or "not logged in" status
    app.logger.info("Auth status requested. Currently placeholder, returning not logged in.")
    return jsonify({
        "logged_in": False,
        "message": "User status check placeholder. Session management not fully implemented."
    }), 200  # Or 501 Not Implemented if preferred for placeholder


@app.route('/')
def health_check():
    return "Backend is running! LitFinder v5.2"


@app.route('/api/find-pdf', methods=['GET'])
def get_pdf_link_api():
    doi = request.args.get('doi')
    title = request.args.get('title')
    print(f"DEBUG: /api/find-pdf received - DOI: '{doi}', Title: '{title}'")
    if not doi and not title: return jsonify({"error": "DOI or Title parameter is required"}), 400
    if doi and not re.match(r"10\.\d{4,9}/[-._;()/:A-Z0-9]+$", doi, re.IGNORECASE):
        return jsonify({"error": "Invalid DOI format"}), 400

    pdf_link = find_pdf_link(doi=doi, title=title)
    if pdf_link:
        return jsonify({"pdfLink": pdf_link})
    else:
        return jsonify({"pdfLink": None, "message": "Could not find PDF link using available strategies."}), 404


@app.route('/api/batch_process_and_zip', methods=['POST'])
def batch_process_and_zip_route():
    data = request.get_json()
    if not data or 'articles' not in data or not isinstance(data['articles'], list):
        return jsonify({"error": "Request body must be JSON with an 'articles' list."}), 400
    articles_to_process = data['articles']
    if not articles_to_process: return jsonify({"error": "'articles' list is empty."}), 400

    current_task_id = generate_task_id(articles_to_process)
    if not current_task_id: return jsonify({"error": "Could not generate task ID."}), 500

    download_records = load_download_records()
    if current_task_id in download_records:
        record = download_records[current_task_id]
        existing_zip_filename = record.get('zip_filename')
        existing_zip_path = os.path.join(ZIPPED_FILES_DIR, existing_zip_filename) if existing_zip_filename else None
        if existing_zip_path and os.path.exists(existing_zip_path):
            print(f"Task ID {current_task_id} already processed. ZIP: '{existing_zip_filename}' exists.")
            return jsonify({
                "status": "previously_processed", "message": "This list was previously processed.",
                "zip_download_filename": existing_zip_filename, "task_id": current_task_id,
                "original_record_timestamp": record.get("timestamp")
            }), 200

    print(f"Task ID {current_task_id}: New task or old ZIP missing. Starting processing...")
    current_task_temp_dir = os.path.join(BATCH_TEMP_ROOT_DIR, current_task_id)
    if os.path.exists(current_task_temp_dir): shutil.rmtree(current_task_temp_dir)  # Clean if exists
    try:
        os.makedirs(current_task_temp_dir)
    except OSError as e:
        return jsonify({"error": f"Could not create temp dir: {e}"}), 500

    downloaded_files_paths = []
    failed_articles_info = []
    for article in articles_to_process:
        pdf_url = article.get('pdfLink')
        title = article.get('title')
        doi = article.get('doi', 'N/A')
        if not pdf_url or not title:
            failed_articles_info.append(
                {"title": title or "Unknown Title", "doi": doi, "reason": "Missing PDF link or title"})
            continue
        saved_path = download_pdf_to_server(pdf_url, title, current_task_temp_dir)
        if saved_path:
            downloaded_files_paths.append(saved_path)
        else:
            failed_articles_info.append({"title": title, "doi": doi, "reason": "Download/Save failed"})

    if not downloaded_files_paths:
        if os.path.exists(current_task_temp_dir): shutil.rmtree(current_task_temp_dir)
        return jsonify({"error": "No PDFs were successfully downloaded.", "failed_items": failed_articles_info}), 400

    zip_filename_base = f"文献包_{current_task_id[:8]}"
    zip_filename_sanitized = sanitize_filename(zip_filename_base, extension=".zip")
    zip_file_path = os.path.join(ZIPPED_FILES_DIR, zip_filename_sanitized)

    try:
        with zipfile.ZipFile(zip_file_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for file_to_zip in downloaded_files_paths:
                zipf.write(file_to_zip, os.path.basename(file_to_zip))
        print(f"ZIP created: {zip_file_path}")
    except Exception as e:
        print(f"ERROR creating ZIP {zip_file_path}: {e}")
        if os.path.exists(current_task_temp_dir): shutil.rmtree(current_task_temp_dir)
        if os.path.exists(zip_file_path): os.remove(zip_file_path)
        return jsonify({"error": "Failed to create ZIP package."}), 500

    if os.path.exists(current_task_temp_dir): shutil.rmtree(current_task_temp_dir)

    new_record = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "zip_filename": zip_filename_sanitized,
        "num_articles_requested": len(articles_to_process),
        "num_articles_success": len(downloaded_files_paths)
    }
    download_records[current_task_id] = new_record
    save_download_records(download_records)

    return jsonify({
        "success": True, "message": f"Successfully processed {len(downloaded_files_paths)} files.",
        "zip_download_filename": zip_filename_sanitized, "task_id": current_task_id,
        "total_requested": len(articles_to_process),
        "successfully_processed": len(downloaded_files_paths),
        "failed_items": failed_articles_info
    }), 200


@app.route('/api/save_screenshot', methods=['POST'])
def save_screenshot_route():
    try:
        data = request.get_json()
        if not data:
            return jsonify({"success": False, "message": "无效的请求：未收到JSON数据。"}), 400

        # --- 1. 从请求中提取并验证必要数据 ---
        article_id = data.get('articleId')  # 前端发送的文献唯一标识
        article_title = data.get('articleTitle')  # 文献标题
        page_number = data.get('pageNumber')
        selection_rect = data.get('selectionRect')  # 选区坐标
        image_data_base64 = data.get('imageData')  # Base64编码的图像数据
        suggested_filename_base = data.get('suggestedFilename', 'screenshot.png')  # 前端建议的文件名
        chart_type = data.get('chartType', '未指定')
        description = data.get('description', '')

        if not all([article_id, image_data_base64, page_number is not None]):
            missing_fields = []
            if not article_id: missing_fields.append("articleId")
            if not image_data_base64: missing_fields.append("imageData")
            if page_number is None: missing_fields.append("pageNumber")
            return jsonify({"success": False, "message": f"请求参数缺失: {', '.join(missing_fields)}"}), 400

        # --- 2. 确定/创建文献专属文件夹 ---
        # 使用净化后的 article_title 或 article_id 作为文件夹名
        # 如果 article_title 可能很长或包含复杂字符，优先用 article_id（如果它适合做文件夹名）
        # 或者结合两者，例如 "Sanitized_Title (ID_Last_5_Chars)"
        # 为简化，我们这里主要用 article_title，如果它存在且不为空

        folder_name_base = article_title if article_title else article_id
        sanitized_article_folder_name = sanitize_directory_name(folder_name_base)

        article_specific_dir = os.path.join(ARTICLE_DATA_ROOT_DIR, sanitized_article_folder_name)
        os.makedirs(article_specific_dir, exist_ok=True)  # exist_ok=True 避免文件夹已存在时报错

        # --- 3. 处理并保存截图文件 ---
        # 从Base64数据中移除 "data:image/png;base64," 前缀 (如果存在)
        try:
            if ',' in image_data_base64:
                header, encoded_data = image_data_base64.split(',', 1)
            else:  # 如果前端发送的就是纯Base64数据
                encoded_data = image_data_base64

            image_bytes = base64.b64decode(encoded_data)
        except Exception as e:
            app.logger.error(f"Base64解码失败 for article {article_id}: {e}")
            return jsonify({"success": False, "message": f"图像数据解码失败: {e}"}), 400

        # 创建一个更唯一的、净化后的文件名，例如：suggested_base + timestamp + .png
        filename_base, filename_ext = os.path.splitext(suggested_filename_base)
        if not filename_ext: filename_ext = ".png"  # 确保有扩展名

        # 使用 sanitize_filename 净化前端建议的文件名部分
        safe_filename_base = sanitize_filename(filename_base, extension="")  # 去掉扩展名进行净化

        # 添加时间戳或唯一ID确保文件名唯一性，防止覆盖
        timestamp_str = time.strftime("%Y%m%d_%H%M%S")
        unique_filename = f"{safe_filename_base}_{timestamp_str}{filename_ext}"

        image_file_path_on_server = os.path.join(article_specific_dir, unique_filename)

        try:
            with open(image_file_path_on_server, 'wb') as f:
                f.write(image_bytes)
            app.logger.info(f"截图已保存到: {image_file_path_on_server}")
        except IOError as e:
            app.logger.error(f"保存截图文件IO错误 for {image_file_path_on_server}: {e}")
            return jsonify({"success": False, "message": f"无法写入截图文件: {e}"}), 500

        # --- 4. 保存截图元数据为 .json 文件 ---
        metadata_filename = f"{safe_filename_base}_{timestamp_str}.json"  # 与图片文件名对应
        metadata_file_path_on_server = os.path.join(article_specific_dir, metadata_filename)

        server_timestamp = time.time()  # 使用Unix时间戳或格式化时间

        metadata_to_save = {
            "originalArticleId": article_id,  # 前端传来的文献ID
            "articleTitle": article_title,
            "pageNumber": page_number,
            "selectionRect": selection_rect,
            "originalSuggestedFilename": suggested_filename_base,  # 前端原始建议名
            "savedImageFilename": unique_filename,  # 服务器上实际保存的图片文件名
            "chartType": chart_type,
            "description": description,
            "serverTimestamp": server_timestamp,
            "serverImageRelativePath": os.path.join(sanitized_article_folder_name, unique_filename).replace("\\", "/"),
            # 相对路径，方便前端
            "serverMetadataRelativePath": os.path.join(sanitized_article_folder_name, metadata_filename).replace("\\",
                                                                                                                 "/")
        }

        try:
            with open(metadata_file_path_on_server, 'w', encoding='utf-8') as mf:
                json.dump(metadata_to_save, mf, ensure_ascii=False, indent=4)
            app.logger.info(f"截图元数据已保存到: {metadata_file_path_on_server}")
        except IOError as e:
            app.logger.error(f"保存元数据文件IO错误 for {metadata_file_path_on_server}: {e}")
            # 注意：此时图片可能已保存，需要考虑事务性或补偿措施（例如删除已保存图片）
            # 为简化，此处仅返回错误
            return jsonify({"success": False, "message": f"无法写入元数据文件: {e}"}), 500

        # --- 5. 返回成功响应 ---
        return jsonify({
            "success": True,
            "message": "截图和元数据已成功保存到服务器。",
            "screenshotServerId": None,  # 如果您为截图生成了数据库ID，可以在此返回
            "serverFilePath": metadata_to_save["serverImageRelativePath"],  # 返回相对于 ARTICLE_DATA_ROOT_DIR 的路径
            "metadataFilePath": metadata_to_save["serverMetadataRelativePath"]
        }), 201  # 201 Created 表示资源创建成功

    except Exception as e:
        app.logger.error(f"处理 /api/save_screenshot 请求时发生未知错误: {e}")
        import traceback
        traceback.print_exc()  # 打印完整的堆栈跟踪到服务器日志
        return jsonify({"success": False, "message": f"服务器内部错误: {str(e)}"}), 500


@app.route('/api/download_screenshot_image', methods=['GET'])
def download_screenshot_image_route():
    # 从查询参数中获取相对路径
    # 例如: /api/download_screenshot_image?path=Sanitized_Article_Title/image_timestamp.png
    relative_path = request.args.get('path')

    if not relative_path:
        return jsonify({"success": False, "message": "请求参数 'path' 缺失。"}), 400

    # 安全性：规范化路径并检查是否在预期的根目录下，防止路径遍历攻击
    # os.path.normpath 会处理 '..' 和 '.' 等，但仍需额外检查
    # os.path.abspath 将路径转换为绝对路径

    # 构建截图文件的绝对路径
    # ARTICLE_DATA_ROOT_DIR 应该是绝对路径或相对于 app.py 的正确相对路径
    base_dir = os.path.abspath(ARTICLE_DATA_ROOT_DIR)
    requested_file_abs_path = os.path.normpath(os.path.join(base_dir, relative_path))

    # 安全检查：确保请求的路径确实在 ARTICLE_DATA_ROOT_DIR 之下
    if not requested_file_abs_path.startswith(base_dir):
        app.logger.warning(f"潜在的路径遍历尝试被拒绝: {relative_path}")
        return jsonify({"success": False, "message": "无效的文件路径或访问被拒绝。"}), 403  # Forbidden

    if not os.path.exists(requested_file_abs_path) or not os.path.isfile(requested_file_abs_path):
        app.logger.error(f"请求下载的文件未找到: {requested_file_abs_path}")
        return jsonify({"success": False, "message": "请求的文件未找到。"}), 404  # Not Found

    try:
        # send_from_directory 需要目录和文件名分开
        directory = os.path.dirname(requested_file_abs_path)
        filename = os.path.basename(requested_file_abs_path)

        app.logger.info(f"准备发送文件: {filename} 从目录: {directory}")
        return send_from_directory(directory, filename, as_attachment=True)
    except Exception as e:
        app.logger.error(f"下载文件时发生错误 ({relative_path}): {e}")
        import traceback
        traceback.print_exc()
        return jsonify({"success": False, "message": f"下载文件时发生服务器内部错误: {str(e)}"}), 500


# ***** 新增API结束 *****
@app.route('/api/delete_batch_record', methods=['POST'])
def delete_batch_record_route():
    data = request.get_json()
    if not data or 'task_id' not in data: return jsonify({"error": "Missing 'task_id'."}), 400
    task_id_to_delete = data['task_id']
    print(f"Received request to delete record for task ID: {task_id_to_delete}")
    download_records = load_download_records()
    if task_id_to_delete in download_records:
        record_to_delete = download_records.pop(task_id_to_delete)  # Remove from dict
        save_download_records(download_records)
        zip_filename_to_delete = record_to_delete.get('zip_filename')
        message = f"Record for task ID {task_id_to_delete} deleted."
        if zip_filename_to_delete:
            zip_file_path_to_delete = os.path.join(ZIPPED_FILES_DIR, zip_filename_to_delete)
            if os.path.exists(zip_file_path_to_delete):
                try:
                    os.remove(
                        zip_file_path_to_delete);
                    message += f" Associated ZIP file '{zip_filename_to_delete}' also deleted."
                except OSError as e:
                    message += f" Record deleted, but failed to delete ZIP '{zip_filename_to_delete}': {e}."
            else:
                message += f" Associated ZIP file '{zip_filename_to_delete}' not found on server."
        return jsonify({"success": True, "message": message}), 200
    else:
        return jsonify({"success": False, "message": f"Task ID {task_id_to_delete} not found."}), 404


@app.route('/api/download_zip_package/<filename>', methods=['GET'])
def download_zip_package_route(filename):
    try:
        print(f"Request to download ZIP: {filename} from dir: {ZIPPED_FILES_DIR}")
        # Sanitize filename just in case, although it should be already sanitized
        safe_filename = sanitize_filename(os.path.splitext(filename)[0], os.path.splitext(filename)[1])
        if filename != safe_filename:  # Basic check for manipulation
            print(
                f"WARNING: Requested filename '{filename}' differs from sanitized '{safe_filename}'. Using sanitized.")
            # For security, you might want to reject if they don't match exactly,
            # or ensure your ZIPPED_FILES_DIR only contains sanitized names.

        return send_from_directory(
            directory=ZIPPED_FILES_DIR,
            path=filename,  # Use original filename from URL path as it should match what's on disk
            as_attachment=True,
            download_name=f"文献集_{time.strftime('%Y%m%d_%H%M%S')}.zip"
        )
    except FileNotFoundError:
        return jsonify({"error": "Requested ZIP file not found."}), 404
    except Exception as e:
        print(f"Error sending ZIP {filename}: {e}");
        return jsonify({"error": "Server error sending ZIP."}), 500


if __name__ == '__main__':
    with app.app_context():  # <-- ADDED for database creation
        db.create_all()  # <-- ADDED for database creation
    print("Starting Flask development server (LitFinder v5.2)...")
    print(f"MY_EMAIL_FOR_APIS: {MY_EMAIL_FOR_APIS}")
    print(f"PDF temp storage: {os.path.abspath(BATCH_TEMP_ROOT_DIR)}")
    print(f"ZIP storage: {os.path.abspath(ZIPPED_FILES_DIR)}")
    print(f"Download records file: {os.path.abspath(DOWNLOAD_RECORDS_FILE)}")
    app.run(host='0.0.0.0', port=5000, debug=True)

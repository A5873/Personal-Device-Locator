import requests
import time
import webbrowser
from tkinter import *
from tkinter import ttk
from tkinter import simpledialog
from tkinter import messagebox
import threading
from datetime import datetime, timedelta
import re
import json
import uuid
import hashlib
import base64
import pyotp
import qrcode
from PIL import Image, ImageTk
from pathlib import Path
from tkinter import font
import os
import logging
import sqlite3
import pyaes
import secrets
import socket
import platform
import io
import asyncio
import websockets
from cryptography.fernet import Fernet

class FontManager:
    @staticmethod
    def load_rubik_font():
        # Create fonts directory if it doesn't exist
        os.makedirs("fonts", exist_ok=True)
        
        # Define font files to check/download
        font_files = {
            "Rubik-Regular.ttf": "https://github.com/googlefonts/rubik/raw/main/fonts/ttf/Rubik-Regular.ttf",
            "Rubik-Bold.ttf": "https://github.com/googlefonts/rubik/raw/main/fonts/ttf/Rubik-Bold.ttf",
            "Rubik-Medium.ttf": "https://github.com/googlefonts/rubik/raw/main/fonts/ttf/Rubik-Medium.ttf"
        }
        
        # Download missing font files
        for font_file, url in font_files.items():
            font_path = f"fonts/{font_file}"
            if not os.path.exists(font_path):
                try:
                    response = requests.get(url)
                    with open(font_path, 'wb') as f:
                        f.write(response.content)
                except Exception as e:
                    print(f"Error downloading font: {e}")
                    return False
        
        # Load fonts into Tkinter
        for font_file in font_files.keys():
            font_path = f"fonts/{font_file}"
            try:
                font.families()  # Initialize font system
                font.Font(file=font_path)
            except Exception as e:
                print(f"Error loading font: {e}")
                return False
        
        return True

class CustomFont:
    REGULAR = "Rubik"
    MEDIUM = "Rubik Medium"
    BOLD = "Rubik Bold"
    
    # Font sizes
    H1 = 24
    H2 = 18
    H3 = 16
    BODY = 12
    SMALL = 10

class ThemeColors:
    PRIMARY = '#2C3E50'
    SECONDARY = '#34495E'
    ACCENT = '#3498DB'
    SUCCESS = '#27AE60'
    ERROR = '#E74C3C'
    WARNING = '#F39C12'
    TEXT_LIGHT = '#ECF0F1'
    TEXT_DARK = '#2C3E50'
    GRAY = '#BDC3C7'

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    filename='personal_device_locator.log'
)
logger = logging.getLogger('PersonalDeviceLocator')

# Current version constants
APP_NAME = "Personal Device Locator"
APP_VERSION = "1.0.0"
PRIVACY_POLICY_VERSION = "1.0.0"
TERMS_VERSION = "1.0.0"

# Request rate limiting
class RateLimiter:
    def __init__(self, max_requests=10, time_window=60):
        self.max_requests = max_requests
        self.time_window = time_window  # in seconds
        self.request_history = {}
        
    def is_allowed(self, key):
        current_time = datetime.now()
        if key not in self.request_history:
            self.request_history[key] = []
            
        # Clear old requests
        self.request_history[key] = [t for t in self.request_history[key] 
                                    if (current_time - t).total_seconds() < self.time_window]
        
        # Check if under limit
        if len(self.request_history[key]) < self.max_requests:
            self.request_history[key].append(current_time)
            return True
        return False

# Encryption utilities
class EncryptionManager:
    def __init__(self):
        self.key_file = "encryption_key.key"
        self.key = self._load_or_create_key()
        self.cipher = Fernet(self.key)
        
    def _load_or_create_key(self):
        if os.path.exists(self.key_file):
            with open(self.key_file, 'rb') as key_file:
                key = key_file.read()
        else:
            key = Fernet.generate_key()
            with open(self.key_file, 'wb') as key_file:
                key_file.write(key)
        return key
    
    def encrypt(self, data):
        if isinstance(data, str):
            data = data.encode('utf-8')
        return self.cipher.encrypt(data)
    
    def decrypt(self, encrypted_data):
        return self.cipher.decrypt(encrypted_data).decode('utf-8')

class DatabaseManager:
    def __init__(self):
        self.db_path = "device_locator.db"
        self._create_tables()
        
    def _create_tables(self):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Users table
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                salt TEXT NOT NULL,
                totp_secret TEXT,
                is_2fa_enabled INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP
            )
            ''')
            
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS devices (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                name TEXT NOT NULL,
                device_type TEXT NOT NULL,
                identifier TEXT NOT NULL,
                verification_code TEXT,
                is_verified INTEGER DEFAULT 0,
                last_location TEXT,
                location_encrypted INTEGER DEFAULT 1,
                last_seen TIMESTAMP,
                consent_given INTEGER DEFAULT 0,
                consent_date TIMESTAMP,
                share_until TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
            ''')
            
            # Activity logs
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS activity_logs (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                device_id TEXT,
                action TEXT NOT NULL,
                ip_address TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id),
                FOREIGN KEY (device_id) REFERENCES devices (id)
            )
            ''')
            
            # Location history
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS location_history (
                id TEXT PRIMARY KEY,
                device_id TEXT NOT NULL,
                location TEXT NOT NULL,
                is_encrypted INTEGER DEFAULT 1,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (device_id) REFERENCES devices (id)
            )
            ''')
            
            # User sessions
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS sessions (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                token TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP NOT NULL,
                ip_address TEXT,
                is_active INTEGER DEFAULT 1,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
            ''')
            
            # Consent records
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS consent_records (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                privacy_policy_version TEXT NOT NULL,
                terms_version TEXT NOT NULL,
                consented_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
            ''')
            
            conn.commit()
            
            # Create indexes for better performance
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_devices_user_id ON devices(user_id)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_activity_logs_user_id ON activity_logs(user_id)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_location_history_device_id ON location_history(device_id)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(token)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id)')
            
    def create_user(self, name, email, password):
        user_id = str(uuid.uuid4())
        salt = os.urandom(32).hex()
        password_hash = self._hash_password(password, salt)
        totp_secret = pyotp.random_base32()
        
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "INSERT INTO users (id, name, email, password_hash, salt, totp_secret) VALUES (?, ?, ?, ?, ?, ?)",
                    (user_id, name, email, password_hash, salt, totp_secret)
                )
                conn.commit()
                self.log_activity(user_id, None, "account_created")
                return user_id
        except sqlite3.IntegrityError:
            return None
    
    def verify_user(self, email, password):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id, password_hash, salt, is_2fa_enabled, totp_secret FROM users WHERE email = ?", (email,))
            result = cursor.fetchone()
            
            if not result:
                return None
                
            user_id, stored_hash, salt, is_2fa_enabled, totp_secret = result
            computed_hash = self._hash_password(password, salt)
            
            if computed_hash == stored_hash:
                return {
                    "user_id": user_id,
                    "requires_2fa": bool(is_2fa_enabled),
                    "totp_secret": totp_secret
                }
            return None
    
    def verify_totp(self, user_id, totp_code):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT totp_secret FROM users WHERE id = ?", (user_id,))
            result = cursor.fetchone()
            
            if not result:
                return False
                
            totp_secret = result[0]
            totp = pyotp.TOTP(totp_secret)
            return totp.verify(totp_code)
    
    def enable_2fa(self, user_id):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE users SET is_2fa_enabled = 1 WHERE id = ?", (user_id,))
            conn.commit()
            self.log_activity(user_id, None, "2fa_enabled")
            return True
    
    def create_session(self, user_id, ip_address):
        session_id = str(uuid.uuid4())
        token = os.urandom(32).hex()
        expires_at = datetime.now().timestamp() + (30 * 24 * 60 * 60)  # 30 days
        
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO sessions (id, user_id, token, expires_at, ip_address) VALUES (?, ?, ?, ?, ?)",
                (session_id, user_id, token, expires_at, ip_address)
            )
            cursor.execute(
                "UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?",
                (user_id,)
            )
            conn.commit()
            self.log_activity(user_id, None, "login")
            return token
    
    def verify_session(self, token):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT user_id, expires_at FROM sessions WHERE token = ? AND is_active = 1",
                (token,)
            )
            result = cursor.fetchone()
            
            if not result:
                return None
                
            user_id, expires_at = result
            
            if datetime.now().timestamp() > expires_at:
                # Session expired
                cursor.execute("UPDATE sessions SET is_active = 0 WHERE token = ?", (token,))
                conn.commit()
                return None
                
            return user_id
    
    def invalidate_session(self, token):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE sessions SET is_active = 0 WHERE token = ?", (token,))
            conn.commit()
    
    def register_device(self, user_id, name, device_type, identifier):
        device_id = str(uuid.uuid4())
        verification_code = ''.join([str(uuid.uuid4().int)[:6] for _ in range(1)])
        
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                """INSERT INTO devices 
                   (id, user_id, name, device_type, identifier, verification_code, share_until) 
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (device_id, user_id, name, device_type, identifier, verification_code, 
                 (datetime.now() + timedelta(days=1)).timestamp())  # Default sharing for 24 hours
            )
            conn.commit()
            self.log_activity(user_id, device_id, "device_registered")
            return device_id, verification_code
    
    def verify_device(self, device_id, verification_code):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT verification_code, user_id FROM devices WHERE id = ?",
                (device_id,)
            )
            result = cursor.fetchone()
            
            if not result or result[0] != verification_code:
                return False
                
            cursor.execute(
                "UPDATE devices SET is_verified = 1, verification_code = NULL WHERE id = ?",
                (device_id,)
            )
            conn.commit()
            self.log_activity(result[1], device_id, "device_verified")
            return True
    
    def get_user_devices(self, user_id):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                """SELECT id, name, device_type, identifier, is_verified, last_location, 
                   last_seen, consent_given, share_until, location_encrypted 
                   FROM devices WHERE user_id = ?""",
                (user_id,)
            )
            columns = [col[0] for col in cursor.description]
            devices = [dict(zip(columns, row)) for row in cursor.fetchall()]
            
            # Convert timestamps to datetime objects
            for device in devices:
                if device['share_until']:
                    device['share_until'] = datetime.fromtimestamp(device['share_until'])
                if device['last_seen']:
                    device['last_seen'] = datetime.fromtimestamp(device['last_seen'])
            
            return devices
    def update_device_location(self, device_id, location, encrypted=True):
        current_timestamp = datetime.now().timestamp()
        
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Check if device is authorized to share location
            cursor.execute(
                "SELECT user_id, consent_given, share_until FROM devices WHERE id = ?",
                (device_id,)
            )
            result = cursor.fetchone()
            
            if not result:
                return False
                
            user_id, consent_given, share_until = result
            
            # Verify consent and sharing timeframe
            if not consent_given or (share_until and current_timestamp > share_until):
                return False
            
            # Update device location
            cursor.execute(
                """UPDATE devices SET last_location = ?, last_seen = ?, 
                   location_encrypted = ? WHERE id = ?""",
                (location, current_timestamp, 1 if encrypted else 0, device_id)
            )
            
            # Add to location history
            history_id = str(uuid.uuid4())
            cursor.execute(
                """INSERT INTO location_history 
                   (id, device_id, location, is_encrypted, timestamp) 
                   VALUES (?, ?, ?, ?, ?)""",
                (history_id, device_id, location, 1 if encrypted else 0, current_timestamp)
            )
            
            conn.commit()
            self.log_activity(user_id, device_id, "location_updated")
            return True
    
    def remove_device(self, device_id):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Get user_id for activity log
            cursor.execute("SELECT user_id FROM devices WHERE id = ?", (device_id,))
            user_id = cursor.fetchone()[0]
            
            cursor.execute("DELETE FROM devices WHERE id = ?", (device_id,))
            conn.commit()
            self.log_activity(user_id, device_id, "device_removed")
    
    def record_consent(self, user_id, privacy_policy_version, terms_version):
        consent_id = str(uuid.uuid4())
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO consent_records (id, user_id, privacy_policy_version, terms_version) VALUES (?, ?, ?, ?)",
                (consent_id, user_id, privacy_policy_version, terms_version)
            )
            conn.commit()
            self.log_activity(user_id, None, "consent_recorded")
    
    def log_activity(self, user_id, device_id, action, ip_address=None):
        log_id = str(uuid.uuid4())
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO activity_logs (id, user_id, device_id, action, ip_address) VALUES (?, ?, ?, ?, ?)",
                (log_id, user_id, device_id, action, ip_address)
            )
            conn.commit()
            
    def get_user_activity(self, user_id, limit=50):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT a.action, a.timestamp, d.name as device_name, a.ip_address
                FROM activity_logs a
                LEFT JOIN devices d ON a.device_id = d.id
                WHERE a.user_id = ?
                ORDER BY a.timestamp DESC
                LIMIT ?
                """,
                (user_id, limit)
            )
            columns = [col[0] for col in cursor.description]
            return [dict(zip(columns, row)) for row in cursor.fetchall()]
            
    def get_device_location_history(self, device_id, limit=100):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT id, location, is_encrypted, timestamp
                FROM location_history
                WHERE device_id = ?
                ORDER BY timestamp DESC
                LIMIT ?
                """,
                (device_id, limit)
            )
            columns = [col[0] for col in cursor.description]
            return [dict(zip(columns, row)) for row in cursor.fetchall()]
    
    def update_device_consent(self, device_id, consent_given, share_duration_hours=24):
        current_time = datetime.now()
        share_until = None
        
        if consent_given:
            share_until = (current_time + timedelta(hours=share_duration_hours)).timestamp()
        
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                UPDATE devices 
                SET consent_given = ?, consent_date = ?, share_until = ?
                WHERE id = ?
                """,
                (1 if consent_given else 0, current_time.timestamp() if consent_given else None, 
                 share_until, device_id)
            )
            conn.commit()
            
            # Get user_id for activity log
            cursor.execute("SELECT user_id FROM devices WHERE id = ?", (device_id,))
            user_id = cursor.fetchone()[0]
            
            action = "location_sharing_enabled" if consent_given else "location_sharing_disabled"
            self.log_activity(user_id, device_id, action)
            return True
    
    def delete_location_history(self, device_id=None, before_date=None):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            if device_id and before_date:
                # Delete history for specific device before a certain date
                cursor.execute(
                    "DELETE FROM location_history WHERE device_id = ? AND timestamp < ?",
                    (device_id, before_date.timestamp())
                )
                # Delete all history for a specific device
                cursor.execute(
                    "DELETE FROM location_history WHERE device_id = ?",
                    (device_id,)
                )
            
            conn.commit()
            return True
                
    def _hash_password(self, password, salt):
        """Create a secure password hash using PBKDF2."""
        password_bytes = password.encode('utf-8')
        salt_bytes = bytes.fromhex(salt)
        hash_bytes = hashlib.pbkdf2_hmac('sha256', password_bytes, salt_bytes, 100000)
        return hash_bytes.hex()


# Custom exceptions for better error handling
class DeviceTrackerError(Exception):
    """Base exception for device tracker errors"""
    pass

class DatabaseError(DeviceTrackerError):
    """Database related errors"""
    pass

class AuthenticationError(DeviceTrackerError):
    """Authentication related errors"""
    pass

class DeviceError(DeviceTrackerError):
    """Device management related errors"""
    pass


class Validator:
    @staticmethod
    def validate_device_name(name):
        if not name or len(name) < 3:
            raise ValueError("Device name must be at least 3 characters long")
        if len(name) > 50:
            raise ValueError("Device name must be less than 50 characters")
        if not re.match(r'^[\w\s-]+$', name):
            raise ValueError("Device name can only contain letters, numbers, spaces, and hyphens")
        return True
        
    @staticmethod
    def validate_email(email):
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.match(pattern, email):
            raise ValueError("Invalid email format")
        return True
        
    @staticmethod
    def validate_password(password):
        if len(password) < 8:
            raise ValueError("Password must be at least 8 characters long")
        if not re.search(r'[A-Z]', password):
            raise ValueError("Password must contain at least one uppercase letter")
        if not re.search(r'[a-z]', password):
            raise ValueError("Password must contain at least one lowercase letter")
        if not re.search(r'\d', password):
            raise ValueError("Password must contain at least one number")
        return True


class DeviceIcons:
    SMARTPHONE = "📱"
    TABLET = "📟"
    LAPTOP = "💻"
    DESKTOP = "🖥️"
    OTHER = "📱"
    
    @staticmethod
    def get_icon(device_type):
        icons = {
            "smartphone": DeviceIcons.SMARTPHONE,
            "tablet": DeviceIcons.TABLET,
            "laptop": DeviceIcons.LAPTOP,
            "desktop": DeviceIcons.DESKTOP,
            "other": DeviceIcons.OTHER
        }
        return icons.get(device_type, DeviceIcons.OTHER)


class LocationUpdater:
    def __init__(self, host="localhost", port=8765):
        self.uri = f"ws://{host}:{port}"
        self.ws = None
        self.running = False
        
    async def connect(self):
        try:
            self.ws = await websockets.connect(self.uri)
            self.running = True
        except Exception as e:
            logger.error(f"Failed to connect to WebSocket server: {e}")
            raise
        
    async def listen(self, callback):
        while self.running:
            try:
                message = await self.ws.recv()
                data = json.loads(message)
                callback(data)
            except websockets.exceptions.ConnectionClosed:
                logger.warning("WebSocket connection closed, attempting to reconnect...")
                try:
                    await self.connect()
                except:
                    await asyncio.sleep(5)
            except Exception as e:
                logger.error(f"Error in location updater: {e}")
                await asyncio.sleep(5)
                
    def stop(self):
        self.running = False
        if self.ws:
            asyncio.run(self.ws.close())


class MapView(Frame):
    def __init__(self, master, **kwargs):
        super().__init__(master, **kwargs)
        self.configure(bg=ThemeColors.PRIMARY)
        
        # Add web view for OpenStreetMap
        self.map_html = """
        <html>
            <head>
                <link rel="stylesheet" href="https://unpkg.com/leaflet@1.7.1/dist/leaflet.css"/>
                <script src="https://unpkg.com/leaflet@1.7.1/dist/leaflet.js"></script>
                <style>
                    #map { height: 100%; width: 100%; }
                </style>
            </head>
            <body style="margin:0">
                <div id="map"></div>
                <script>
                    var map = L.map('map').setView([0, 0], 2);
                    L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
                        attribution: '© OpenStreetMap contributors'
                    }).addTo(map);
                    
                    var markers = {};
                    
                    function updateMarker(deviceId, lat, lng, name) {
                        if (markers[deviceId]) {
                            markers[deviceId].setLatLng([lat, lng]);
                        } else {
                            markers[deviceId] = L.marker([lat, lng])
                                .bindPopup(name)
                                .addTo(map);
                        }
                        map.setView([lat, lng], 13);
                    }
                </script>
            </body>
        </html>
        """
        
        # Create a temporary HTML file for the map
        self.map_file = "temp_map.html"
        with open(self.map_file, "w") as f:
            f.write(self.map_html)
            
        try:
            # Create web view widget (using platform-specific webview)
            if platform.system() == "Windows":
                try:
                    from tkinterweb import HtmlFrame
                    self.web_view = HtmlFrame(self)
                    self.web_view.load_file(self.map_file)
                    self.web_view.pack(fill=BOTH, expand=True)
                except ImportError:
                    logger.warning("tkinterweb not installed, using fallback map display")
                    self._use_fallback_map()
            else:
                try:
                    import webview
                    Label(
                        self,
                        text="Click to open map in browser",
                        font=(CustomFont.MEDIUM, CustomFont.BODY),
                        bg=ThemeColors.PRIMARY,
                        fg=ThemeColors.TEXT_LIGHT,
                        cursor="hand2"
                    ).pack(pady=20)
                    Button(
                        self,
                        text="Open Map",
                        command=lambda: webview.create_window("Map", self.map_file),
                        bg=ThemeColors.ACCENT,
                        fg=ThemeColors.TEXT_LIGHT,
                        font=(CustomFont.MEDIUM, CustomFont.BODY),
                        relief=FLAT
                    ).pack()
                except ImportError:
                    logger.warning("webview not installed, using fallback map display")
                    self._use_fallback_map()
        except Exception as e:
            logger.error(f"Error setting up map: {e}")
            self._use_fallback_map()
    
    def _use_fallback_map(self):
        """Fallback if web view libraries aren't available"""
        Label(
            self,
            text="Map View (Integration Not Available)",
            font=(CustomFont.BOLD, CustomFont.H2),
            bg=ThemeColors.PRIMARY,
            fg=ThemeColors.TEXT_LIGHT
        ).pack(pady=20)
        
        self.location_label = Label(
            self,
            text="No location data available",
            font=(CustomFont.REGULAR, CustomFont.BODY),
            bg=ThemeColors.PRIMARY,
            fg=ThemeColors.TEXT_LIGHT
        )
        self.location_label.pack(pady=10)
        
        # Button to open location in browser
        self.open_map_button = Button(
            self,
            text="Open in Browser",
            command=self.open_in_browser,
            bg=ThemeColors.ACCENT,
            fg=ThemeColors.TEXT_LIGHT,
            font=(CustomFont.MEDIUM, CustomFont.BODY),
            relief=FLAT,
            state=DISABLED
        )
        self.open_map_button.pack(pady=10)
        
        self.current_location = None
        
    def update_device_location(self, device_id, lat, lng, name):
        """Update the device location on the map"""
        try:
            if hasattr(self, 'web_view'):
                js_code = f"updateMarker('{device_id}', {lat}, {lng}, '{name}')"
                self.web_view.evaluate_js(js_code)
            elif hasattr(self, 'location_label'):
                # Update fallback display
                self.current_location = (lat, lng)
                self.location_label.config(text=f"Device: {name}\nLocation: {lat}, {lng}")
                self.open_map_button.config(state=NORMAL)
        except Exception as e:
            logger.error(f"Error updating map: {e}")
            
    def open_in_browser(self):
        """Open the current location in the default web browser"""
        if self.current_location:
            lat, lng = self.current_location
            url = f"https://www.openstreetmap.org/?mlat={lat}&mlon={lng}#map=15/{lat}/{lng}"
            webbrowser.open(url)


class LoginWindow:
    def __init__(self, on_login_success):
        self.on_login_success = on_login_success
        self.window = Tk()
        self.window.title(f"{APP_NAME} - Login")
        self.window.geometry("500x650")
        self.window.configure(bg=ThemeColors.PRIMARY)
        
        # Header
        self.header = Label(
            self.window,
            text=f"🌟 Welcome to {APP_NAME}",
            font=(CustomFont.BOLD, CustomFont.H2),
            bg=ThemeColors.PRIMARY,
            fg=ThemeColors.TEXT_LIGHT
        )
        self.header.pack(pady=20)
        
        # Login frame
        self.login_frame = Frame(self.window, bg=ThemeColors.SECONDARY, padx=20, pady=20)
        self.login_frame.pack(fill=X, padx=20)
        
        # Email
        Label(
            self.login_frame,
            text="📧 Email",
            bg=ThemeColors.SECONDARY,
            fg=ThemeColors.TEXT_LIGHT,
            font=(CustomFont.MEDIUM, CustomFont.BODY)
        ).pack(pady=5)
        
        self.email_entry = Entry(
            self.login_frame,
            font=(CustomFont.REGULAR, CustomFont.BODY),
            bg=ThemeColors.TEXT_LIGHT
        )
        self.email_entry.pack(fill=X, pady=5)
        
        # Password
        Label(
            self.login_frame,
            text="🔑 Password",
            bg=ThemeColors.SECONDARY,
            fg=ThemeColors.TEXT_LIGHT,
            font=(CustomFont.MEDIUM, CustomFont.BODY)
        ).pack(pady=5)
        
        self.password_entry = Entry(
            self.login_frame,
            font=(CustomFont.REGULAR, CustomFont.BODY),
            bg=ThemeColors.TEXT_LIGHT,
            show="•"
        )
        self.password_entry.pack(fill=X, pady=5)
        
        # Remember me
        self.remember_var = BooleanVar()
        Checkbutton(
            self.login_frame,
            text="Remember me",
            variable=self.remember_var,
            bg=ThemeColors.SECONDARY,
            fg=ThemeColors.TEXT_LIGHT,
            selectcolor=ThemeColors.PRIMARY,
            font=(CustomFont.REGULAR, CustomFont.SMALL)
        ).pack(pady=10)
        
        # Login button with hover effect
        self.login_button = Button(
            self.login_frame,
            text="🚀 Login",
            command=self.login,
            bg=ThemeColors.SUCCESS,
            fg=ThemeColors.TEXT_LIGHT,
            font=(CustomFont.BOLD, CustomFont.BODY),
            width=15,
            height=2,
            relief=FLAT,
            cursor="hand2"
        )
        self.login_button.pack(pady=10)
        
        # Add hover effect
        self.login_button.bind("<Enter>", lambda e: self.login_button.configure(bg=ThemeColors.ACCENT))
        self.login_button.bind("<Leave>", lambda e: self.login_button.configure(bg=ThemeColors.SUCCESS))
        
        # Register link
        self.register_button = Button(
            self.login_frame,
            text="📝 New User? Register Here",
            command=self.show_register,
            bg=ThemeColors.SECONDARY,
            fg=ThemeColors.ACCENT,
            font=(CustomFont.REGULAR, CustomFont.SMALL, "underline"),
            bd=0,
            relief=FLAT,
            cursor="hand2"
        )
        self.register_button.pack(pady=5)
        
        # Status label
        self.status_label = Label(
            self.login_frame,
            text="",
            bg=ThemeColors.SECONDARY,
            fg=ThemeColors.ERROR,
            font=(CustomFont.REGULAR, CustomFont.SMALL)
        )
        self.status_label.pack(pady=5)
        
        # Load saved credentials if any
        self.load_saved_credentials()
        
    def validate_email(self, email):
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return re.match(pattern, email) is not None
        
    def login(self):
        email = self.email_entry.get()
        password = self.password_entry.get()
        
        if not email or not password:
            self.status_label.config(text="❌ Please fill in all fields")
            return
            
        if not self.validate_email(email):
            self.status_label.config(text="❌ Invalid email format")
            return
            
        # Simulate login verification
        self.login_button.config(state=DISABLED, text="🔄 Logging in...")
        self.window.after(1500, lambda: self.process_login(email, password))
        
    def process_login(self, email, password):
        # Save credentials if remember me is checked
        if self.remember_var.get():
            self.save_credentials(email, password)
            
        self.window.destroy()
        self.on_login_success(email)
        
    def show_register(self):
        RegisterWindow(self.window)
        
    def save_credentials(self, email, password):
        data = {'email': email, 'password': password}
        Path('credentials.json').write_text(json.dumps(data))
        
    def load_saved_credentials(self):
        try:
            if Path('credentials.json').exists():
                data = json.loads(Path('credentials.json').read_text())
                self.email_entry.insert(0, data.get('email', ''))
                self.password_entry.insert(0, data.get('password', ''))
                self.remember_var.set(True)
        except:
            pass
            
    def run(self):
        self.window.mainloop()

class RegisterWindow:
    def __init__(self, parent):
        self.window = Toplevel(parent)
        self.window.title("📝 Register New Account")
        self.window.geometry("400x500")
        self.window.configure(bg='#2C3E50')
        
        # Register frame
        self.register_frame = Frame(self.window, bg='#34495E', padx=20, pady=20)
        self.register_frame.pack(fill=X, padx=20, pady=20)
        
        # Fields
        fields = [
            ("👤 Full Name", "name"),
            ("📧 Email", "email"),
            ("🔑 Password", "password"),
            ("🔄 Confirm Password", "confirm_password")
        ]
        
        self.entries = {}
        for label_text, key in fields:
            Label(
                self.register_frame,
                text=label_text,
                bg='#34495E',
                fg='white',
                font=("Rubik", 12)
            ).pack(pady=5)
            
            entry = Entry(
                self.register_frame,
                font=("Rubik", 12),
                bg='#ECF0F1'
            )
            if 'password' in key:
                entry.config(show="•")
            entry.pack(fill=X, pady=5)
            self.entries[key] = entry
            
        # Register button
        Button(
            self.register_frame,
            text="📝 Register",
            command=self.register,
            bg='#27AE60',
            fg='white',
            font=("Rubik", 12, "bold"),
            width=15,
            height=2,
            relief=FLAT
        ).pack(pady=20)
        
        # Status label
        self.status_label = Label(
            self.register_frame,
            text="",
            bg='#34495E',
            fg='#E74C3C',
            font=("Rubik", 10)
        )
        self.status_label.pack(pady=5)
        
    def register(self):
        # Validate fields
        if not all(entry.get() for entry in self.entries.values()):
            self.status_label.config(text="❌ Please fill in all fields")
            return
            
        if self.entries['password'].get() != self.entries['confirm_password'].get():
            self.status_label.config(text="❌ Passwords don't match")
            return
            
        # Simulate registration success
        self.status_label.config(text="✅ Registration successful!", fg='#27AE60')
        self.window.after(1500, self.window.destroy)

class AnimatedLabel(Label):
    def __init__(self, master, **kwargs):
        super().__init__(master, **kwargs)
        self.colors = ['#FF5733', '#33FF57', '#3357FF', '#FF33F5']
        self.current_color = 0
        
    def animate(self):
        self.configure(fg=self.colors[self.current_color])
        self.current_color = (self.current_color + 1) % len(self.colors)
        self.after(1000, self.animate)

class LoadingBar:
    def __init__(self, master, width=300):
        self.progress = ttk.Progressbar(
            master, 
            orient="horizontal",
            length=width,
            mode="determinate"
        )
        self.progress.pack(pady=10)
        self.progress.pack_forget()
        
    def start(self):
        self.progress.pack(pady=10)
        self.progress["value"] = 0
        
    def update(self, value):
        self.progress["value"] = value
        
    def hide(self):
        self.progress.pack_forget()

class TabView:
    """A tabbed interface component for the application"""
    def __init__(self, parent):
        self.parent = parent
        self.tabs = {}
        self.current_tab = None
        self.tab_bar = Frame(parent, bg=ThemeColors.PRIMARY)
        self.tab_bar.pack(fill=X, padx=10, pady=5)
        self.content_frame = Frame(parent, bg=ThemeColors.SECONDARY)
        self.content_frame.pack(fill=BOTH, expand=True, padx=10, pady=5)
        
    def add_tab(self, name, title, content_frame):
        """Add a new tab to the view"""
        tab_button = Button(
            self.tab_bar,
            text=title,
            bg=ThemeColors.PRIMARY,
            fg=ThemeColors.TEXT_LIGHT,
            font=(CustomFont.MEDIUM, CustomFont.BODY),
            bd=0,
            padx=15,
            pady=8,
            relief=FLAT,
            command=lambda: self.show_tab(name)
        )
        tab_button.pack(side=LEFT, padx=2)
        
        content_frame.pack_forget()
        self.tabs[name] = {
            "button": tab_button,
            "frame": content_frame,
            "title": title
        }
        
        # If this is the first tab, show it
        if not self.current_tab:
            self.show_tab(name)
            
    def show_tab(self, name):
        """Switch to the specified tab"""
        if name in self.tabs:
            # Hide current tab if any
            if self.current_tab and self.current_tab in self.tabs:
                self.tabs[self.current_tab]["frame"].pack_forget()
                self.tabs[self.current_tab]["button"].config(
                    bg=ThemeColors.PRIMARY,
                    fg=ThemeColors.TEXT_LIGHT
                )
                
            # Show the new tab
            self.tabs[name]["frame"].pack(fill=BOTH, expand=True)
            self.tabs[name]["button"].config(
                bg=ThemeColors.ACCENT,
                fg=ThemeColors.TEXT_LIGHT
            )
            self.current_tab = name

class QRCodeGenerator:
    """Generates QR codes for device pairing"""
    def __init__(self):
        self.qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        
    def generate_qr_code(self, data, size=(300, 300)):
        """Generate a QR code image from the given data"""
        self.qr.clear()
        self.qr.add_data(data)
        self.qr.make(fit=True)
        
        qr_image = self.qr.make_image(fill_color="black", back_color="white")
        qr_image = qr_image.resize(size, Image.LANCZOS)
        return qr_image
        
    def get_tk_image(self, data, size=(300, 300)):
        """Generate a QR code and convert it to a Tkinter compatible image"""
        qr_image = self.generate_qr_code(data, size)
        
        # Convert PIL image to Tkinter compatible image
        img_buffer = io.BytesIO()
        qr_image.save(img_buffer, format="PNG")
        img_buffer.seek(0)
        
        tk_image = ImageTk.PhotoImage(Image.open(img_buffer))
        return tk_image
class DeviceTracker:
    def __init__(self, user_email):
        self.user_email = user_email
        self.db = DatabaseManager()
        self.encryption = EncryptionManager()
        self.rate_limiter = RateLimiter()
        self.qr_generator = QRCodeGenerator()
        self.setup_window()
        
    def setup_window(self):
        self.window = Tk()
        self.window.title(f"{APP_NAME} v{APP_VERSION}")
        self.window.geometry("1024x768")
        self.window.title(f"{APP_NAME} v{APP_VERSION}")
        self.window.geometry("1024x768")
        self.window.configure(bg=ThemeColors.PRIMARY)
        self.window.protocol("WM_DELETE_WINDOW", self.on_closing)
        self.header_frame = Frame(self.window, bg=ThemeColors.PRIMARY)
        self.header_frame.pack(fill=X, pady=10)
        
        Label(
            self.header_frame,
            text=f"{APP_NAME}",
            font=(CustomFont.BOLD, CustomFont.H1),
            bg=ThemeColors.PRIMARY,
            fg=ThemeColors.TEXT_LIGHT
        ).pack(pady=5)
        
        Label(
            self.header_frame,
            text=f"Logged in as: {self.user_email}",
            font=(CustomFont.REGULAR, CustomFont.SMALL),
            bg=ThemeColors.PRIMARY,
            fg=ThemeColors.TEXT_LIGHT
        ).pack(pady=5)
        
        # Setup tab view
        self.tab_view = TabView(self.window)
        
        # Add main tabs
        self.setup_dashboard_tab()
        self.setup_devices_tab()
        self.setup_location_tab()
        self.setup_settings_tab()
        
        # Footer with status
        self.status_frame = Frame(self.window, bg=ThemeColors.PRIMARY)
        self.status_frame.pack(fill=X, side=BOTTOM, pady=5)
        
        self.status_label = Label(
            self.status_frame,
            text="Ready",
            font=(CustomFont.REGULAR, CustomFont.SMALL),
            bg=ThemeColors.PRIMARY,
            fg=ThemeColors.TEXT_LIGHT
        )
        self.status_label.pack(side=LEFT, padx=10)
        
    def setup_dashboard_tab(self):
        frame = Frame(self.window, bg=ThemeColors.SECONDARY)
        
        # Welcome section
        welcome_frame = Frame(frame, bg=ThemeColors.SECONDARY, padx=20, pady=20)
        welcome_frame.pack(fill=X)
        
        Label(
            welcome_frame,
            text="Welcome to Personal Device Locator",
            font=(CustomFont.BOLD, CustomFont.H2),
            bg=ThemeColors.SECONDARY,
            fg=ThemeColors.TEXT_LIGHT
        ).pack(pady=10)
        
        Label(
            welcome_frame,
            text="Track and manage your personal devices securely",
            font=(CustomFont.REGULAR, CustomFont.BODY),
            bg=ThemeColors.SECONDARY,
            fg=ThemeColors.TEXT_LIGHT
        ).pack(pady=5)
        
        # Stats section
        stats_frame = Frame(frame, bg=ThemeColors.SECONDARY, padx=20, pady=20)
        stats_frame.pack(fill=X)
        
        stats = [
            ("Registered Devices", "0", ThemeColors.ACCENT),
            ("Active Sharing", "0", ThemeColors.SUCCESS),
            ("Location Updates", "0", ThemeColors.WARNING)
        ]
        
        for title, value, color in stats:
            stat_frame = Frame(stats_frame, bg=ThemeColors.PRIMARY, padx=15, pady=15)
            stat_frame.pack(side=LEFT, padx=10, expand=True, fill=X)
            
            Label(
                stat_frame,
                text=title,
                font=(CustomFont.MEDIUM, CustomFont.BODY),
                bg=ThemeColors.PRIMARY,
                fg=ThemeColors.TEXT_LIGHT
            ).pack(pady=5)
            
            Label(
                stat_frame,
                text=value,
                font=(CustomFont.BOLD, CustomFont.H2),
                bg=ThemeColors.PRIMARY,
                fg=color
            ).pack(pady=5)
        
        # Recent activity section
        activity_frame = Frame(frame, bg=ThemeColors.SECONDARY, padx=20, pady=20)
        activity_frame.pack(fill=BOTH, expand=True)
        
        Label(
            activity_frame,
            text="Recent Activity",
            font=(CustomFont.BOLD, CustomFont.H3),
            bg=ThemeColors.SECONDARY,
            fg=ThemeColors.TEXT_LIGHT
        ).pack(pady=10, anchor=W)
        
        # Activity list (placeholder)
        activity_list = Listbox(
            activity_frame,
            bg=ThemeColors.PRIMARY,
            fg=ThemeColors.TEXT_LIGHT,
            font=(CustomFont.REGULAR, CustomFont.BODY),
            relief=FLAT,
            highlightthickness=0,
            bd=0
        )
        activity_list.pack(fill=BOTH, expand=True, pady=10)
        
        self.tab_view.add_tab("dashboard", "📊 Dashboard", frame)
        
    def setup_devices_tab(self):
        frame = Frame(self.window, bg=ThemeColors.SECONDARY)
        
        # Device management header
        header_frame = Frame(frame, bg=ThemeColors.SECONDARY, padx=20, pady=10)
        header_frame.pack(fill=X)
        
        Label(
            header_frame,
            text="Manage Your Devices",
            font=(CustomFont.BOLD, CustomFont.H2),
            bg=ThemeColors.SECONDARY,
            fg=ThemeColors.TEXT_LIGHT
        ).pack(side=LEFT, pady=10)
        
        Button(
            header_frame,
            text="+ Add Device",
            bg=ThemeColors.SUCCESS,
            fg=ThemeColors.TEXT_LIGHT,
            font=(CustomFont.MEDIUM, CustomFont.BODY),
            relief=FLAT,
            padx=15,
            pady=5,
            command=self.show_add_device_dialog
        ).pack(side=RIGHT, pady=10)
        
        # Devices list frame
        devices_list_frame = Frame(frame, bg=ThemeColors.SECONDARY, padx=20, pady=10)
        devices_list_frame.pack(fill=BOTH, expand=True)
        
        # Devices list header
        device_header = Frame(devices_list_frame, bg=ThemeColors.PRIMARY)
        device_header.pack(fill=X, pady=5)
        
        headers = ["Device Name", "Type", "Status", "Last Seen", "Actions"]
        weights = [3, 2, 2, 3, 2]
        
        for i, header in enumerate(headers):
            header_frame = Frame(device_header, bg=ThemeColors.PRIMARY)
            header_frame.grid(row=0, column=i, sticky='ew', padx=5)
            header_frame.grid_columnconfigure(0, weight=weights[i])
            
            Label(
                header_frame,
                text=header,
                font=(CustomFont.MEDIUM, CustomFont.BODY),
                bg=ThemeColors.PRIMARY,
                fg=ThemeColors.TEXT_LIGHT
            ).pack(pady=5)
            
        # Devices list (scrollable)
        devices_canvas = Canvas(devices_list_frame, bg=ThemeColors.SECONDARY, highlightthickness=0)
        scrollbar = ttk.Scrollbar(devices_list_frame, orient=VERTICAL, command=devices_canvas.yview)
        devices_canvas.configure(yscrollcommand=scrollbar.set)
        
        # Pack scrollbar and canvas
        scrollbar.pack(side=RIGHT, fill=Y)
        devices_canvas.pack(side=LEFT, fill=BOTH, expand=True)
        
        # Create a frame for the devices
        self.devices_frame = Frame(devices_canvas, bg=ThemeColors.SECONDARY)
        devices_canvas.create_window((0, 0), window=self.devices_frame, anchor=NW)
        
        # Update scroll region when the frame changes
        self.devices_frame.bind('<Configure>', lambda e: devices_canvas.configure(
            scrollregion=devices_canvas.bbox("all")
        ))
        
        self.tab_view.add_tab("devices", "📱 Devices", frame)
        
        # Load devices
        self.load_devices()
        
    def load_devices(self):
        """Load and display the user's registered devices"""
        # Clear existing devices
        for widget in self.devices_frame.winfo_children():
            widget.destroy()
            
        # Get devices from database
        # For demo purposes, we'll create some sample devices
        sample_devices = [
            {
                "id": "device1",
                "name": "My Smartphone",
                "device_type": "smartphone", 
                "is_verified": 1,
                "last_seen": datetime.now() - timedelta(minutes=5),
                "consent_given": 1
            },
            {
                "id": "device2",
                "name": "Work Laptop",
                "device_type": "laptop",
                "is_verified": 1,
                "last_seen": datetime.now() - timedelta(hours=2),
                "consent_given": 1
            },
            {
                "id": "device3",
                "name": "Tablet",
                "device_type": "tablet",
                "is_verified": 0,
                "last_seen": None,
                "consent_given": 0
            }
        ]
        
        # Display each device
        for i, device in enumerate(sample_devices):
            device_frame = Frame(self.devices_frame, bg=ThemeColors.PRIMARY, padx=10, pady=10)
            device_frame.pack(fill=X, pady=5, padx=10)
            
            # Device info
            info_frame = Frame(device_frame, bg=ThemeColors.PRIMARY)
            info_frame.pack(side=LEFT, fill=X, expand=True)
            
            Label(
                info_frame,
                text=device["name"],
                font=(CustomFont.MEDIUM, CustomFont.BODY),
                bg=ThemeColors.PRIMARY,
                fg=ThemeColors.TEXT_LIGHT
            ).pack(anchor=W)
            
            Label(
                info_frame,
                text=device["device_type"].capitalize(),
                font=(CustomFont.REGULAR, CustomFont.SMALL),
                bg=ThemeColors.PRIMARY,
                fg=ThemeColors.GRAY
            ).pack(anchor=W)
            
            # Status indicator
            status_color = ThemeColors.SUCCESS if device["is_verified"] else ThemeColors.WARNING
            status_text = "Verified" if device["is_verified"] else "Pending Verification"
            
            status_frame = Frame(device_frame, bg=ThemeColors.PRIMARY)
            status_frame.pack(side=LEFT, padx=10)
            
            Label(
                status_frame,
                text=status_text,
                font=(CustomFont.REGULAR, CustomFont.SMALL),
                bg=ThemeColors.PRIMARY,
                fg=status_color
            ).pack()
            
            # Last seen
            last_seen_frame = Frame(device_frame, bg=ThemeColors.PRIMARY)
            last_seen_frame.pack(side=LEFT, padx=10)
            
            if device["last_seen"]:
                last_seen_text = device["last_seen"].strftime("%Y-%m-%d %H:%M")
            else:
                last_seen_text = "Never"
                
            Label(
                last_seen_frame,
                text=last_seen_text,
                font=(CustomFont.REGULAR, CustomFont.SMALL),
                bg=ThemeColors.PRIMARY,
                fg=ThemeColors.GRAY
            ).pack()
            
            # Actions
            actions_frame = Frame(device_frame, bg=ThemeColors.PRIMARY)
            actions_frame.pack(side=RIGHT, padx=10)
            
            Button(
                actions_frame,
                text="📍 Locate",
                bg=ThemeColors.ACCENT,
                fg=ThemeColors.TEXT_LIGHT,
                font=(CustomFont.REGULAR, CustomFont.SMALL),
                relief=FLAT,
                padx=10,
                command=lambda d=device: self.locate_device(d)
            ).pack(side=LEFT, padx=2)
            
            Button(
                actions_frame,
                text="❌ Remove",
                bg=ThemeColors.ERROR,
                fg=ThemeColors.TEXT_LIGHT,
                font=(CustomFont.REGULAR, CustomFont.SMALL),
                relief=FLAT,
                padx=10,
                command=lambda d=device: self.remove_device(d)
            ).pack(side=LEFT, padx=2)
            
    def locate_device(self, device):
        """Request location for the specified device"""
        messagebox.showinfo("Locate Device", f"Locating {device['name']}...")
        
        # For demo purposes, let's update the map with a sample location
        try:
            if hasattr(self, 'map_view'):
                # Random coordinates near San Francisco for demo
                import random
                lat = 37.7749 + (random.random() - 0.5) * 0.01
                lng = -122.4194 + (random.random() - 0.5) * 0.01
                self.map_view.update_device_location(
                    device['id'], 
                    lat, 
                    lng, 
                    f"{device['name']} ({DeviceIcons.get_icon(device['device_type'])})"
                )
                
                # Update last seen time
                self.last_update_label.config(text=f"Last update: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        except Exception as e:
            logger.error(f"Error updating map: {e}")
        
    def remove_device(self, device):
        """Remove the specified device from user's account"""
        confirm = messagebox.askyesno(
            "Confirm Removal", 
            f"Are you sure you want to remove {device['name']}?\nThis will delete all location data for this device."
        )
        if confirm:
            messagebox.showinfo("Device Removed", f"{device['name']} has been removed.")
            self.load_devices()  # Refresh the list
            
    def generate_device_code(self, dialog, name, device_type):
        """Generate a pairing code for the device and display QR code"""
        if not name:
            messagebox.showerror("Error", "Please enter a device name")
            return
            
        # Generate a unique device ID and pairing code
        device_id = str(uuid.uuid4())
        pairing_code = ''.join([str(uuid.uuid4().int)[:6] for _ in range(1)])
        
        # Create pairing data
        pairing_data = {
            "device_id": device_id,
            "pairing_code": pairing_code,
            "app": APP_NAME,
            "timestamp": datetime.now().timestamp()
        }
        
        # Create QR code frame
        qr_frame = Frame(dialog, bg=ThemeColors.SECONDARY)
        qr_frame.pack(fill=BOTH, expand=True, padx=20, pady=20)
        
        # Generate QR code
        qr_image = self.qr_generator.get_tk_image(json.dumps(pairing_data))
        qr_label = Label(qr_frame, image=qr_image, bg=ThemeColors.SECONDARY)
        qr_label.image = qr_image  # Keep a reference to prevent garbage collection
        qr_label.pack(pady=10)
        
        # Display pairing instructions
        Label(
            qr_frame,
            text="Scan this QR code with your device to pair it",
            font=(CustomFont.MEDIUM, CustomFont.BODY),
            bg=ThemeColors.SECONDARY,
            fg=ThemeColors.TEXT_LIGHT
        ).pack(pady=5)
        
        # Display the pairing code for manual entry
        Label(
            qr_frame,
            text=f"Manual pairing code: {pairing_code}",
            font=(CustomFont.REGULAR, CustomFont.BODY),
            bg=ThemeColors.SECONDARY,
            fg=ThemeColors.ACCENT
        ).pack(pady=5)
        
        # Register the device in the database
        # self.db.register_device(user_id, name, device_type, device_id)
        
    def setup_location_tab(self):
        frame = Frame(self.window, bg=ThemeColors.SECONDARY)
        
        # Location tracking header
        header_frame = Frame(frame, bg=ThemeColors.SECONDARY, padx=20, pady=10)
        header_frame.pack(fill=X)
        
        Label(
            header_frame,
            text="Location Tracking",
            font=(CustomFont.BOLD, CustomFont.H2),
            bg=ThemeColors.SECONDARY,
            fg=ThemeColors.TEXT_LIGHT
        ).pack(side=LEFT, pady=10)
        
        # Last update time
        self.last_update_label = Label(
            header_frame,
            text="Last update: Never",
            font=(CustomFont.REGULAR, CustomFont.SMALL),
            bg=ThemeColors.SECONDARY,
            fg=ThemeColors.GRAY
        )
        self.last_update_label.pack(side=RIGHT, pady=10)
        
        # Location map frame with MapView
        try:
            self.map_view = MapView(frame, bg=ThemeColors.PRIMARY, padx=20, pady=20)
            self.map_view.pack(fill=BOTH, expand=True, padx=20, pady=10)
        except Exception as e:
            logger.error(f"Failed to create map view: {e}")
            # Fallback to placeholder
            map_frame = Frame(frame, bg=ThemeColors.PRIMARY, padx=20, pady=20)
            map_frame.pack(fill=BOTH, expand=True, padx=20, pady=10)
            
            Label(
                map_frame,
                text="Location Map View\n(Map integration not available)",
                font=(CustomFont.REGULAR, CustomFont.BODY),
                bg=ThemeColors.PRIMARY,
                fg=ThemeColors.TEXT_LIGHT
            ).pack(expand=True)
        
        # Location history
        history_frame = Frame(frame, bg=ThemeColors.SECONDARY, padx=20, pady=10)
        history_frame.pack(fill=X)
        
        Label(
            history_frame,
            text="Location History",
            font=(CustomFont.BOLD, CustomFont.H3),
            bg=ThemeColors.SECONDARY,
            fg=ThemeColors.TEXT_LIGHT
        ).pack(anchor=W, pady=5)
        
        self.history_list = Listbox(
            history_frame,
            bg=ThemeColors.PRIMARY,
            fg=ThemeColors.TEXT_LIGHT,
            font=(CustomFont.REGULAR, CustomFont.BODY),
            height=6,
            relief=FLAT
        )
        self.history_list.pack(fill=X, pady=5)
        
        self.tab_view.add_tab("location", "📍 Location", frame)
        
    def setup_settings_tab(self):
        frame = Frame(self.window, bg=ThemeColors.SECONDARY)
        
        # Settings header
        Label(
            frame,
            text="Settings",
            font=(CustomFont.BOLD, CustomFont.H2),
            bg=ThemeColors.SECONDARY,
            fg=ThemeColors.TEXT_LIGHT
        ).pack(pady=20)
        
        # Settings sections
        sections = [
            ("Account Settings", [
                ("Enable 2FA", "toggle_2fa"),
                ("Change Password", "change_password"),
                ("Update Email", "update_email")
            ]),
            ("Privacy Settings", [
                ("Location History Retention", "retention_period"),
                ("Auto-delete Old Data", "auto_delete"),
                ("Export My Data", "export_data")
            ]),
            ("Notifications", [
                ("Email Notifications", "email_notifications"),
                ("Desktop Notifications", "desktop_notifications"),
                ("Location Alerts", "location_alerts")
            ])
        ]
        
        for section_title, settings in sections:
            section_frame = Frame(frame, bg=ThemeColors.SECONDARY, padx=20, pady=10)
            section_frame.pack(fill=X, pady=5)
            
            Label(
                section_frame,
                text=section_title,
                font=(CustomFont.MEDIUM, CustomFont.H3),
                bg=ThemeColors.SECONDARY,
                fg=ThemeColors.TEXT_LIGHT
            ).pack(anchor=W, pady=5)
            
            for setting_name, setting_id in settings:
                setting_frame = Frame(section_frame, bg=ThemeColors.PRIMARY, padx=15, pady=10)
                setting_frame.pack(fill=X, pady=2)
                
                Label(
                    setting_frame,
                    text=setting_name,
                    font=(CustomFont.REGULAR, CustomFont.BODY),
                    bg=ThemeColors.PRIMARY,
                    fg=ThemeColors.TEXT_LIGHT
                ).pack(side=LEFT)
                
                if setting_id.startswith("toggle"):
                    # Toggle switch
                    switch_var = BooleanVar()
                    switch = ttk.Checkbutton(
                        setting_frame,
                        variable=switch_var,
                        style="Switch.TCheckbutton"
                    )
                    switch.pack(side=RIGHT)
                else:
                    # Action button
                    Button(
                        setting_frame,
                        text="Configure",
                        bg=ThemeColors.ACCENT,
                        fg=ThemeColors.TEXT_LIGHT,
                        font=(CustomFont.REGULAR, CustomFont.SMALL),
                        relief=FLAT,
                        padx=10,
                        command=lambda s=setting_id: self.handle_setting(s)
                    ).pack(side=RIGHT)
        
        self.tab_view.add_tab("settings", "⚙️ Settings", frame)
        
    def handle_setting(self, setting_id):
        """Handle setting configuration actions"""
        if setting_id == "change_password":
            self.show_change_password_dialog()
        elif setting_id == "update_email":
            self.show_update_email_dialog()
        elif setting_id == "retention_period":
            self.show_retention_settings()
        elif setting_id == "export_data":
            self.export_user_data()
        else:
            messagebox.showinfo("Not Implemented", "This feature is coming soon!")
            
    def show_change_password_dialog(self):
        dialog = Toplevel(self.window)
        dialog.title("Change Password")
        dialog.geometry("400x300")
        dialog.configure(bg=ThemeColors.SECONDARY)
        
        Label(
            dialog,
            text="Change Password",
            font=(CustomFont.BOLD, CustomFont.H2),
            bg=ThemeColors.SECONDARY,
            fg=ThemeColors.TEXT_LIGHT
        ).pack(pady=20)
        
        # Current password
        Label(
            dialog,
            text="Current Password",
            font=(CustomFont.REGULAR, CustomFont.BODY),
            bg=ThemeColors.SECONDARY,
            fg=ThemeColors.TEXT_LIGHT
        ).pack(pady=5)
        
        current_pass = Entry(dialog, show="•", font=(CustomFont.REGULAR, CustomFont.BODY))
        current_pass.pack(padx=20, fill=X)
        
        # New password
        Label(
            dialog,
            text="New Password",
            font=(CustomFont.REGULAR, CustomFont.BODY),
            bg=ThemeColors.SECONDARY,
            fg=ThemeColors.TEXT_LIGHT
        ).pack(pady=5)
        
        new_pass = Entry(dialog, show="•", font=(CustomFont.REGULAR, CustomFont.BODY))
        new_pass.pack(padx=20, fill=X)
        
        # Confirm new password
        Label(
            dialog,
            text="Confirm New Password",
            font=(CustomFont.REGULAR, CustomFont.BODY),
            bg=ThemeColors.SECONDARY,
            fg=ThemeColors.TEXT_LIGHT
        ).pack(pady=5)
        
        confirm_pass = Entry(dialog, show="•", font=(CustomFont.REGULAR, CustomFont.BODY))
        confirm_pass.pack(padx=20, fill=X)
        
        # Update button
        Button(
            dialog,
            text="Update Password",
            bg=ThemeColors.SUCCESS,
            fg=ThemeColors.TEXT_LIGHT,
            font=(CustomFont.MEDIUM, CustomFont.BODY),
            relief=FLAT,
            command=lambda: self.update_password(
                current_pass.get(),
                new_pass.get(),
                confirm_pass.get(),
                dialog
            )
        ).pack(pady=20)
    
    def update_password(self, current_password, new_password, confirm_password, dialog):
        """Update the user's password"""
        if not current_password or not new_password or not confirm_password:
            messagebox.showerror("Error", "Please fill in all fields")
            return
            
        if new_password != confirm_password:
            messagebox.showerror("Error", "New passwords don't match")
            return
            
        if len(new_password) < 8:
            messagebox.showerror("Error", "Password must be at least 8 characters")
            return
            
        # Here we would verify the current password and update with the new one
        # For demo purposes, we'll just show a success message
        messagebox.showinfo("Success", "Password has been updated successfully")
        dialog.destroy()
    
    def show_update_email_dialog(self):
        """Show dialog to update email address"""
        dialog = Toplevel(self.window)
        dialog.title("Update Email")
        dialog.geometry("400x250")
        dialog.configure(bg=ThemeColors.SECONDARY)
        
        Label(
            dialog,
            text="Update Email Address",
            font=(CustomFont.BOLD, CustomFont.H2),
            bg=ThemeColors.SECONDARY,
            fg=ThemeColors.TEXT_LIGHT
        ).pack(pady=20)
        
        # Current email
        Label(
            dialog,
            text=f"Current Email: {self.user_email}",
            font=(CustomFont.REGULAR, CustomFont.BODY),
            bg=ThemeColors.SECONDARY,
            fg=ThemeColors.TEXT_LIGHT
        ).pack(pady=5)
        
        # New email
        Label(
            dialog,
            text="New Email Address",
            font=(CustomFont.REGULAR, CustomFont.BODY),
            bg=ThemeColors.SECONDARY,
            fg=ThemeColors.TEXT_LIGHT
        ).pack(pady=5)
        
        new_email = Entry(dialog, font=(CustomFont.REGULAR, CustomFont.BODY))
        new_email.pack(padx=20, fill=X)
        
        # Update button
        Button(
            dialog,
            text="Update Email",
            bg=ThemeColors.SUCCESS,
            fg=ThemeColors.TEXT_LIGHT,
            font=(CustomFont.MEDIUM, CustomFont.BODY),
            relief=FLAT,
            command=lambda: self.update_email(new_email.get(), dialog)
        ).pack(pady=20)
    
    def update_email(self, new_email, dialog):
        """Update the user's email address"""
        if not new_email:
            messagebox.showerror("Error", "Please enter a new email address")
            return
            
        # Validate email format
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.match(pattern, new_email):
            messagebox.showerror("Error", "Invalid email format")
            return
            
        # Here we would update the email in the database
        # For demo purposes, we'll just show a success message
        messagebox.showinfo("Success", f"Email has been updated to {new_email}")
        self.user_email = new_email
        dialog.destroy()
    
    def show_retention_settings(self):
        """Show dialog to configure data retention settings"""
        dialog = Toplevel(self.window)
        dialog.title("Data Retention Settings")
        dialog.geometry("400x300")
        dialog.configure(bg=ThemeColors.SECONDARY)
        
        Label(
            dialog,
            text="Data Retention Settings",
            font=(CustomFont.BOLD, CustomFont.H2),
            bg=ThemeColors.SECONDARY,
            fg=ThemeColors.TEXT_LIGHT
        ).pack(pady=20)
        
        # Retention period options
        retention_periods = [
            ("Keep data for 30 days", 30),
            ("Keep data for 90 days", 90),
            ("Keep data for 6 months", 180),
            ("Keep data for 1 year", 365),
            ("Keep data indefinitely", -1)
        ]
        
        period_var = IntVar(value=30)
        
        for text, value in retention_periods:
            Radiobutton(
                dialog,
                text=text,
                value=value,
                variable=period_var,
                bg=ThemeColors.SECONDARY,
                fg=ThemeColors.TEXT_LIGHT,
                selectcolor=ThemeColors.PRIMARY
            ).pack(anchor=W, padx=20, pady=2)
        
        # Save button
        Button(
            dialog,
            text="Save Settings",
            bg=ThemeColors.SUCCESS,
            fg=ThemeColors.TEXT_LIGHT,
            font=(CustomFont.MEDIUM, CustomFont.BODY),
            relief=FLAT,
            command=lambda: self.save_retention_settings(period_var.get(), dialog)
        ).pack(pady=20)
    
    def save_retention_settings(self, days, dialog):
        """Save the data retention settings"""
        if days == -1:
            period_text = "indefinitely"
        else:
            period_text = f"for {days} days"
            
        messagebox.showinfo("Success", f"Location data will be kept {period_text}")
        dialog.destroy()
    
    def export_user_data(self):
        """Export user data to a file"""
        export_path = f"user_data_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        # For demo purposes, we'll create a sample data structure
        sample_data = {
            "user": {
                "email": self.user_email,
                "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            },
            "devices": [
                {
                    "name": "My Smartphone",
                    "type": "smartphone",
                    "last_seen": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                },
                {
                    "name": "Work Laptop",
                    "type": "laptop",
                    "last_seen": (datetime.now() - timedelta(hours=2)).strftime("%Y-%m-%d %H:%M:%S")
                }
            ],
            "location_history": [
                {
                    "device": "My Smartphone",
                    "location": "37.7749,-122.4194",
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                },
                {
                    "device": "My Smartphone",
                    "location": "37.7748,-122.4193",
                    "timestamp": (datetime.now() - timedelta(hours=1)).strftime("%Y-%m-%d %H:%M:%S")
                }
            ]
        }
        
        # Write the data to a file
        try:
            with open(export_path, 'w') as f:
                json.dump(sample_data, f, indent=4)
            messagebox.showinfo("Export Successful", f"Data exported to {export_path}")
        except Exception as e:
            messagebox.showerror("Export Failed", f"Error exporting data: {str(e)}")
    
    def show_add_device_dialog(self):
        """Show dialog to add a new device"""
        dialog = Toplevel(self.window)
        dialog.title("Add New Device")
        dialog.geometry("400x500")
        dialog.configure(bg=ThemeColors.SECONDARY)
        
        # Device details form
        Label(
            dialog,
            text="Add New Device",
            font=(CustomFont.BOLD, CustomFont.H2),
            bg=ThemeColors.SECONDARY,
            fg=ThemeColors.TEXT_LIGHT
        ).pack(pady=20)
        
        # Device name
        Label(
            dialog,
            text="Device Name",
            font=(CustomFont.REGULAR, CustomFont.BODY),
            bg=ThemeColors.SECONDARY,
            fg=ThemeColors.TEXT_LIGHT
        ).pack(pady=5)
        
        name_entry = Entry(
            dialog,
            font=(CustomFont.REGULAR, CustomFont.BODY),
            bg=ThemeColors.TEXT_LIGHT
        )
        name_entry.pack(padx=20, fill=X)
        
        # Device type
        Label(
            dialog,
            text="Device Type",
            font=(CustomFont.REGULAR, CustomFont.BODY),
            bg=ThemeColors.SECONDARY,
            fg=ThemeColors.TEXT_LIGHT
        ).pack(pady=5)
        
        type_var = StringVar(value="smartphone")
        device_types = [
            ("Smartphone", "smartphone"),
            ("Tablet", "tablet"),
            ("Laptop", "laptop"),
            ("Desktop", "desktop"),
            ("Other", "other")
        ]
        
        type_frame = Frame(dialog, bg=ThemeColors.SECONDARY)
        type_frame.pack(fill=X, padx=20)
        
        for text, value in device_types:
            Radiobutton(
                type_frame,
                text=text,
                value=value,
                variable=type_var,
                bg=ThemeColors.SECONDARY,
                fg=ThemeColors.TEXT_LIGHT,
                selectcolor=ThemeColors.PRIMARY
            ).pack(anchor=W)
        
        # Add button
        Button(
            dialog,
            text="Generate Pairing Code",
            bg=ThemeColors.SUCCESS,
            fg=ThemeColors.TEXT_LIGHT,
            font=(CustomFont.MEDIUM, CustomFont.BODY),
            relief=FLAT,
            command=lambda: self.generate_device_code(dialog, name_entry.get(), type_var.get())
        ).pack(pady=20)
    
    def cleanup(self):
        """Cleanup resources before closing"""
        # Stop location updater if running
        if hasattr(self, 'location_updater'):
            self.location_updater.stop()
        
        # Remove temporary map file if it exists
        if hasattr(self, 'map_view') and hasattr(self.map_view, 'map_file') and os.path.exists(self.map_view.map_file):
            try:
                os.remove(self.map_view.map_file)
            except Exception as e:
                logger.error(f"Error removing temporary map file: {e}")
                pass
    
    def on_closing(self):
        """Handle window closing"""
        self.cleanup()
        self.window.destroy()
    
    def run(self):
        """Start the device tracker application"""
        self.window.mainloop()

def main():
    """Main entry point for the application"""
    # Initialize fonts
    if not FontManager.load_rubik_font():
        print("Warning: Could not load custom fonts. Using system defaults.")
    
    # Create login window
    def start_main_app(user_email):
        app = DeviceTracker(user_email)
        app.run()
    
    login_window = LoginWindow(on_login_success=start_main_app)
    login_window.run()

if __name__ == "__main__":
    main()

import unittest
from unittest.mock import MagicMock, patch
import os
import sqlite3
from datetime import datetime, timedelta
import json
import time
import sys

# Create more comprehensive mocks for Tkinter
class MockTk:
    def __init__(self, *args, **kwargs):
        pass
    
    def title(self, *args, **kwargs):
        pass
    
    def geometry(self, *args, **kwargs):
        pass
    
    def configure(self, *args, **kwargs):
        pass
    
    def protocol(self, *args, **kwargs):
        pass
    
    def mainloop(self, *args, **kwargs):
        pass
    
    def destroy(self, *args, **kwargs):
        pass

class MockWidget:
    def __init__(self, *args, **kwargs):
        self.children = []
        
    def pack(self, *args, **kwargs):
        return None
    
    def grid(self, *args, **kwargs):
        return None
    
    def place(self, *args, **kwargs):
        return None
        
    def configure(self, *args, **kwargs):
        return None
    
    def destroy(self, *args, **kwargs):
        return None
    
    def pack_forget(self, *args, **kwargs):
        return None
    
    def bind(self, *args, **kwargs):
        return None
    
    def get(self, *args, **kwargs):
        return ""
    
    def insert(self, *args, **kwargs):
        return None
    
    def delete(self, *args, **kwargs):
        return None

# Create specialized widgets
class MockFrame(MockWidget):
    pass

class MockLabel(MockWidget):
    pass

class MockButton(MockWidget):
    pass

class MockEntry(MockWidget):
    pass

class MockListbox(MockWidget):
    pass

class MockCheckbutton(MockWidget):
    pass

class MockRadiobutton(MockWidget):
    pass

class MockCanvas(MockWidget):
    def create_window(self, *args, **kwargs):
        return None
    
    def yview(self, *args, **kwargs):
        return None
    
    def configure(self, *args, **kwargs):
        return None
    
    def bbox(self, *args, **kwargs):
        return (0, 0, 100, 100)

# Create a mock tkinter module
mock_tkinter = MagicMock()
mock_tkinter.Tk = MockTk
mock_tkinter.Frame = MockFrame
mock_tkinter.Label = MockLabel
mock_tkinter.Button = MockButton
mock_tkinter.Entry = MockEntry
mock_tkinter.Listbox = MockListbox
mock_tkinter.Checkbutton = MockCheckbutton
mock_tkinter.Radiobutton = MockRadiobutton
mock_tkinter.Canvas = MockCanvas
mock_tkinter.StringVar = MagicMock
mock_tkinter.IntVar = MagicMock
mock_tkinter.BooleanVar = MagicMock
mock_tkinter.FLAT = "flat"
mock_tkinter.DISABLED = "disabled"
mock_tkinter.NORMAL = "normal"
mock_tkinter.LEFT = "left"
mock_tkinter.RIGHT = "right"
mock_tkinter.TOP = "top"
mock_tkinter.BOTTOM = "bottom"
mock_tkinter.X = "x"
mock_tkinter.Y = "y"
mock_tkinter.BOTH = "both"
mock_tkinter.NW = "nw"
mock_tkinter.Toplevel = MockTk

# Mock ttk module
mock_ttk = MagicMock()
mock_ttk.Progressbar = MockWidget
mock_ttk.Checkbutton = MockCheckbutton
mock_ttk.Scrollbar = MockWidget

# Mock PIL modules
mock_pil = MagicMock()
mock_pil_image = MagicMock()
mock_pil_imagetk = MagicMock()
mock_pil.Image = mock_pil_image
mock_pil_image.LANCZOS = "lanczos"
mock_pil_image.open = MagicMock(return_value=MagicMock())

# Mock qrcode
mock_qrcode = MagicMock()
mock_qrcode.QRCode = MagicMock()
mock_qrcode.constants = MagicMock()
mock_qrcode.constants.ERROR_CORRECT_L = "L"

# Install the mocks
sys.modules['tkinter'] = mock_tkinter
sys.modules['tkinter.ttk'] = mock_ttk
sys.modules['tkinter.font'] = MagicMock()
sys.modules['PIL'] = mock_pil
sys.modules['PIL.Image'] = mock_pil_image
sys.modules['PIL.ImageTk'] = mock_pil_imagetk
sys.modules['qrcode'] = mock_qrcode

# Now we can safely import our classes
from CyberTrack import (
    DatabaseManager,
    EncryptionManager,
    Validator,
    RateLimiter
)

# DeviceTracker is not included as it's heavily GUI-dependent
class TestDatabaseManager(unittest.TestCase):
    def setUp(self):
        """Set up test database"""
        self.test_db_path = "test_device_locator.db"
        
        # Remove any existing test database
        if os.path.exists(self.test_db_path):
            os.remove(self.test_db_path)
            
        # Create a fresh database manager
        self.db = DatabaseManager()
        
        # Override the db path for testing
        self.db.db_path = self.test_db_path
        
        # Explicitly create tables
        self.db._create_tables()
        
    def tearDown(self):
        """Clean up test database after tests"""
        if os.path.exists(self.test_db_path):
            os.remove(self.test_db_path)
    
    def test_create_user(self):
        """Test user creation with valid data"""
        user_id = self.db.create_user("Test User", "test@example.com", "SecurePassword123")
        self.assertIsNotNone(user_id)
        
        # Verify user exists
        with sqlite3.connect(self.test_db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT name, email FROM users WHERE id = ?", (user_id,))
            result = cursor.fetchone()
            self.assertEqual(result[0], "Test User")
            self.assertEqual(result[1], "test@example.com")
    
    def test_verify_user(self):
        """Test user verification with correct credentials"""
        # Create a test user
        user_id = self.db.create_user("Test User", "verify@example.com", "SecurePassword123")
        
        # Test verification with correct credentials
        result = self.db.verify_user("verify@example.com", "SecurePassword123")
        self.assertIsNotNone(result)
        self.assertEqual(result["user_id"], user_id)
        
        # Test verification with incorrect password
        result = self.db.verify_user("verify@example.com", "WrongPassword")
        self.assertIsNone(result)
        
        # Test verification with nonexistent email
        result = self.db.verify_user("nonexistent@example.com", "AnyPassword")
        self.assertIsNone(result)
    
    def test_enable_2fa(self):
        """Test enabling 2FA for a user"""
        # Create a test user
        user_id = self.db.create_user("2FA User", "2fa@example.com", "SecurePassword123")
        
        # Enable 2FA
        result = self.db.enable_2fa(user_id)
        self.assertTrue(result)
        
        # Verify 2FA is enabled
        with sqlite3.connect(self.test_db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT is_2fa_enabled FROM users WHERE id = ?", (user_id,))
            is_enabled = cursor.fetchone()[0]
            self.assertEqual(is_enabled, 1)
    
    def test_register_device(self):
        """Test registering a new device"""
        # Create a test user
        user_id = self.db.create_user("Device User", "device@example.com", "SecurePassword123")
        
        # Register a device
        device_id, verification_code = self.db.register_device(
            user_id, "Test Phone", "smartphone", "IMEI123456789"
        )
        
        # Verify device is registered
        with sqlite3.connect(self.test_db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT name, device_type FROM devices WHERE id = ?", (device_id,))
            result = cursor.fetchone()
            self.assertEqual(result[0], "Test Phone")
            self.assertEqual(result[1], "smartphone")
    
    def test_verify_device(self):
        """Test device verification process"""
        # Create a test user
        user_id = self.db.create_user("Device User", "device_verify@example.com", "SecurePassword123")
        
        # Register a device
        device_id, verification_code = self.db.register_device(
            user_id, "Test Phone", "smartphone", "IMEI987654321"
        )
        
        # Verify device with correct code
        result = self.db.verify_device(device_id, verification_code)
        self.assertTrue(result)
        
        # Verify device status is updated
        with sqlite3.connect(self.test_db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT is_verified FROM devices WHERE id = ?", (device_id,))
            is_verified = cursor.fetchone()[0]
            self.assertEqual(is_verified, 1)
        
        # Try verifying with incorrect code (should fail)
        new_device_id, new_code = self.db.register_device(
            user_id, "Another Phone", "smartphone", "IMEI111222333"
        )
        result = self.db.verify_device(new_device_id, "wrong_code")
        self.assertFalse(result)
    
    def test_update_device_location(self):
        """Test updating a device's location"""
        # Create a test user and device
        user_id = self.db.create_user("Location User", "location@example.com", "SecurePassword123")
        device_id, _ = self.db.register_device(
            user_id, "GPS Phone", "smartphone", "IMEI444555666"
        )
        
        # Enable consent for location sharing
        self.db.update_device_consent(device_id, True, 24)
        
        # Update location
        location_data = json.dumps({"lat": 37.7749, "lng": -122.4194})
        result = self.db.update_device_location(device_id, location_data)
        self.assertTrue(result)
        
        # Verify location is updated
        with sqlite3.connect(self.test_db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT last_location FROM devices WHERE id = ?", (device_id,))
            stored_location = cursor.fetchone()[0]
            self.assertEqual(stored_location, location_data)
            
            # Verify location history entry is created
            cursor.execute("SELECT location FROM location_history WHERE device_id = ?", (device_id,))
            history_location = cursor.fetchone()[0]
            self.assertEqual(history_location, location_data)
    
    def test_get_user_devices(self):
        """Test retrieving a user's devices"""
        # Create a test user
        user_id = self.db.create_user("Devices User", "devices@example.com", "SecurePassword123")
        
        # Register multiple devices
        self.db.register_device(user_id, "Phone 1", "smartphone", "IMEI-A")
        self.db.register_device(user_id, "Laptop", "laptop", "SN-B")
        self.db.register_device(user_id, "Tablet", "tablet", "SN-C")
        
        # Retrieve devices
        devices = self.db.get_user_devices(user_id)
        
        # Verify correct number of devices
        self.assertEqual(len(devices), 3)
        
        # Verify device names
        device_names = [device["name"] for device in devices]
        self.assertIn("Phone 1", device_names)
        self.assertIn("Laptop", device_names)
        self.assertIn("Tablet", device_names)


class TestValidator(unittest.TestCase):
    def test_validate_device_name(self):
        """Test device name validation"""
        # Valid names
        self.assertTrue(Validator.validate_device_name("My Phone"))
        self.assertTrue(Validator.validate_device_name("Work Laptop 2022"))
        self.assertTrue(Validator.validate_device_name("Alex-iPad"))
        
        # Invalid names - too short
        with self.assertRaises(ValueError):
            Validator.validate_device_name("XY")
            
        # Invalid names - too long
        long_name = "X" * 51
        with self.assertRaises(ValueError):
            Validator.validate_device_name(long_name)
            
        # Invalid names - special characters
        with self.assertRaises(ValueError):
            Validator.validate_device_name("Phone#123!")

    def test_validate_email(self):
        """Test email validation"""
        # Valid emails
        self.assertTrue(Validator.validate_email("user@example.com"))
        self.assertTrue(Validator.validate_email("first.last@domain.co.uk"))
        self.assertTrue(Validator.validate_email("email+tag@gmail.com"))
        
        # Invalid emails
        with self.assertRaises(ValueError):
            Validator.validate_email("not-an-email")
            
        with self.assertRaises(ValueError):
            Validator.validate_email("@missing-username.com")
            
        with self.assertRaises(ValueError):
            Validator.validate_email("no-domain@")

    def test_validate_password(self):
        """Test password validation"""
        # Valid passwords
        self.assertTrue(Validator.validate_password("SecurePass123"))
        self.assertTrue(Validator.validate_password("StrongP@ssw0rd"))
        
        # Invalid - too short
        with self.assertRaises(ValueError):
            Validator.validate_password("Short1")
            
        # Invalid - no uppercase
        with self.assertRaises(ValueError):
            Validator.validate_password("nouppercase123")
            
        # Invalid - no lowercase
        with self.assertRaises(ValueError):
            Validator.validate_password("NOLOWERCASE123")
            
        # Invalid - no number
        with self.assertRaises(ValueError):
            Validator.validate_password("NoNumbersHere")


class TestRateLimiter(unittest.TestCase):
    def setUp(self):
        """Set up a rate limiter for testing"""
        # Configure a strict rate limiter for testing (3 requests in 1 second)
        self.rate_limiter = RateLimiter(max_requests=3, time_window=1)
        
    def test_rate_limiting(self):
        """Test basic rate limiting functionality"""
        test_key = "test_user_1"
        
        # First 3 requests should be allowed
        self.assertTrue(self.rate_limiter.is_allowed(test_key))
        self.assertTrue(self.rate_limiter.is_allowed(test_key))
        self.assertTrue(self.rate_limiter.is_allowed(test_key))
        
        # Fourth request should be denied
        self.assertFalse(self.rate_limiter.is_allowed(test_key))
        
    def test_different_keys(self):
        """Test that different keys have separate rate limits"""
        key1 = "user_a"
        key2 = "user_b"
        
        # Use up the limit for key1
        for _ in range(3):
            self.rate_limiter.is_allowed(key1)
        
        # Key1 should be limited
        self.assertFalse(self.rate_limiter.is_allowed(key1))
        
        # Key2 should still be allowed
        self.assertTrue(self.rate_limiter.is_allowed(key2))
        
    def test_time_window_expiry(self):
        """Test that rate limit resets after time window"""
        test_key = "test_user_2"
        
        # Use up the limit
        for _ in range(3):
            self.rate_limiter.is_allowed(test_key)
        
        # Should be denied immediately
        self.assertFalse(self.rate_limiter.is_allowed(test_key))
        
        # Sleep for just over the time window
        time.sleep(1.1)
        
        # Should be allowed again
        self.assertTrue(self.rate_limiter.is_allowed(test_key))


class TestEncryptionManager(unittest.TestCase):
    def setUp(self):
        """Set up test encryption manager"""
        self.test_key_file = "test_encryption_key.key"
        # Create a patched encryption manager that uses the test key file
        self.encryption = EncryptionManager()
        self.encryption.key_file = self.test_key_file
        self.encryption.key = self.encryption._load_or_create_key()
        
    def tearDown(self):
        """Clean up test key file"""
        if os.path.exists(self.test_key_file):
            os.remove(self.test_key_file)
    
    def test_key_generation(self):
        """Test that a key is generated and saved to file"""
        self.assertTrue(os.path.exists(self.test_key_file))
        with open(self.test_key_file, 'rb') as key_file:
            key = key_file.read()
        self.assertEqual(len(key), 44)  # Fernet keys are 44 bytes long
        
    def test_encrypt_decrypt(self):
        """Test encryption and decryption of data"""
        test_data = "This is sensitive information"
        
        # Encrypt the data
        encrypted = self.encryption.encrypt(test_data)
        self.assertNotEqual(encrypted, test_data.encode())
        
        # Decrypt the data
        decrypted = self.encryption.decrypt(encrypted)
        self.assertEqual(decrypted, test_data)
        
    def test_encrypt_decrypt_binary(self):
        """Test encryption and decryption of binary data"""
        test_data = b"\x00\x01\x02\x03\x04\x05"
        
        # Encrypt the data
        encrypted = self.encryption.encrypt(test_data)
        self.assertNotEqual(encrypted, test_data)
        
        # Decrypt the data
        decrypted = self.encryption.decrypt(encrypted)
        self.assertEqual(decrypted, test_data.decode('utf-8', errors='ignore'))
        
    def test_key_persistence(self):
        """Test that the same key is used across instances"""
        # Get the current key
        original_key = self.encryption.key
        
        # Create a new encryption manager instance
        new_encryption = EncryptionManager()
        new_encryption.key_file = self.test_key_file
        new_encryption.key = new_encryption._load_or_create_key()
        
        # Keys should be the same
        self.assertEqual(original_key, new_encryption.key)
        
        # Encrypt with one, decrypt with the other
        test_data = "Cross-instance encryption test"
        encrypted = self.encryption.encrypt(test_data)
        decrypted = new_encryption.decrypt(encrypted)
        self.assertEqual(decrypted, test_data)


if __name__ == "__main__":
    unittest.main()

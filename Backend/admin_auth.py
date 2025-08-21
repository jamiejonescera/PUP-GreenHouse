import hashlib
import secrets
import smtplib
from email.mime.text import MIMEText           
from email.mime.multipart import MIMEMultipart  
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
import os
from dotenv import load_dotenv
import pg8000
import json
import asyncio
import concurrent.futures
from urllib.parse import urlparse

load_dotenv()
print(f"🔍 DEBUG - SMTP_PASSWORD from env: {os.getenv('SMTP_PASSWORD')}")

# Email configuration
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
SMTP_USERNAME = os.getenv("SMTP_USERNAME")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD")
DATABASE_URL = os.getenv("DATABASE_URL")

class AdminAuthManager:
    def get_db_connection(self):
        """Get PostgreSQL database connection using pg8000 (pure Python)"""
        try:
            # Parse DATABASE_URL
            url = urlparse(DATABASE_URL)
            
            conn = pg8000.connect(
                host=url.hostname,
                port=url.port or 5432,
                user=url.username,
                password=url.password,
                database=url.path[1:] if url.path else None,  # Remove leading '/'
                ssl_context=True  # Add SSL support for Render
            )
            return conn
        except Exception as e:
            print(f"❌ Database connection error: {e}")
            raise
    
    def run_in_thread(self, func, *args, **kwargs):
        """Run synchronous database operations in a thread"""
        try:
            # Check if we're in an event loop
            loop = asyncio.get_running_loop()
            # If we are, run in a thread
            with concurrent.futures.ThreadPoolExecutor() as executor:
                future = executor.submit(func, *args, **kwargs)
                return future.result()
        except RuntimeError:
            # No event loop, run directly
            return func(*args, **kwargs)
        
    def hash_password(self, password: str) -> str:
        """Hash password with salt"""
        salt = secrets.token_hex(16)
        password_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
        return f"{salt}:{password_hash.hex()}"
    
    def verify_password(self, password: str, hash_string: str) -> bool:
        """Verify password against hash"""
        try:
            salt, password_hash = hash_string.split(':')
            return hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000).hex() == password_hash
        except:
            return False
    
    def _check_first_time_setup(self) -> bool:
        """Check if admin setup is needed (no admin exists) - sync version"""
        try:
            conn = self.get_db_connection()
            try:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT * FROM app_settings WHERE setting_key = %s",
                    ("admin_profile",)
                )
                admin_row = cursor.fetchone()
                return admin_row is None
            finally:
                conn.close()
        except Exception as e:
            print(f"Error checking first-time setup: {e}")
            return True  # Assume first time if error
    
    def check_first_time_setup(self) -> bool:
        """Check if admin setup is needed (async-safe wrapper)"""
        return self.run_in_thread(self._check_first_time_setup)
    
    def _create_admin(self, name: str, email: str, password: str) -> Dict[str, Any]:
        """Create the first admin account - sync version"""
        try:
            # Check if admin already exists
            if not self._check_first_time_setup():
                return {"success": False, "error": "Admin already exists"}
            
            # Hash password
            password_hash = self.hash_password(password)
            
            # Create admin record
            admin_data = {
                "name": name,
                "email": email,
                "password_hash": password_hash,
                "is_admin": True,
                "created_at": datetime.utcnow().isoformat(),
                "last_login": None,
                "reset_token": None,
                "reset_expires": None
            }
            
            conn = self.get_db_connection()
            try:
                cursor = conn.cursor()
                # Store admin profile in app_settings table
                cursor.execute("""
                    INSERT INTO app_settings (setting_key, setting_value, updated_at, updated_by)
                    VALUES (%s, %s, %s, %s)
                """,
                ("admin_profile", json.dumps(admin_data), datetime.utcnow(), "system")
                )
                conn.commit()
            finally:
                conn.close()
            
            return {
                "success": True,
                "message": "Admin account created successfully",
                "admin": {
                    "name": name,
                    "email": email
                }
            }
            
        except Exception as e:
            print(f"Error creating admin: {e}")
            return {"success": False, "error": str(e)}
    
    def create_admin(self, name: str, email: str, password: str) -> Dict[str, Any]:
        """Create admin account (async-safe wrapper)"""
        return self.run_in_thread(self._create_admin, name, email, password)
    
    def _authenticate_admin(self, email: str, password: str) -> Dict[str, Any]:
        """Authenticate admin login - sync version"""
        try:
            conn = self.get_db_connection()
            try:
                cursor = conn.cursor()
                # Get admin record
                cursor.execute(
                    "SELECT * FROM app_settings WHERE setting_key = %s",
                    ("admin_profile",)
                )
                admin_row = cursor.fetchone()
                
                if not admin_row:
                    return {"success": False, "error": "Admin not found"}
                
                # pg8000 returns tuples, so we need to map to dict
                admin = json.loads(admin_row[1])  # setting_value is at index 1
                
                # Check email and password
                if admin.get("email") != email:
                    return {"success": False, "error": "Invalid credentials"}
                
                if not self.verify_password(password, admin.get("password_hash", "")):
                    return {"success": False, "error": "Invalid credentials"}
                
                # Update last login
                admin["last_login"] = datetime.utcnow().isoformat()
                
                cursor.execute("""
                    UPDATE app_settings 
                    SET setting_value = %s, updated_at = %s 
                    WHERE setting_key = %s
                """,
                (json.dumps(admin), datetime.utcnow(), "admin_profile")
                )
                conn.commit()
                
                return {
                    "success": True,
                    "admin": {
                        "user_id": "ADMIN",
                        "name": admin.get("name"),
                        "email": admin.get("email"),
                        "is_admin": True
                    }
                }
            finally:
                conn.close()
            
        except Exception as e:
            print(f"Error authenticating admin: {e}")
            return {"success": False, "error": str(e)}
    
    def authenticate_admin(self, email: str, password: str) -> Dict[str, Any]:
        """Authenticate admin (async-safe wrapper)"""
        return self.run_in_thread(self._authenticate_admin, email, password)
    
    def _update_admin_profile(self, current_email: str, new_name: str = None, new_email: str = None, new_password: str = None) -> Dict[str, Any]:
        """Update admin profile - sync version"""
        try:
            conn = self.get_db_connection()
            try:
                cursor = conn.cursor()
                # Get current admin
                cursor.execute(
                    "SELECT * FROM app_settings WHERE setting_key = %s",
                    ("admin_profile",)
                )
                admin_row = cursor.fetchone()
                
                if not admin_row:
                    return {"success": False, "error": "Admin not found"}
                
                admin = json.loads(admin_row[1])  # setting_value is at index 1
                
                # Verify current email
                if admin.get("email") != current_email:
                    return {"success": False, "error": "Current email doesn't match"}
                
                # Update fields
                if new_name and new_name.strip():
                    admin["name"] = new_name.strip()
                
                if new_email and new_email.strip():
                    admin["email"] = new_email.strip()
                
                if new_password and new_password.strip():
                    admin["password_hash"] = self.hash_password(new_password)
                
                admin["updated_at"] = datetime.utcnow().isoformat()
                
                print(f"🔄 Updating admin profile")
                
                # Update admin record
                cursor.execute("""
                    UPDATE app_settings 
                    SET setting_value = %s, updated_at = %s 
                    WHERE setting_key = %s
                """,
                (json.dumps(admin), datetime.utcnow(), "admin_profile")
                )
                conn.commit()
                
                return {
                    "success": True,
                    "message": "Admin profile updated successfully",
                    "admin": {
                        "name": admin.get("name"),
                        "email": admin.get("email")
                    }
                }
            finally:
                conn.close()
            
        except Exception as e:
            print(f"❌ Error updating admin profile: {e}")
            import traceback
            traceback.print_exc()
            return {"success": False, "error": str(e)}
    
    def update_admin_profile(self, current_email: str, new_name: str = None, new_email: str = None, new_password: str = None) -> Dict[str, Any]:
        """Update admin profile (async-safe wrapper)"""
        return self.run_in_thread(self._update_admin_profile, current_email, new_name, new_email, new_password)
    
    def _generate_reset_token(self, email: str) -> Dict[str, Any]:
        """Generate password reset token - SECURE VERSION - sync"""
        try:
            conn = self.get_db_connection()
            try:
                cursor = conn.cursor()
                # Get admin record first
                cursor.execute(
                    "SELECT * FROM app_settings WHERE setting_key = %s",
                    ("admin_profile",)
                )
                admin_row = cursor.fetchone()
                
                if not admin_row:
                    print(f"❌ Admin account not found in database")
                    return {"success": False, "error": "Admin not found"}
                
                admin = json.loads(admin_row[1])  # setting_value is at index 1
                admin_email = admin.get("email")
                
                # SECURITY CHECK: Only allow reset for the actual admin email
                if admin_email != email:
                    print(f"🚨 Security blocked: Attempted reset for '{email}' but admin email is '{admin_email}'")
                    return {"success": False, "error": "Email must match admin email for reset"}
                
                print(f"✅ Email verification passed: {email} matches admin email")
                
                # Generate reset token
                reset_token = secrets.token_urlsafe(32)
                reset_expires = (datetime.utcnow() + timedelta(hours=1)).isoformat()
                
                # Save reset token
                admin["reset_token"] = reset_token
                admin["reset_expires"] = reset_expires
                
                cursor.execute("""
                    UPDATE app_settings 
                    SET setting_value = %s, updated_at = %s 
                    WHERE setting_key = %s
                """,
                (json.dumps(admin), datetime.utcnow(), "admin_profile")
                )
                conn.commit()
                
                return {
                    "success": True,
                    "reset_token": reset_token,
                    "admin_name": admin.get("name", "Admin")
                }
            finally:
                conn.close()
            
        except Exception as e:
            print(f"Error generating reset token: {e}")
            return {"success": False, "error": "An error occurred. Please try again."}
    
    def generate_reset_token(self, email: str) -> Dict[str, Any]:
        """Generate reset token (async-safe wrapper)"""
        return self.run_in_thread(self._generate_reset_token, email)
    
    def _reset_password(self, token: str, new_password: str) -> Dict[str, Any]:
        """Reset password with token - sync version"""
        try:
            conn = self.get_db_connection()
            try:
                cursor = conn.cursor()
                # Get admin record
                cursor.execute(
                    "SELECT * FROM app_settings WHERE setting_key = %s",
                    ("admin_profile",)
                )
                admin_row = cursor.fetchone()
                
                if not admin_row:
                    return {"success": False, "error": "Admin not found"}
                
                admin = json.loads(admin_row[1])  # setting_value is at index 1
                
                # Check token
                if admin.get("reset_token") != token:
                    return {"success": False, "error": "Invalid reset token"}
                
                # Check expiration
                reset_expires = admin.get("reset_expires")
                if not reset_expires or datetime.fromisoformat(reset_expires) < datetime.utcnow():
                    return {"success": False, "error": "Reset token expired"}
                
                # Hash new password
                admin["password_hash"] = self.hash_password(new_password)
                
                # Clear reset token
                admin["reset_token"] = None
                admin["reset_expires"] = None
                admin["updated_at"] = datetime.utcnow().isoformat()
                
                # Update password and clear reset token
                cursor.execute("""
                    UPDATE app_settings 
                    SET setting_value = %s, updated_at = %s 
                    WHERE setting_key = %s
                """,
                (json.dumps(admin), datetime.utcnow(), "admin_profile")
                )
                conn.commit()
                
                return {
                    "success": True,
                    "message": "Password reset successfully"
                }
            finally:
                conn.close()
            
        except Exception as e:
            print(f"Error resetting password: {e}")
            return {"success": False, "error": str(e)}
    
    def reset_password(self, token: str, new_password: str) -> Dict[str, Any]:
        """Reset password (async-safe wrapper)"""
        return self.run_in_thread(self._reset_password, token, new_password)
    
    def send_reset_email(self, email: str, reset_token: str, admin_name: str) -> bool:
        """Send password reset email with environment-aware reset link"""
        try:
            if not SMTP_USERNAME or not SMTP_PASSWORD:
                print("❌ SMTP credentials not configured")
                return False
            
            print(f"📧 Attempting to send email to: {email}")
            print(f"🔐 Using SMTP username: {SMTP_USERNAME}")
            print(f"🔑 Password length: {len(SMTP_PASSWORD)} chars")
            
            # Smart environment detection for reset link
            environment = os.getenv("ENVIRONMENT", "production")
            
            if environment.lower() in ["local", "development", "dev"]:
                # Local development - FIXED: Use correct path
                frontend_url = "http://localhost:3000"
                reset_path = "/admin-reset-password"  # ✅ FIXED PATH
            else:
                # Production deployment
                frontend_url = os.getenv("FRONTEND_URL", "https://thegreenhouse-project.netlify.app")
                reset_path = "/admin-reset-password"
            
            reset_link = f"{frontend_url}{reset_path}?token={reset_token}"
            
            print(f"🌍 Environment: {environment}")
            print(f"🔗 Reset link: {reset_link}")
            
            # Create email message
            msg = MIMEMultipart()
            msg['From'] = SMTP_USERNAME
            msg['To'] = email
            msg['Subject'] = "Eco Pantry - Admin Password Reset"
            
            body = f"""
Hello {admin_name},

You requested a password reset for your PUP-GreenHouse admin account.

Click the link below to reset your password (valid for 1 hour):
{reset_link}

If you didn't request this reset, please ignore this email.

Best regards,
GreenHouse Project - PUP Sustainability Platform

---

Reset expires: {(datetime.utcnow() + timedelta(hours=1)).strftime('%Y-%m-%d %I:%M:%S %p UTC')}
            """
            
            msg.attach(MIMEText(body, 'plain'))
            
            # Connect to Gmail SMTP
            print("🔗 Connecting to Gmail...")
            server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
            server.starttls()
            
            print("🔑 Authenticating...")
            server.login(SMTP_USERNAME, SMTP_PASSWORD)
            
            print("📤 Sending email...")
            server.send_message(msg)
            server.quit()
            
            print(f"✅ Password reset email sent successfully to: {email}")
            return True
            
        except smtplib.SMTPAuthenticationError as e:
            print(f"❌ SMTP Authentication failed: {e}")
            return False
            
        except Exception as e:
            print(f"❌ Error sending email: {e}")
            return False
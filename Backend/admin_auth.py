import hashlib
import secrets
import smtplib
from email.mime.text import MIMEText           
from email.mime.multipart import MIMEMultipart  
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
import asyncpg
import os
from dotenv import load_dotenv

load_dotenv()
print(f"🔍 DEBUG - SMTP_PASSWORD from env: {os.getenv('SMTP_PASSWORD')}")

# Email configuration
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
SMTP_USERNAME = os.getenv("SMTP_USERNAME")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD") 

class AdminAuthManager:
    def __init__(self, db_pool):
        """Initialize with PostgreSQL connection pool instead of DynamoDB table"""
        self.db_pool = db_pool
        
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
    
    async def check_first_time_setup(self) -> bool:
        """Check if admin setup is needed (no admin exists)"""
        try:
            if not self.db_pool:
                return True
                
            async with self.db_pool.acquire() as conn:
                result = await conn.fetchval("SELECT COUNT(*) FROM admin_accounts")
                return result == 0
        except Exception as e:
            print(f"Error checking first-time setup: {e}")
            return True  # Assume first time if error
    
    async def create_admin(self, name: str, email: str, password: str) -> Dict[str, Any]:
        """Create the first admin account"""
        try:
            # Check if admin already exists
            if not await self.check_first_time_setup():
                return {"success": False, "error": "Admin already exists"}
            
            if not self.db_pool:
                return {"success": False, "error": "Database not connected"}
            
            # Hash password
            password_hash = self.hash_password(password)
            admin_id = str(secrets.token_hex(16))  # Generate unique admin ID
            
            # Create admin record
            async with self.db_pool.acquire() as conn:
                await conn.execute("""
                    INSERT INTO admin_accounts (
                        user_id, name, email, password_hash, created_at, 
                        last_login, reset_token, reset_expires
                    ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                """, admin_id, name, email.lower(), password_hash, 
                   datetime.utcnow(), None, None, None)
            
            return {
                "success": True,
                "message": "Admin account created successfully",
                "admin_id": admin_id,
                "admin": {
                    "name": name,
                    "email": email
                }
            }
            
        except Exception as e:
            print(f"Error creating admin: {e}")
            return {"success": False, "error": str(e)}
    
    async def authenticate_admin(self, email: str, password: str) -> Dict[str, Any]:
        """Authenticate admin login"""
        try:
            if not self.db_pool:
                return {"success": False, "error": "Database not connected"}
                
            # Get admin record
            async with self.db_pool.acquire() as conn:
                admin = await conn.fetchrow(
                    "SELECT * FROM admin_accounts WHERE email = $1", 
                    email.lower()
                )
            
            if not admin:
                return {"success": False, "error": "Invalid credentials"}
            
            # Check password
            if not self.verify_password(password, admin.get("password_hash", "")):
                return {"success": False, "error": "Invalid credentials"}
            
            # Update last login
            async with self.db_pool.acquire() as conn:
                await conn.execute(
                    "UPDATE admin_accounts SET last_login = $1 WHERE user_id = $2",
                    datetime.utcnow(), admin["user_id"]
                )
            
            return {
                "success": True,
                "admin": {
                    "user_id": admin["user_id"],
                    "name": admin.get("name"),
                    "email": admin.get("email"),
                    "is_admin": True
                }
            }
            
        except Exception as e:
            print(f"Error authenticating admin: {e}")
            return {"success": False, "error": str(e)}
    
    async def update_admin_profile(self, current_email: str, new_name: str = None, new_email: str = None, new_password: str = None) -> Dict[str, Any]:
        """Update admin profile"""
        try:
            if not self.db_pool:
                return {"success": False, "error": "Database not connected"}
                
            # Get current admin
            async with self.db_pool.acquire() as conn:
                admin = await conn.fetchrow(
                    "SELECT * FROM admin_accounts WHERE email = $1", 
                    current_email.lower()
                )
            
            if not admin:
                return {"success": False, "error": "Admin not found"}
            
            # Prepare update fields
            update_fields = ["updated_at = $1"]
            values = [datetime.utcnow()]
            param_count = 1
            
            if new_name and new_name.strip():
                param_count += 1
                update_fields.append(f"name = ${param_count}")
                values.append(new_name.strip())
            
            if new_email and new_email.strip():
                param_count += 1
                update_fields.append(f"email = ${param_count}")
                values.append(new_email.strip().lower())
            
            if new_password and new_password.strip():
                password_hash = self.hash_password(new_password)
                param_count += 1
                update_fields.append(f"password_hash = ${param_count}")
                values.append(password_hash)
            
            # Add WHERE clause parameter
            param_count += 1
            values.append(admin["user_id"])
            
            update_query = f"""
                UPDATE admin_accounts 
                SET {', '.join(update_fields)}
                WHERE user_id = ${param_count}
            """
            
            print(f"🔄 Updating admin profile with query: {update_query}")
            print(f"📝 Values count: {len(values)}")
            
            # Execute update
            async with self.db_pool.acquire() as conn:
                await conn.execute(update_query, *values)
            
            return {
                "success": True,
                "message": "Admin profile updated successfully",
                "admin": {
                    "name": new_name or admin.get("name"),
                    "email": new_email or admin.get("email")
                }
            }
            
        except Exception as e:
            print(f"❌ Error updating admin profile: {e}")
            import traceback
            traceback.print_exc()
            return {"success": False, "error": str(e)}
    
    async def generate_reset_token(self, email: str) -> Dict[str, Any]:
        """Generate password reset token - SECURE VERSION"""
        try:
            if not self.db_pool:
                return {"success": False, "error": "Database not connected"}
                
            # Get admin record first
            async with self.db_pool.acquire() as conn:
                admin = await conn.fetchrow(
                    "SELECT * FROM admin_accounts WHERE email = $1", 
                    email.lower()
                )
            
            if not admin:
                print(f"❌ Admin account not found in database")
                return {"success": False, "error": "Admin not found"}
            
            admin_email = admin.get("email")
            
            # SECURITY CHECK: Only allow reset for the actual admin email
            if admin_email != email.lower():
                print(f"🚨 Security blocked: Attempted reset for '{email}' but admin email is '{admin_email}'")
                # Return generic error message to prevent email enumeration
                return {"success": False, "error": "Email must match admin email for reset"}
            
            print(f"✅ Email verification passed: {email} matches admin email")
            
            # Generate reset token
            reset_token = secrets.token_urlsafe(32)
            reset_expires = datetime.utcnow() + timedelta(hours=1)
            
            # Save reset token
            async with self.db_pool.acquire() as conn:
                await conn.execute("""
                    UPDATE admin_accounts 
                    SET reset_token = $1, reset_expires = $2 
                    WHERE user_id = $3
                """, reset_token, reset_expires, admin["user_id"])
            
            return {
                "success": True,
                "reset_token": reset_token,
                "admin_name": admin.get("name", "Admin")
            }
            
        except Exception as e:
            print(f"Error generating reset token: {e}")
            return {"success": False, "error": "An error occurred. Please try again."}
    
    async def reset_password(self, token: str, new_password: str) -> Dict[str, Any]:
        """Reset password with token"""
        try:
            if not self.db_pool:
                return {"success": False, "error": "Database not connected"}
                
            # Get admin record by reset token
            async with self.db_pool.acquire() as conn:
                admin = await conn.fetchrow(
                    "SELECT * FROM admin_accounts WHERE reset_token = $1", 
                    token
                )
            
            if not admin:
                return {"success": False, "error": "Invalid reset token"}
            
            # Check expiration
            reset_expires = admin.get("reset_expires")
            if not reset_expires or reset_expires < datetime.utcnow():
                return {"success": False, "error": "Reset token expired"}
            
            # Hash new password
            password_hash = self.hash_password(new_password)
            
            # Update password and clear reset token
            async with self.db_pool.acquire() as conn:
                await conn.execute("""
                    UPDATE admin_accounts 
                    SET password_hash = $1, reset_token = NULL, reset_expires = NULL, updated_at = $2
                    WHERE user_id = $3
                """, password_hash, datetime.utcnow(), admin["user_id"])
            
            return {
                "success": True,
                "message": "Password reset successfully"
            }
            
        except Exception as e:
            print(f"Error resetting password: {e}")
            return {"success": False, "error": str(e)}
    
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


# COMPATIBILITY: For existing imports in main.py
class LocalAdminAuthManager(AdminAuthManager):
    """Alias for backward compatibility"""
    pass
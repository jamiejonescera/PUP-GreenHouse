import hashlib
import secrets
import smtplib
from email.mime.text import MIMEText           
from email.mime.multipart import MIMEMultipart  
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
import boto3
from botocore.exceptions import ClientError
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
    def __init__(self, dynamodb_table):
        self.table = dynamodb_table
        
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
    
    def check_first_time_setup(self) -> bool:
        """Check if admin setup is needed (no admin exists)"""
        try:
            response = self.table.get_item(
                Key={"user_id": "ADMIN", "item_id": "PROFILE"}
            )
            return "Item" not in response
        except Exception as e:
            print(f"Error checking first-time setup: {e}")
            return True  # Assume first time if error
    
    def create_admin(self, name: str, email: str, password: str) -> Dict[str, Any]:
        """Create the first admin account"""
        try:
            # Check if admin already exists
            if not self.check_first_time_setup():
                return {"success": False, "error": "Admin already exists"}
            
            # Hash password
            password_hash = self.hash_password(password)
            
            # Create admin record
            admin_data = {
                "user_id": "ADMIN",
                "item_id": "PROFILE",
                "name": name,
                "email": email,
                "password_hash": password_hash,
                "is_admin": True,
                "created_at": datetime.utcnow().isoformat(),
                "last_login": None,
                "reset_token": None,
                "reset_expires": None
            }
            
            self.table.put_item(Item=admin_data)
            
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
    
    def authenticate_admin(self, email: str, password: str) -> Dict[str, Any]:
        """Authenticate admin login"""
        try:
            # Get admin record
            response = self.table.get_item(
                Key={"user_id": "ADMIN", "item_id": "PROFILE"}
            )
            
            if "Item" not in response:
                return {"success": False, "error": "Admin not found"}
            
            admin = response["Item"]
            
            # Check email and password
            if admin.get("email") != email:
                return {"success": False, "error": "Invalid credentials"}
            
            if not self.verify_password(password, admin.get("password_hash", "")):
                return {"success": False, "error": "Invalid credentials"}
            
            # Update last login
            self.table.update_item(
                Key={"user_id": "ADMIN", "item_id": "PROFILE"},
                UpdateExpression="SET last_login = :timestamp",
                ExpressionAttributeValues={":timestamp": datetime.utcnow().isoformat()}
            )
            
            return {
                "success": True,
                "admin": {
                    "user_id": "ADMIN",
                    "name": admin.get("name"),
                    "email": admin.get("email"),
                    "is_admin": True
                }
            }
            
        except Exception as e:
            print(f"Error authenticating admin: {e}")
            return {"success": False, "error": str(e)}
    
    def update_admin_profile(self, current_email: str, new_name: str = None, new_email: str = None, new_password: str = None) -> Dict[str, Any]:
        """Update admin profile"""
        try:
            # Get current admin
            response = self.table.get_item(
                Key={"user_id": "ADMIN", "item_id": "PROFILE"}
            )
            
            if "Item" not in response:
                return {"success": False, "error": "Admin not found"}
            
            admin = response["Item"]
            
            # Verify current email
            if admin.get("email") != current_email:
                return {"success": False, "error": "Current email doesn't match"}
            
            # Prepare update - FIXED VERSION
            update_expression = "SET updated_at = :timestamp"
            expression_values = {":timestamp": datetime.utcnow().isoformat()}
            expression_names = {}  # Add this for reserved words
                
            if new_name and new_name.strip():
                update_expression += ", #name = :name"
                expression_values[":name"] = new_name.strip()
                expression_names["#name"] = "name"  # 'name' is reserved in DynamoDB
            
            if new_email and new_email.strip():
                update_expression += ", email = :email"
                expression_values[":email"] = new_email.strip()
            
            if new_password and new_password.strip():
                password_hash = self.hash_password(new_password)
                update_expression += ", password_hash = :password_hash"
                expression_values[":password_hash"] = password_hash
            
            print(f"🔄 Updating admin profile: {update_expression}")
            print(f"📝 Values: {expression_values}")
            
            # Update admin record - FIXED
            update_params = {
                "Key": {"user_id": "ADMIN", "item_id": "PROFILE"},
                "UpdateExpression": update_expression,
                "ExpressionAttributeValues": expression_values
            }
            
            # Only add ExpressionAttributeNames if we have reserved words
            if expression_names:
                update_params["ExpressionAttributeNames"] = expression_names
            
            self.table.update_item(**update_params)
            
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
    
    def generate_reset_token(self, email: str) -> Dict[str, Any]:
        """Generate password reset token - SECURE VERSION"""
        try:
            # Get admin record first
            response = self.table.get_item(
                Key={"user_id": "ADMIN", "item_id": "PROFILE"}
            )
            
            if "Item" not in response:
                print(f"❌ Admin account not found in database")
                return {"success": False, "error": "Admin not found"}
            
            admin = response["Item"]
            admin_email = admin.get("email")
            
            # SECURITY CHECK: Only allow reset for the actual admin email
            if admin_email != email:
                print(f"🚨 Security blocked: Attempted reset for '{email}' but admin email is '{admin_email}'")
                # Return generic error message to prevent email enumeration
                return {"success": False, "error": "Email must match admin email for reset"}
            
            print(f"✅ Email verification passed: {email} matches admin email")
            
            # Generate reset token
            reset_token = secrets.token_urlsafe(32)
            reset_expires = (datetime.utcnow() + timedelta(hours=1)).isoformat()
            
            # Save reset token
            self.table.update_item(
                Key={"user_id": "ADMIN", "item_id": "PROFILE"},
                UpdateExpression="SET reset_token = :token, reset_expires = :expires",
                ExpressionAttributeValues={
                    ":token": reset_token,
                    ":expires": reset_expires
                }
            )
            
            return {
                "success": True,
                "reset_token": reset_token,
                "admin_name": admin.get("name", "Admin")
            }
            
        except Exception as e:
            print(f"Error generating reset token: {e}")
            return {"success": False, "error": "An error occurred. Please try again."}
    
    def reset_password(self, token: str, new_password: str) -> Dict[str, Any]:
        """Reset password with token"""
        try:
            # Get admin record
            response = self.table.get_item(
                Key={"user_id": "ADMIN", "item_id": "PROFILE"}
            )
            
            if "Item" not in response:
                return {"success": False, "error": "Admin not found"}
            
            admin = response["Item"]
            
            # Check token
            if admin.get("reset_token") != token:
                return {"success": False, "error": "Invalid reset token"}
            
            # Check expiration
            reset_expires = admin.get("reset_expires")
            if not reset_expires or datetime.fromisoformat(reset_expires) < datetime.utcnow():
                return {"success": False, "error": "Reset token expired"}
            
            # Hash new password
            password_hash = self.hash_password(new_password)
            
            # Update password and clear reset token
            self.table.update_item(
                Key={"user_id": "ADMIN", "item_id": "PROFILE"},
                UpdateExpression="SET password_hash = :password, reset_token = :null, reset_expires = :null, updated_at = :timestamp",
                ExpressionAttributeValues={
                    ":password": password_hash,
                    ":null": None,
                    ":timestamp": datetime.utcnow().isoformat()
                }
            )
            
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
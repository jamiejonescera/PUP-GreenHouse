from fastapi import FastAPI, HTTPException, Depends, UploadFile, File, Form, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, EmailStr
from typing import Optional, List, Dict, Any
import json
import uuid
from datetime import datetime, timedelta
import base64
import hashlib
from dotenv import load_dotenv
import jwt
import google.generativeai as genai
import os
import admin_auth
import uuid
from typing import List, Optional
import cloudinary
import cloudinary.uploader
from cloudinary.utils import cloudinary_url
import aiofiles
from pathlib import Path

# Load environment variables
load_dotenv()

# Initialize FastAPI app
app = FastAPI(title="Eco Pantry API", version="1.0.0")

# Render deployment configuration
PORT = int(os.getenv("PORT", 8000))

# CORS middleware - Environment aware
CORS_ORIGINS = os.getenv("CORS_ORIGINS", "http://localhost:3000").split(",")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",  # Local development
        "https://thegreenhouse-project.netlify.app",  # Your Netlify frontend
        "https://pup-greenhouse.onrender.com"  # Your backend (for docs)
    ],
    allow_credentials=True,
    allow_methods=["*"],  # Allow all HTTP methods
    allow_headers=["*"],  # Allow all headers
)
# Database Configuration
DATABASE_URL = os.getenv("DATABASE_URL")

# Cloudinary Configuration
cloudinary.config(
    cloud_name=os.getenv("CLOUDINARY_CLOUD_NAME"),
    api_key=os.getenv("CLOUDINARY_API_KEY"),
    api_secret=os.getenv("CLOUDINARY_API_SECRET")
)

# Upload settings
UPLOAD_PROVIDER = os.getenv("UPLOAD_PROVIDER", "cloudinary")
MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB

# Security
security = HTTPBearer()
SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key-here")

# Google OAuth Config
GOOGLE_CLIENT_ID = "740603627895-39r4nspre969ll50ehr4ele2isnn24du.apps.googleusercontent.com"

# Pydantic Models
class UserCreate(BaseModel):
    email: EmailStr
    name: str
    google_id: str
    profile_picture: Optional[str] = None

class UserResponse(BaseModel):
    user_id: str
    email: str
    name: str
    profile_picture: Optional[str] = None
    is_admin: bool
    is_active: bool
    created_at: str

class ItemCreate(BaseModel):
    name: str
    quantity: int
    category: str
    location: str
    expiry_date: Optional[str] = None
    duration_days: int
    comments: Optional[str] = None
    contact_info: Optional[str] = None

class ItemUpdate(BaseModel):
    name: Optional[str] = None
    quantity: Optional[int] = None
    category: Optional[str] = None
    location: Optional[str] = None
    expiry_date: Optional[str] = None
    duration_days: Optional[int] = None
    comments: Optional[str] = None
    contact_info: Optional[str] = None

class ItemResponse(BaseModel):
    item_id: str
    name: str
    quantity: int
    category: str
    location: str
    owner_id: str
    owner_name: str
    owner_email: str
    expiry_date: Optional[str] = None
    duration_days: int
    comments: Optional[str] = None
    contact_info: Optional[str] = None
    image_urls: List[str]
    status: str
    created_at: str
    approved: bool
    claimed_by: Optional[str] = None
    claimant_email: Optional[str] = None
    claim_expires_at: Optional[str] = None

class ClaimResponse(BaseModel):
    claim_id: str
    item_id: str
    claimant_id: str
    status: str
    created_at: str
    expires_at: str

class ChatMessage(BaseModel):
    message: str

class LocationCreate(BaseModel):
    name: str
    description: str
    is_active: bool = True

class AdminSetup(BaseModel):
    name: str
    email: EmailStr
    password: str

class AdminLogin(BaseModel):
    email: EmailStr
    password: str

class AdminProfileUpdate(BaseModel):
    current_email: EmailStr
    new_name: Optional[str] = None
    new_email: Optional[EmailStr] = None
    new_password: Optional[str] = None

class ForgotPassword(BaseModel):
    email: EmailStr

class ResetPassword(BaseModel):
    token: str
    new_password: str

class NotificationCreate(BaseModel):
    user_id: str
    title: str
    message: str
    type: str  # 'item_approved', 'item_rejected', 'item_claimed', 'new_message', etc.
    related_item_id: Optional[str] = None
    action_url: Optional[str] = None

class NotificationResponse(BaseModel):
    notification_id: str
    user_id: str
    title: str
    message: str
    type: str
    related_item_id: Optional[str] = None
    action_url: Optional[str] = None
    is_read: bool
    created_at: str

# Database connection helper
async def get_db_connection():
    """Get PostgreSQL database connection"""
    try:
        conn = await asyncpg.connect(DATABASE_URL)
        return conn
    except Exception as e:
        print(f"❌ Database connection error: {e}")
        raise

# Database table creation
async def create_tables_if_not_exist(conn):
    """Create database tables if they don't exist"""
    try:
        # Users table
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                user_id VARCHAR(255) PRIMARY KEY,
                google_id VARCHAR(255) UNIQUE,
                email VARCHAR(255) UNIQUE NOT NULL,
                name VARCHAR(255) NOT NULL,
                profile_picture TEXT,
                is_admin BOOLEAN DEFAULT FALSE,
                is_active BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP
            )
        """)
        
        # Items table
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS items (
                item_id VARCHAR(255) PRIMARY KEY,
                name VARCHAR(255) NOT NULL,
                quantity INTEGER NOT NULL,
                category VARCHAR(255) NOT NULL,
                location VARCHAR(255) NOT NULL,
                owner_id VARCHAR(255),
                owner_name VARCHAR(255),
                owner_email VARCHAR(255),
                expiry_date TIMESTAMP,
                duration_days INTEGER DEFAULT 7,
                comments TEXT,
                contact_info VARCHAR(255),
                image_urls TEXT[],
                status VARCHAR(50) DEFAULT 'available',
                approved BOOLEAN DEFAULT FALSE,
                claimed_by VARCHAR(255),
                claimant_email VARCHAR(255),
                claim_expires_at TIMESTAMP,
                rejection_reason TEXT,
                rejected_at TIMESTAMP,
                approved_at TIMESTAMP,
                completed_at TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Chat messages table
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS chat_messages (
                message_id VARCHAR(255) PRIMARY KEY,
                item_id VARCHAR(255),
                sender_id VARCHAR(255),
                sender_email VARCHAR(255),
                sender_name VARCHAR(255),
                message TEXT NOT NULL,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Notifications table
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS notifications (
                notification_id VARCHAR(255) PRIMARY KEY,
                user_id VARCHAR(255),
                title VARCHAR(255) NOT NULL,
                message TEXT NOT NULL,
                type VARCHAR(100) NOT NULL,
                related_item_id VARCHAR(255),
                action_url VARCHAR(255),
                is_read BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Locations table
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS locations (
                location_id VARCHAR(255) PRIMARY KEY,
                name VARCHAR(255) NOT NULL,
                description TEXT,
                is_active BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # App settings table
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS app_settings (
                setting_key VARCHAR(255) PRIMARY KEY,
                setting_value TEXT,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_by VARCHAR(255)
            )
        """)
        
        print("✅ Database tables created/verified successfully")
        
    except Exception as e:
        print(f"❌ Error creating tables: {e}")
        raise

# Initialize admin manager with PostgreSQL
try:
    from admin_auth import AdminAuthManager
    admin_manager = AdminAuthManager
    print("✅ Admin manager initialized successfully")
except ImportError:
    print("⚠️ admin_auth.py not found - admin features will not work")
    admin_manager = None

# Database initialization
async def init_database():
    """Initialize database tables if they don't exist"""
    conn = await get_db_connection()
    try:
        await create_tables_if_not_exist(conn)
        print("✅ Database tables initialized")
    except Exception as e:
        print(f"❌ Database initialization error: {e}")
    finally:
        await conn.close()

# Initialize Gemini AI model
try:
    GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")    
    if GEMINI_API_KEY:
        genai.configure(api_key=GEMINI_API_KEY)
        model = genai.GenerativeModel('gemini-1.5-flash')
        print("✅ Gemini AI model initialized successfully")
    else:
        print("No AI detected")
        model = None
        
except Exception as e:
    print(f"❌ Error initializing Gemini AI: {e}")
    model = None

# Helper Functions
def generate_token(user_id: str, is_admin: bool = False) -> str:
    payload = {
        "user_id": user_id,
        "is_admin": is_admin,
        "exp": datetime.utcnow() + timedelta(days=7)
    }
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")

def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        payload = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=["HS256"])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

def admin_required(token_data: dict = Depends(verify_token)):
    if not token_data.get("is_admin"):
        raise HTTPException(status_code=403, detail="Admin access required")
    return token_data

async def upload_to_cloudinary(file: UploadFile, folder: str) -> str:
    """Upload file to Cloudinary"""
    try:
        if not file.filename:
            raise ValueError("No filename provided")
            
        print(f"📸 Starting Cloudinary upload: {file.filename}")
        
        # Validate file
        if file.size and file.size > MAX_FILE_SIZE:
            raise ValueError(f"File too large: {file.size} bytes")
        
        # Read file content
        file_content = await file.read()
        print(f"📄 File size: {len(file_content)} bytes")
        
        if len(file_content) == 0:
            raise ValueError("Empty file")
        
        # Upload to Cloudinary
        result = cloudinary.uploader.upload(
            file_content,
            folder=folder,
            resource_type="auto",
            format="jpg",
            quality="auto",
            fetch_format="auto"
        )
        
        url = result.get('secure_url')
        print(f"✅ Cloudinary upload successful: {url}")
        
        return url
        
    except Exception as e:
        print(f"❌ Cloudinary upload error: {str(e)}")
        raise

async def create_notification(user_id: str, title: str, message: str, notification_type: str, 
                            related_item_id: str = None, action_url: str = None):
    """Create a new notification for a user"""
    try:
        notification_id = str(uuid.uuid4())
        
        conn = await get_db_connection()
        try:
            await conn.execute("""
                INSERT INTO notifications (notification_id, user_id, title, message, type, related_item_id, action_url, is_read, created_at)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            """, 
            notification_id,
            user_id,
            title,
            message,
            notification_type,
            related_item_id,
            action_url,
            False,
            datetime.utcnow()
            )
        finally:
            await conn.close()
        
        print(f"✅ Notification created for user {user_id}: {title}")
        return notification_id
        
    except Exception as e:
        print(f"❌ Error creating notification: {e}")
        return None

# Authentication Endpoints
@app.post("/auth/login")
async def login(user_data: UserCreate):
    """Login or register user with Google OAuth"""
    try:
        print(f"🔍 Login attempt with data: {user_data.email}")
        
        # Check if user exists in PostgreSQL
        print(f"🔍 Checking for existing user with google_id: {user_data.google_id}")
        conn = await get_db_connection()
        try:
            user_row = await conn.fetchrow("SELECT * FROM users WHERE user_id = $1", user_data.google_id)
            
            if user_row:
                print(f"✅ Found existing user")
                user = dict(user_row)  # Convert to dictionary (same format as DynamoDB)
                if not user.get("is_active", True):
                    raise HTTPException(status_code=403, detail="Account suspended")
                
                # Update last login
                await conn.execute(
                    "UPDATE users SET last_login = $1 WHERE user_id = $2",
                    datetime.utcnow(),
                    user_data.google_id
                )
            else:
                print(f"❌ User not found, creating new user...")
                # Create new user in PostgreSQL
                await conn.execute("""
                    INSERT INTO users (user_id, google_id, email, name, profile_picture, is_admin, is_active, created_at, last_login)
                    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
                """, 
                user_data.google_id,           # $1 (user_id)
                user_data.google_id,           # $2 (google_id)
                user_data.email,               # $3 (email)
                user_data.name,                # $4 (name)
                user_data.profile_picture,     # $5 (profile_picture)
                False,                         # $6 (is_admin)
                True,                          # $7 (is_active)
                datetime.utcnow(),             # $8 (created_at)
                datetime.utcnow()              # $9 (last_login)
                )
                
                print(f"💾 Saving new user: {user_data.name}")
                
                # Create user dict for response (same format as before)
                user = {
                    "user_id": user_data.google_id,
                    "google_id": user_data.google_id,
                    "email": user_data.email,
                    "name": user_data.name,
                    "profile_picture": user_data.profile_picture,
                    "is_admin": False,
                    "is_active": True,
                    "created_at": datetime.utcnow().isoformat(),
                    "last_login": datetime.utcnow().isoformat()
                }
                print(f"✅ User saved successfully!")
            
        finally:
            await conn.close()  # Always close the connection
        
        # Generate token using google_id as user_id (same as before)
        token = generate_token(user_data.google_id, user.get("is_admin", False))
        print(f"🔑 Generated token for user: {user_data.name}")
        
        return {
            "access_token": token,  # Frontend expects this field name
            "user": {
                "user_id": user_data.google_id,
                "email": user["email"],
                "name": user["name"],
                "profile_picture": user.get("profile_picture"),
                "is_admin": user.get("is_admin", False),
                "is_active": user.get("is_active", True)
            }
        }
        
    except Exception as e:
        print(f"❌ Login error: {e}")
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/admin/setup/check")
async def check_admin_setup():
    """Check if admin setup is needed"""
    try:
        is_first_time = admin_manager.check_first_time_setup()
        return {
            "first_time_setup": is_first_time,
            "message": "Admin setup required" if is_first_time else "Admin already exists"
        }
    except Exception as e:
        print(f"Error checking admin setup: {e}")
        return {"first_time_setup": True, "error": str(e)}

@app.post("/admin/setup")
async def setup_admin(admin_data: AdminSetup):
    """Create the first admin account"""
    try:
        print(f"🔧 Setting up admin account: {admin_data.email}")
        
        # Validate password strength
        if len(admin_data.password) < 8:
            return {"success": False, "error": "Password must be at least 8 characters"}
        
        if not any(c.isupper() for c in admin_data.password):
            return {"success": False, "error": "Password must contain at least one uppercase letter"}
        
        if not any(c.islower() for c in admin_data.password):
            return {"success": False, "error": "Password must contain at least one lowercase letter"}
        
        if not any(c.isdigit() for c in admin_data.password):
            return {"success": False, "error": "Password must contain at least one number"}
        
        # Create admin
        result = admin_manager.create_admin(
            name=admin_data.name,
            email=admin_data.email,
            password=admin_data.password
        )
        
        if result["success"]:
            print(f"✅ Admin created: {admin_data.name}")
            return result
        else:
            print(f"❌ Admin creation failed: {result['error']}")
            return result
            
    except Exception as e:
        print(f"❌ Error in admin setup: {e}")
        return {"success": False, "error": str(e)}

@app.post("/admin/login")
async def admin_login_new(login_data: AdminLogin):
    """New admin login with email/password"""
    try:
        print(f"🔍 Admin login attempt: {login_data.email}")
        
        # Authenticate admin
        result = admin_manager.authenticate_admin(login_data.email, login_data.password)
        
        if result["success"]:
            # Generate JWT token
            admin_data = result["admin"]
            token = generate_token(admin_data["user_id"], is_admin=True)
            
            print(f"✅ Admin login successful: {admin_data['name']}")
            return {
                "access_token": token,
                "user": admin_data
            }
        else:
            print(f"❌ Admin login failed: {result['error']}")
            raise HTTPException(status_code=401, detail=result["error"])
            
    except HTTPException:
        raise
    except Exception as e:
        print(f"❌ Error in admin login: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/admin/profile")
async def get_admin_profile(token_data: dict = Depends(admin_required)):
    """Get current admin profile"""
    try:
        conn = await get_db_connection()
        try:
            admin_row = await conn.fetchrow("SELECT * FROM app_settings WHERE setting_key = $1", "admin_profile")
            
            if not admin_row:
                raise HTTPException(status_code=404, detail="Admin profile not found")
            
            # Parse admin data from settings
            admin_data = json.loads(admin_row["setting_value"])
            return {
                "name": admin_data.get("name"),
                "email": admin_data.get("email"),
                "created_at": admin_data.get("created_at"),
                "last_login": admin_data.get("last_login")
            }
        finally:
            await conn.close()
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.put("/admin/profile")
async def update_admin_profile(
    profile_data: AdminProfileUpdate,
    token_data: dict = Depends(admin_required)
):
    """Update admin profile"""
    try:
        print(f"🔍 Admin updating profile: {profile_data.current_email}")
        
        # Validate new password if provided
        if profile_data.new_password:
            if len(profile_data.new_password) < 8:
                return {"success": False, "error": "Password must be at least 8 characters"}
        
        # Update profile
        result = admin_manager.update_admin_profile(
            current_email=profile_data.current_email,
            new_name=profile_data.new_name,
            new_email=profile_data.new_email,
            new_password=profile_data.new_password
        )
        
        if result["success"]:
            print(f"✅ Admin profile updated successfully")
            return result
        else:
            print(f"❌ Profile update failed: {result['error']}")
            return result
            
    except Exception as e:
        print(f"❌ Error updating admin profile: {e}")
        return {"success": False, "error": str(e)}

@app.post("/admin/forgot-password")
async def admin_forgot_password(request: dict):
    """Secure admin password reset request"""
    try:
        email = request.get("email", "").strip().lower()
        
        if not email:
            return {"success": False, "error": "Email is required"}
        
        print(f"📧 Password reset requested for: {email}")
        
        # Generate reset token (includes security check)
        result = admin_manager.generate_reset_token(email)
        
        if not result["success"]:
            print(f"❌ Reset token generation failed: {result['error']}")
            return {
                "success": False, 
                "error": result["error"]
            }
        
        # Send email only if token generation succeeded
        reset_token = result["reset_token"]
        admin_name = result["admin_name"]
        
        email_sent = admin_manager.send_reset_email(email, reset_token, admin_name)
        
        if email_sent:
            print(f"✅ Reset email sent to: {email}")
            return {
                "success": True,
                "message": "Password reset email sent successfully"
            }
        else:
            print(f"❌ Failed to send reset email to: {email}")
            return {
                "success": False,
                "error": "Failed to send email. Please try again later."
            }
            
    except Exception as e:
        print(f"❌ Error in forgot password: {e}")
        return {
            "success": False,
            "error": "An error occurred. Please try again."
        }

@app.post("/admin/reset-password")
async def admin_reset_password(reset_data: ResetPassword):
    """Reset admin password with token"""
    try:
        print(f"🔒 Password reset attempt with token")
        
        # Validate new password
        if len(reset_data.new_password) < 8:
            return {"success": False, "error": "Password must be at least 8 characters"}
        
        # Reset password
        result = admin_manager.reset_password(reset_data.token, reset_data.new_password)
        
        if result["success"]:
            print(f"✅ Password reset successful")
            return result
        else:
            print(f"❌ Password reset failed: {result['error']}")
            return result
            
    except Exception as e:
        print(f"❌ Error resetting password: {e}")
        return {"success": False, "error": str(e)}

@app.post("/auth/admin/login")
async def admin_login_legacy(username: str = Form(), password: str = Form()):
    """Legacy admin login - redirects to new system"""
    try:
        print(f"📄 Legacy admin login attempt: {username}")
        
        # Check if this is the old hardcoded admin
        if username == "admin" and password == "1admin@123!":
            # Check if new admin system is set up
            is_first_time = admin_manager.check_first_time_setup()
            
            if is_first_time:
                # Allow legacy login but indicate setup needed
                admin_id = "admin-user-001"
                token = generate_token(admin_id, is_admin=True)
                
                return {
                    "access_token": token,
                    "user": {
                        "user_id": admin_id,
                        "name": "Administrator",
                        "email": "admin@ecopantry.com",
                        "is_admin": True,
                        "setup_required": True  # Flag for frontend
                    }
                }
            else:
                # New system is set up, redirect to new login
                raise HTTPException(
                    status_code=410,
                    detail="Please use the new admin login system"
                )
        
        # Try new login system
        try:
            result = admin_manager.authenticate_admin(username, password)
            if result["success"]:
                admin_data = result["admin"]
                token = generate_token(admin_data["user_id"], is_admin=True)
                
                return {
                    "access_token": token,
                    "user": admin_data
                }
        except:
            pass
        
        # Invalid credentials
        raise HTTPException(status_code=401, detail="Invalid credentials")
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"❌ Legacy admin login error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# User Management Endpoints
@app.get("/users")
async def get_users(token_data: dict = Depends(admin_required)):
    """Get all users (Admin only)"""
    try:
        print("🔍 Admin getting users...")
        
        conn = await get_db_connection()
        try:
            users_rows = await conn.fetch("SELECT * FROM users")
            
            users = []
            for user_row in users_rows:
                user_data = {
                    "user_id": user_row["user_id"],
                    "google_id": user_row["google_id"],
                    "name": user_row["name"],
                    "email": user_row["email"],
                    "profile_picture": user_row["profile_picture"],
                    "is_active": user_row["is_active"],
                    "created_at": user_row["created_at"].isoformat() if user_row["created_at"] else None,
                    "last_login": user_row["last_login"].isoformat() if user_row["last_login"] else None
                }
                users.append(user_data)
                print(f"✅ Added user: {user_row['name']}")
            
            print(f"🎯 Returning {len(users)} users to admin")
            return users
        finally:
            await conn.close()
        
    except Exception as e:
        print(f"❌ Error getting users: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.put("/users/{google_id}/status")
async def update_user_status(
    google_id: str, 
    is_active: bool,
    token_data: dict = Depends(admin_required)
):
    """Suspend/activate user account (Admin only)"""
    try:
        print(f"🔄 Updating user status: {google_id} -> {is_active}")
        
        conn = await get_db_connection()
        try:
            await conn.execute(
                "UPDATE users SET is_active = $1 WHERE user_id = $2",
                is_active,
                google_id
            )
        finally:
            await conn.close()
        
        print(f"✅ User status updated successfully")
        return {"message": "User status updated successfully"}
        
    except Exception as e:
        print(f"❌ Error updating user status: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# Item Management Endpoints
@app.post("/items")
async def create_item(
    name: str = Form(...),
    quantity: int = Form(...),
    category: str = Form(...),
    location: str = Form(...),
    expiry_date: str = Form(...),
    duration_days: int = Form(7),
    comments: str = Form(...),
    contact_info: str = Form(...),
    images: List[UploadFile] = File(...),
    token_data: dict = Depends(verify_token)
):
    """Create new item for donation - ALL FIELDS REQUIRED"""
    try:
        print(f"🔍 Creating item for user: {token_data.get('user_id', 'Unknown')}")
        print(f"🔍 Item data: name={name}, quantity={quantity}, category={category}, location={location}")
        
        # Validate required fields
        validation_errors = []
        
        # Name validation
        if not name or not name.strip():
            validation_errors.append("Item name is required and cannot be empty")
        elif len(name.strip()) < 2:
            validation_errors.append("Item name must be at least 2 characters")
        elif len(name.strip()) > 100:
            validation_errors.append("Item name cannot exceed 100 characters")
            
        # Category validation
        if not category or not category.strip():
            validation_errors.append("Category is required")
            
        # Location validation
        if not location or not location.strip():
            validation_errors.append("Location is required")
            
        # Expiry date validation
        if not expiry_date or not expiry_date.strip():
            validation_errors.append("Expiry date is required")
        else:
            try:
                # Validate date format and ensure it's not in the past
                expiry_datetime = datetime.fromisoformat(expiry_date.replace('Z', '+00:00'))
                if expiry_datetime.date() < datetime.utcnow().date():
                    validation_errors.append("Expiry date cannot be in the past")
            except ValueError:
                validation_errors.append("Invalid expiry date format")
            
        # Comments validation
        if not comments or not comments.strip():
            validation_errors.append("Description/comments are required")
        elif len(comments.strip()) < 10:
            validation_errors.append("Description must be at least 10 characters")
        elif len(comments.strip()) > 500:
            validation_errors.append("Description cannot exceed 500 characters")
            
        # Contact info validation
        if not contact_info or not contact_info.strip():
            validation_errors.append("Contact information is required")
        elif len(contact_info.strip()) > 100:
            validation_errors.append("Contact information cannot exceed 100 characters")
            
        # Quantity validation
        if quantity < 1:
            validation_errors.append("Quantity must be at least 1")
        elif quantity > 999:
            validation_errors.append("Quantity cannot exceed 999")
            
        # Images validation - MANDATORY
        if not images or len(images) == 0:
            validation_errors.append("At least one image is required")
        else:
            # Validate each image
            for i, image in enumerate(images):
                if not image.filename:
                    validation_errors.append(f"Image {i+1} is invalid or empty")
                    continue
                    
                # Check file size (5MB limit)
                if hasattr(image, 'size') and image.size > 5 * 1024 * 1024:
                    validation_errors.append(f"Image {i+1} exceeds 5MB size limit")
                    
                # Check file type
                allowed_types = {'image/jpeg', 'image/jpg', 'image/png', 'image/gif'}
                if image.content_type not in allowed_types:
                    validation_errors.append(f"Image {i+1} must be JPEG, PNG, or GIF format")
        
        # If validation errors, return them
        if validation_errors:
            print(f"❌ Validation errors: {validation_errors}")
            raise HTTPException(
                status_code=400, 
                detail={
                    "message": "Validation failed",
                    "errors": validation_errors
                }
            )
        
        # Get user info
        conn = await get_db_connection()
        try:
            user_row = await conn.fetchrow("SELECT * FROM users WHERE user_id = $1", token_data["user_id"])
            
            if not user_row:
                print(f"❌ User not found: {token_data['user_id']}")
                raise HTTPException(status_code=404, detail="User not found")
            
            user = dict(user_row)
            print(f"✅ Found user: {user.get('name', 'Unknown')}")
            
            # Upload images to Cloudinary
            image_urls = []
            print(f"📸 Uploading {len(images)} images...")
            
            for i, image in enumerate(images):
                try:
                    print(f"📸 Uploading image {i+1}/{len(images)}: {image.filename}")
                    url = await upload_to_cloudinary(image, "items")
                    if url:
                        image_urls.append(url)
                        print(f"✅ Image {i+1} uploaded: {url}")
                    else:
                        print(f"❌ Failed to upload image {i+1}: {image.filename}")
                        raise HTTPException(
                            status_code=500, 
                            detail=f"Failed to upload image: {image.filename}"
                        )
                except Exception as e:
                    print(f"❌ Error uploading image {i+1}: {e}")
                    raise HTTPException(
                        status_code=500, 
                        detail=f"Failed to upload image {image.filename}: {str(e)}"
                    )
            
            # Ensure at least one image was uploaded successfully
            if not image_urls:
                print("❌ No images uploaded successfully")
                raise HTTPException(status_code=500, detail="Failed to upload any images")
            
            # Create item
            item_id = str(uuid.uuid4())
            
            # Save item to PostgreSQL
            await conn.execute("""
                INSERT INTO items (item_id, name, quantity, category, location, owner_id, owner_name, owner_email, 
                                  expiry_date, duration_days, comments, contact_info, image_urls, status, approved, created_at)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)
            """,
            item_id,
            name.strip(),
            quantity,
            category.strip(),
            location.strip(),
            token_data["user_id"],
            user.get("name", "Unknown"),
            user.get("email", ""),
            datetime.fromisoformat(expiry_date.replace('Z', '+00:00')) if expiry_date else None,
            duration_days,
            comments.strip(),
            contact_info.strip(),
            image_urls,
            "available",
            False,  # Requires admin approval
            datetime.utcnow()
            )
            
            print(f"💾 Item saved successfully: {item_id}")
            
            return {
                "success": True,
                "message": "Item created successfully",
                "item_id": item_id,
                "item": {
                    "item_id": item_id,
                    "name": name.strip(),
                    "quantity": quantity,
                    "category": category.strip(),
                    "location": location.strip(),
                    "status": "available",
                    "image_count": len(image_urls),
                    "created_at": datetime.utcnow().isoformat()
                }
            }
        finally:
            await conn.close()
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"❌ Error creating item: {e}")
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Failed to create item: {str(e)}")

@app.get("/items")
async def get_items(
    category: Optional[str] = None,
    status: Optional[str] = None,
    approved_only: bool = True
):
    """Get all items (newsfeed)"""
    try:
        print(f"🔍 GET /items called with: category={category}, status={status}, approved_only={approved_only}")
        
        conn = await get_db_connection()
        try:
            # Build query based on filters
            query = "SELECT * FROM items WHERE 1=1"
            params = []
            param_count = 0
            
            if approved_only:
                param_count += 1
                query += f" AND approved = ${param_count}"
                params.append(True)
            
            if category:
                param_count += 1
                query += f" AND category = ${param_count}"
                params.append(category)
                
            if status:
                param_count += 1
                query += f" AND status = ${param_count}"
                params.append(status)
            
            query += " ORDER BY created_at DESC"
            
            items_rows = await conn.fetch(query, *params)
            
            items = []
            for item_row in items_rows:
                item_response_data = {
                    "item_id": item_row["item_id"],
                    "name": item_row["name"],
                    "quantity": item_row["quantity"],
                    "category": item_row["category"],
                    "location": item_row["location"],
                    "owner_id": item_row["owner_id"],
                    "owner_name": item_row["owner_name"],
                    "owner_email": item_row["owner_email"],
                    "expiry_date": item_row["expiry_date"].isoformat() if item_row["expiry_date"] else None,
                    "duration_days": item_row["duration_days"],
                    "comments": item_row["comments"],
                    "contact_info": item_row["contact_info"],
                    "image_urls": item_row["image_urls"] or [],
                    "images": item_row["image_urls"] or [],
                    "status": item_row["status"],
                    "created_at": item_row["created_at"].isoformat() if item_row["created_at"] else "",
                    "approved": item_row["approved"],
                    "claimed_by": item_row["claimed_by"],
                    "claimant_email": item_row["claimant_email"],
                    "claim_expires_at": item_row["claim_expires_at"].isoformat() if item_row["claim_expires_at"] else None
                }
                items.append(item_response_data)
            
            print(f"🎯 Returning {len(items)} items")
            return items
        finally:
            await conn.close()
        
    except Exception as e:
        print(f"❌ Error getting items: {e}")
        import traceback
        traceback.print_exc()
        return []

@app.get("/items/{item_id}")
async def get_item(item_id: str):
    """Get specific item details"""
    try:
        conn = await get_db_connection()
        try:
            item_row = await conn.fetchrow("SELECT * FROM items WHERE item_id = $1", item_id)
            
            if not item_row:
                raise HTTPException(status_code=404, detail="Item not found")
            
            return {
                "item_id": item_row["item_id"],
                "name": item_row["name"],
                "quantity": item_row["quantity"],
                "category": item_row["category"],
                "location": item_row["location"],
                "owner_id": item_row["owner_id"],
                "owner_name": item_row["owner_name"],
                "owner_email": item_row["owner_email"],
                "expiry_date": item_row["expiry_date"].isoformat() if item_row["expiry_date"] else None,
                "duration_days": item_row["duration_days"],
                "comments": item_row["comments"],
                "contact_info": item_row["contact_info"],
                "image_urls": item_row["image_urls"] or [],
                "status": item_row["status"],
                "created_at": item_row["created_at"].isoformat() if item_row["created_at"] else "",
                "approved": item_row["approved"],
                "claimed_by": item_row["claimed_by"],
                "claimant_email": item_row["claimant_email"],
                "claim_expires_at": item_row["claim_expires_at"].isoformat() if item_row["claim_expires_at"] else None
            }
        finally:
            await conn.close()
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.put("/items/{item_id}")
async def update_item(
    item_id: str,
    item_update: ItemUpdate,
    token_data: dict = Depends(verify_token)
):
    """Update item (owner only)"""
    try:
        conn = await get_db_connection()
        try:
            # Find item
            item_row = await conn.fetchrow("SELECT * FROM items WHERE item_id = $1", item_id)
            
            if not item_row:
                raise HTTPException(status_code=404, detail="Item not found")
            
            # Check ownership or admin
            if item_row["owner_id"] != token_data["user_id"] and not token_data.get("is_admin"):
                raise HTTPException(status_code=403, detail="Not authorized to update this item")
            
            # Build update query
            update_fields = []
            params = []
            param_count = 0
            
            for field, value in item_update.dict(exclude_unset=True).items():
                if value is not None:
                    param_count += 1
                    update_fields.append(f"{field} = ${param_count}")
                    params.append(value)
            
            # Add approved = false if not admin (requires re-approval)
            if not token_data.get("is_admin"):
                param_count += 1
                update_fields.append(f"approved = ${param_count}")
                params.append(False)
            
            if update_fields:
                param_count += 1
                query = f"UPDATE items SET {', '.join(update_fields)} WHERE item_id = ${param_count}"
                params.append(item_id)
                
                await conn.execute(query, *params)
            
            return {"message": "Item updated successfully"}
        finally:
            await conn.close()
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.delete("/items/{item_id}")
async def delete_item(item_id: str, token_data: dict = Depends(verify_token)):
    """Delete item (owner only)"""
    try:
        conn = await get_db_connection()
        try:
            # Find item
            item_row = await conn.fetchrow("SELECT * FROM items WHERE item_id = $1", item_id)
            
            if not item_row:
                raise HTTPException(status_code=404, detail="Item not found")
            
            # Check ownership or admin
            if item_row["owner_id"] != token_data["user_id"] and not token_data.get("is_admin"):
                raise HTTPException(status_code=403, detail="Not authorized to delete this item")
            
            # Delete item
            await conn.execute("DELETE FROM items WHERE item_id = $1", item_id)
            
            return {"message": "Item deleted successfully"}
        finally:
            await conn.close()
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# Admin Item Management
@app.get("/admin/items/pending")
async def get_pending_items(token_data: dict = Depends(admin_required)):
    """Get pending items awaiting approval (Admin only)"""
    try:
        print("🔍 Getting pending items...")
        
        conn = await get_db_connection()
        try:
            items_rows = await conn.fetch("""
                SELECT * FROM items 
                WHERE approved = false AND rejection_reason IS NULL 
                ORDER BY created_at DESC
            """)
            
            items = []
            for item_row in items_rows:
                formatted_item = {
                    "item_id": item_row["item_id"],
                    "name": item_row["name"],
                    "quantity": item_row["quantity"],
                    "category": item_row["category"],
                    "location": item_row["location"],
                    "owner_email": item_row["owner_email"],
                    "owner_name": item_row["owner_name"],
                    "status": item_row["status"],
                    "created_at": item_row["created_at"].isoformat() if item_row["created_at"] else "",
                    "comments": item_row["comments"],
                    "images": item_row["image_urls"] or [],
                    "image_urls": item_row["image_urls"] or []
                }
                items.append(formatted_item)
                print(f"✅ Including pending item: {item_row['name']}")
            
            print(f"📊 Returning {len(items)} pending items")
            return items
        finally:
            await conn.close()
        
    except Exception as e:
        print(f"❌ Error getting pending items: {e}")
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/admin/items/approved")
async def get_approved_items(token_data: dict = Depends(admin_required)):
    """Get all approved items (Admin only)"""
    try:
        print("✅ Getting approved items...")
        
        conn = await get_db_connection()
        try:
            items_rows = await conn.fetch("SELECT * FROM items WHERE approved = true ORDER BY created_at DESC")
            
            items = []
            for item_row in items_rows:
                formatted_item = {
                    "item_id": item_row["item_id"],
                    "name": item_row["name"],
                    "quantity": item_row["quantity"],
                    "category": item_row["category"],
                    "location": item_row["location"],
                    "owner_email": item_row["owner_email"],
                    "owner_name": item_row["owner_name"],
                    "status": item_row["status"],
                    "approved": item_row["approved"],
                    "created_at": item_row["created_at"].isoformat() if item_row["created_at"] else "",
                    "images": item_row["image_urls"] or [],
                    "image_urls": item_row["image_urls"] or []
                }
                items.append(formatted_item)
            
            print(f"📊 Returning {len(items)} approved items")
            return items
        finally:
            await conn.close()
        
    except Exception as e:
        print(f"❌ Error getting approved items: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/admin/items/rejected")
async def get_rejected_items(token_data: dict = Depends(admin_required)):
    """Get all rejected items (Admin only)"""
    try:
        print("❌ Getting rejected items...")
        
        conn = await get_db_connection()
        try:
            items_rows = await conn.fetch("SELECT * FROM items WHERE rejection_reason IS NOT NULL ORDER BY created_at DESC")
            
            items = []
            for item_row in items_rows:
                formatted_item = {
                    "item_id": item_row["item_id"],
                    "name": item_row["name"],
                    "quantity": item_row["quantity"],
                    "category": item_row["category"],
                    "location": item_row["location"],
                    "owner_email": item_row["owner_email"],
                    "owner_name": item_row["owner_name"],
                    "status": item_row["status"],
                    "approved": item_row["approved"],
                    "rejection_reason": item_row["rejection_reason"],
                    "rejected_at": item_row["rejected_at"].isoformat() if item_row["rejected_at"] else None,
                    "created_at": item_row["created_at"].isoformat() if item_row["created_at"] else "",
                    "images": item_row["image_urls"] or [],
                    "image_urls": item_row["image_urls"] or []
                }
                items.append(formatted_item)
                print(f"🔍 Including rejected item: {item_row['name']} (reason: {item_row['rejection_reason']})")
            
            print(f"📊 Returning {len(items)} rejected items")
            return items
        finally:
            await conn.close()
        
    except Exception as e:
        print(f"❌ Error getting rejected items: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.put("/admin/items/{item_id}/approve")
async def approve_item(item_id: str, token_data: dict = Depends(admin_required)):
    """Approve pending item (Admin only) - WITH NOTIFICATION"""
    try:
        print(f"✅ Admin approving item: {item_id}")
        
        conn = await get_db_connection()
        try:
            # Find the item
            item_row = await conn.fetchrow("SELECT * FROM items WHERE item_id = $1", item_id)
            
            if not item_row:
                raise HTTPException(status_code=404, detail="Item not found")
            
            # Update the item to approved
            await conn.execute("""
                UPDATE items 
                SET approved = $1, approved_at = $2 
                WHERE item_id = $3
            """, 
            True,
            datetime.utcnow(),
            item_id
            )
            
            # Create notification
            await create_notification(
                user_id=item_row["owner_id"],
                title="🎉 Item Approved!",
                message=f'Your item "{item_row["name"]}" has been approved and is now live!',
                notification_type="item_approved",
                related_item_id=item_id,
                action_url=f"/dashboard"
            )
            
            print(f"✅ Item approved and notification sent: {item_row['name']}")
            return {"message": "Item approved successfully"}
        finally:
            await conn.close()
        
    except Exception as e:
        print(f"❌ Error approving item: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.put("/admin/items/{item_id}/reject")
async def reject_item(
    item_id: str,
    request: dict,
    token_data: dict = Depends(admin_required)
):
    """Reject an item (Admin only) - WITH NOTIFICATION"""
    try:
        reason = request.get("reason", "")
        print(f"❌ Admin rejecting item: {item_id}, reason: {reason}")
        
        conn = await get_db_connection()
        try:
            # Find the item
            item_row = await conn.fetchrow("SELECT * FROM items WHERE item_id = $1", item_id)
            
            if not item_row:
                raise HTTPException(status_code=404, detail="Item not found")
            
            # Update item as rejected
            await conn.execute("""
                UPDATE items 
                SET approved = $1, rejection_reason = $2, rejected_at = $3 
                WHERE item_id = $4
            """, 
            False,
            reason,
            datetime.utcnow(),
            item_id
            )
            
            # Create notification
            await create_notification(
                user_id=item_row["owner_id"],
                title="❌ Item Rejected",
                message=f'Your item "{item_row["name"]}" was rejected. Reason: {reason}',
                notification_type="item_rejected",
                related_item_id=item_id,
                action_url=f"/dashboard"
            )
            
            print(f"✅ Item rejected and notification sent: {item_row['name']}")
            return {"message": "Item rejected successfully"}
        finally:
            await conn.close()
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"❌ Error rejecting item: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# Claims System
@app.post("/items/{item_id}/claim")
async def claim_item(item_id: str, token_data: dict = Depends(verify_token)):
    """Claim an available item - WITH NOTIFICATION"""
    try:
        print(f"🎯 User {token_data['user_id']} attempting to claim item: {item_id}")
        
        conn = await get_db_connection()
        try:
            # Find item
            item_row = await conn.fetchrow("SELECT * FROM items WHERE item_id = $1", item_id)
            
            if not item_row:
                raise HTTPException(status_code=404, detail="Item not found")
            
            # Validation checks
            if not item_row["approved"]:
                raise HTTPException(status_code=400, detail="Item not approved")
            
            if item_row["status"] != "available":
                raise HTTPException(status_code=400, detail="Item not available")
            
            if item_row["owner_id"] == token_data["user_id"]:
                raise HTTPException(status_code=400, detail="Cannot claim your own item")
            
            # Get claimant info
            claimant_row = await conn.fetchrow("SELECT * FROM users WHERE user_id = $1", token_data["user_id"])
            
            if not claimant_row:
                raise HTTPException(status_code=404, detail="User not found")
            
            # Update item to claimed
            await conn.execute("""
                UPDATE items 
                SET status = $1, claimed_by = $2, claimant_email = $3, claim_expires_at = $4 
                WHERE item_id = $5
            """,
            "claimed",
            token_data["user_id"],
            claimant_row["email"],
            datetime.utcnow() + timedelta(days=3),
            item_id
            )
            
            # Create notification for item owner
            await create_notification(
                user_id=item_row["owner_id"],
                title="🎯 Someone Claimed Your Item!",
                message=f'{claimant_row["name"]} wants to claim your "{item_row["name"]}". You can now chat with them!',
                notification_type="item_claimed",
                related_item_id=item_id,
                action_url=f"/dashboard"
            )
            
            print(f"✅ Item claimed and notification sent to owner")
            return {"message": "Item claimed successfully"}
        finally:
            await conn.close()
        
    except Exception as e:
        print(f"❌ Error claiming item: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/my-claims")
async def get_my_claims(token_data: dict = Depends(verify_token)):
    """Get user's claims"""
    try:
        print(f"🔍 Getting claims for user: {token_data['user_id']}")
        
        conn = await get_db_connection()
        try:
            items_rows = await conn.fetch("SELECT * FROM items WHERE claimed_by = $1", token_data["user_id"])
            
            claims = []
            for item_row in items_rows:
                claim_data = {
                    "claim_id": item_row["item_id"],
                    "item_id": item_row["item_id"],
                    "claimant_id": token_data["user_id"],
                    "status": item_row["status"],
                    "created_at": item_row["claim_expires_at"].isoformat() if item_row["claim_expires_at"] else "",
                    "expires_at": item_row["claim_expires_at"].isoformat() if item_row["claim_expires_at"] else "",
                    "name": item_row["name"],
                    "owner_name": item_row["owner_name"],
                    "location": item_row["location"]
                }
                claims.append(claim_data)
            
            print(f"📊 Found {len(claims)} claims for user")
            return claims
        finally:
            await conn.close()
        
    except Exception as e:
        print(f"❌ Error getting claims: {e}")
        return []

# Chat System
@app.post("/items/{item_id}/chat/messages")
async def send_message(
    item_id: str,
    message: ChatMessage,
    token_data: dict = Depends(verify_token)
):
    """Send chat message - WITH NOTIFICATION"""
    try:
        print(f"💬 Sending message for item: {item_id}")
        
        conn = await get_db_connection()
        try:
            # Find item
            item_row = await conn.fetchrow("SELECT * FROM items WHERE item_id = $1", item_id)
            
            if not item_row:
                raise HTTPException(status_code=404, detail="Item not found")
            
            # Check authorization
            if token_data["user_id"] not in [item_row["owner_id"], item_row["claimed_by"]]:
                raise HTTPException(status_code=403, detail="Not authorized to chat for this item")
            
            # Get sender info
            sender_row = await conn.fetchrow("SELECT * FROM users WHERE user_id = $1", token_data["user_id"])
            sender = dict(sender_row) if sender_row else {}
            
            # Create message
            message_id = str(uuid.uuid4())
            await conn.execute("""
                INSERT INTO chat_messages (message_id, item_id, sender_id, sender_email, sender_name, message, timestamp, created_at)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            """,
            message_id,
            item_id,
            token_data["user_id"],
            sender.get("email", ""),
            sender.get("name", ""),
            message.message,
            datetime.utcnow(),
            datetime.utcnow()
            )
            
            # Notify the other person (not the sender)
            recipient_id = item_row["claimed_by"] if token_data["user_id"] == item_row["owner_id"] else item_row["owner_id"]
            
            if recipient_id:
                await create_notification(
                    user_id=recipient_id,
                    title="💬 New Message",
                    message=f'{sender.get("name")} sent you a message about "{item_row["name"]}"',
                    notification_type="new_message",
                    related_item_id=item_id,
                    action_url=f"/dashboard"
                )
            
            print(f"✅ Message sent and notification created")
            return {"message": "Message sent successfully", "message_id": message_id}
        finally:
            await conn.close()
        
    except Exception as e:
        print(f"❌ Error sending message: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/items/{item_id}/chat/messages")
async def get_chat_messages(item_id: str, token_data: dict = Depends(verify_token)):
    """Get chat messages for item (only owner and claimant)"""
    try:
        print(f"💬 Getting messages for item: {item_id}")
        
        conn = await get_db_connection()
        try:
            # Find item
            item_row = await conn.fetchrow("SELECT * FROM items WHERE item_id = $1", item_id)
            
            if not item_row:
                raise HTTPException(status_code=404, detail="Item not found")
            
            # Check if user is owner or claimant
            if token_data["user_id"] not in [item_row["owner_id"], item_row["claimed_by"]]:
                raise HTTPException(status_code=403, detail="Not authorized to view chat for this item")
            
            # Get messages
            messages_rows = await conn.fetch("""
                SELECT * FROM chat_messages 
                WHERE item_id = $1 
                ORDER BY timestamp ASC
            """, item_id)
            
            messages = []
            for msg_row in messages_rows:
                messages.append({
                    "message_id": msg_row["message_id"],
                    "sender_id": msg_row["sender_id"],
                    "sender_email": msg_row["sender_email"],
                    "sender_name": msg_row["sender_name"],
                    "message": msg_row["message"],
                    "timestamp": msg_row["timestamp"].isoformat() if msg_row["timestamp"] else "",
                    "created_at": msg_row["created_at"].isoformat() if msg_row["created_at"] else ""
                })
            
            print(f"📊 Found {len(messages)} messages")
            return messages
        finally:
            await conn.close()
        
    except Exception as e:
        print(f"❌ Error getting messages: {e}")
        return []

@app.put("/items/{item_id}/complete")
async def complete_transaction(item_id: str, token_data: dict = Depends(verify_token)):
    """Mark item as completed (owner or claimant)"""
    try:
        conn = await get_db_connection()
        try:
            # Find item
            item_row = await conn.fetchrow("SELECT * FROM items WHERE item_id = $1", item_id)
            
            if not item_row:
                raise HTTPException(status_code=404, detail="Item not found")
            
            # Check if user is owner or claimant
            if token_data["user_id"] not in [item_row["owner_id"], item_row["claimed_by"]]:
                raise HTTPException(status_code=403, detail="Not authorized to complete this transaction")
            
            # Update item status
            await conn.execute("""
                UPDATE items 
                SET status = $1, completed_at = $2 
                WHERE item_id = $3
            """,
            "completed",
            datetime.utcnow(),
            item_id
            )
            
            return {"message": "Transaction completed successfully"}
        finally:
            await conn.close()
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# Location Management
@app.get("/locations")
async def get_locations():
    """Get all available locations"""
    try:
        conn = await get_db_connection()
        try:
            locations_rows = await conn.fetch("SELECT * FROM locations WHERE is_active = true")
            
            locations = []
            for location_row in locations_rows:
                locations.append({
                    "location_id": location_row["location_id"],
                    "name": location_row["name"],
                    "description": location_row["description"]
                })
            
            print(f"Found {len(locations)} locations")
            return locations
        finally:
            await conn.close()
        
    except Exception as e:
        print(f"Error in get_locations: {e}")
        import traceback
        traceback.print_exc()
        return []

@app.post("/admin/locations")
async def create_location(location: LocationCreate, token_data: dict = Depends(admin_required)):
    """Create new location (Admin only)"""
    try:
        location_id = str(uuid.uuid4())
        
        conn = await get_db_connection()
        try:
            await conn.execute("""
                INSERT INTO locations (location_id, name, description, is_active, created_at)
                VALUES ($1, $2, $3, $4, $5)
            """,
            location_id,
            location.name,
            location.description,
            True,
            datetime.utcnow()
            )
            
            print(f"Location created successfully: {location.name}")
            return {"message": "Location created successfully", "location_id": location_id}
        finally:
            await conn.close()
        
    except Exception as e:
        print(f"Error creating location: {e}")
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Failed to create location: {str(e)}")

@app.delete("/admin/locations/{location_id}")
async def delete_location(
    location_id: str,
    token_data: dict = Depends(admin_required)
):
    """Delete a location (Admin only)"""
    try:
        print(f"🗑️ Admin deleting location: {location_id}")
        
        conn = await get_db_connection()
        try:
            # Delete from PostgreSQL
            result = await conn.execute("DELETE FROM locations WHERE location_id = $1", location_id)
            
            if result == "DELETE 0":
                raise HTTPException(status_code=404, detail="Location not found")
            
            print(f"✅ Location deleted successfully")
            return {"message": "Location deleted successfully"}
        finally:
            await conn.close()
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"❌ Error deleting location: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/terms-content")
async def get_terms_content():
    """Get current terms and conditions content"""
    try:
        print("📋 Getting terms content...")
        
        conn = await get_db_connection()
        try:
            terms_row = await conn.fetchrow("SELECT * FROM app_settings WHERE setting_key = $1", "TERMS_CONTENT")
            
            if terms_row:
                content = terms_row["setting_value"]
                print(f"✅ Found custom terms content ({len(content)} chars)")
                return {"content": content}
            else:
                # Return default terms if none set
                print("🔍 Using default terms content")
                default_terms = """Welcome to Eco Pantry - PUP Community Exchange!

By using this application, you agree to the following terms:

1. Community Guidelines
   • Respect all community members
   • Only post items you genuinely want to share
   • Be honest about item conditions

2. Item Sharing Rules
   • Items must be in good, usable condition
   • No illegal, dangerous, or inappropriate items
   • You are responsible for arranging pickup/delivery

3. Account Responsibility
   • Keep your account information accurate
   • Do not share your login credentials
   • Report any suspicious activity

4. Privacy & Safety
   • We protect your personal information
   • Contact details are only shared between exchange participants
   • Admin may moderate content for community safety

5. Liability
   • Use the app at your own risk
   • PUP and Eco Pantry are not responsible for disputes
   • Users are responsible for their own safety during exchanges

By clicking "I Accept", you agree to these terms and conditions.

Last updated: August 2025"""
                
                return {"content": default_terms}
        finally:
            await conn.close()
            
    except Exception as e:
        print(f"❌ Error getting terms content: {e}")
        return {"content": "By using this app, you agree to our terms and conditions."}

@app.put("/admin/terms-content")
async def update_terms_content(
    request: dict,
    token_data: dict = Depends(admin_required)
):
    """Update terms and conditions content (Admin only)"""
    try:
        content = request.get("content", "")
        print(f"🔍 Admin updating terms content ({len(content)} chars)")
        
        conn = await get_db_connection()
        try:
            # Use UPSERT (INSERT ... ON CONFLICT)
            await conn.execute("""
                INSERT INTO app_settings (setting_key, setting_value, updated_at, updated_by)
                VALUES ($1, $2, $3, $4)
                ON CONFLICT (setting_key) 
                DO UPDATE SET 
                    setting_value = EXCLUDED.setting_value,
                    updated_at = EXCLUDED.updated_at,
                    updated_by = EXCLUDED.updated_by
            """,
            "TERMS_CONTENT",
            content,
            datetime.utcnow(),
            token_data["user_id"]
            )
            
            print("✅ Terms content updated successfully")
            return {"message": "Terms content updated successfully"}
        finally:
            await conn.close()
        
    except Exception as e:
        print(f"❌ Error updating terms content: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# Categories endpoint
@app.get("/categories")
async def get_categories():
    """Get item categories"""
    return [
        "Plastic Bottles",
        "Glass Containers", 
        "Paper Products",
        "Electronics",
        "Textiles",
        "Metal Items",
        "Cardboard",
        "Other"
    ]

@app.post("/get-ai-recommendations")
async def get_ai_recommendations(token_data: dict = Depends(verify_token)):
    """Get AI recommendations based on available recyclable materials"""
    try:
        print(f"🤖 Getting AI recommendations for user: {token_data.get('user_id')}")
        
        if not model:
            return {"success": False, "error": "AI service not available"}
        
        # Get user info for personalization
        conn = await get_db_connection()
        try:
            user_row = await conn.fetchrow("SELECT * FROM users WHERE user_id = $1", token_data["user_id"])
            user_name = "Friend"
            if user_row:
                user_name = user_row["name"].split()[0] if user_row["name"] else "Friend"
            
            # Get current approved items
            items_rows = await conn.fetch("SELECT * FROM items WHERE approved = true")
            
            # Create materials context with ALL items
            materials_context = "\n".join([f"- {item_row['name']} ({item_row['category']})" for item_row in items_rows])
            
            # Calculate suggestions count based on items
            items_count = len(items_rows)
            if items_count <= 5:
                suggestions_count = "3-5"
            elif items_count <= 15:
                suggestions_count = "7-10"
            elif items_count <= 30:
                suggestions_count = "10-15"
            else:
                suggestions_count = "15-20"
            
            # Check if Christmas season
            current_month = datetime.now().month
            is_christmas = current_month in [11, 12, 1]
            
            prompt = f"""Hello {user_name}! 👋

Welcome to GreenHouse AI! Here are ALL {items_count} recyclable materials from your PUP community:

{materials_context}

Based on these {items_count} available materials, give {suggestions_count} creative Filipino ways to reuse them:

{"🎄 Include Christmas parol ideas since it's Christmas season!" if is_christmas else ""}

Make the suggestions practical and versatile for:
- Home use (any living situation)
- School projects and activities 
- Community events and celebrations
- Creative arts and crafts
- Practical everyday solutions

Group similar materials together and suggest combination projects when possible.
Be specific about which items from the list to use for each suggestion.

Format your response cleanly with numbered suggestions (1, 2, 3...) without asterisks or special formatting.
Use simple, clean formatting - no asterisks, no bold markers, just clear numbered lists."""
            
            # Generate AI response
            ai_response = model.generate_content(
                prompt,
                generation_config={
                    'max_output_tokens': 2000,
                    'temperature': 0.8,
                }
            )
            
            # Clean up the formatting
            ai_text = ai_response.text
            ai_text = ai_text.replace('**', '')   # Remove double asterisks
            ai_text = ai_text.replace('***', '')  # Remove triple asterisks
            ai_text = ai_text.replace('*', '')    # Remove single asterisks
            
            return {
                "success": True,
                "recommendations": ai_text,
                "available_items_count": len(items_rows),
                "suggestions_count": suggestions_count
            }
        finally:
            await conn.close()
        
    except Exception as e:
        print(f"❌ AI error: {e}")
        return {"success": False, "error": str(e)}

# Notification endpoints
@app.get("/notifications")
async def get_user_notifications(token_data: dict = Depends(verify_token)):
    """Get all notifications for the current user"""
    try:
        user_id = token_data["user_id"]
        print(f"📬 Getting notifications for user: {user_id}")
        
        conn = await get_db_connection()
        try:
            notifications_rows = await conn.fetch("""
                SELECT * FROM notifications 
                WHERE user_id = $1 
                ORDER BY created_at DESC
            """, user_id)
            
            notifications = []
            for notif_row in notifications_rows:
                notification = {
                    "notification_id": notif_row["notification_id"],
                    "user_id": notif_row["user_id"],
                    "title": notif_row["title"],
                    "message": notif_row["message"],
                    "type": notif_row["type"],
                    "related_item_id": notif_row["related_item_id"],
                    "action_url": notif_row["action_url"],
                    "is_read": notif_row["is_read"],
                    "created_at": notif_row["created_at"].isoformat() if notif_row["created_at"] else ""
                }
                notifications.append(notification)
            
            print(f"📨 Found {len(notifications)} notifications")
            return notifications
        finally:
            await conn.close()
        
    except Exception as e:
        print(f"❌ Error getting notifications: {e}")
        return []

@app.put("/notifications/{notification_id}/read")
async def mark_notification_read(notification_id: str, token_data: dict = Depends(verify_token)):
    """Mark a notification as read"""
    try:
        user_id = token_data["user_id"]
        print(f"👁️ Marking notification as read: {notification_id}")
        
        conn = await get_db_connection()
        try:
            result = await conn.execute("""
                UPDATE notifications 
                SET is_read = true 
                WHERE notification_id = $1 AND user_id = $2
            """, notification_id, user_id)
            
            if result == "UPDATE 0":
                raise HTTPException(status_code=404, detail="Notification not found")
                
            print(f"✅ Notification marked as read")
            return {"message": "Notification marked as read"}
        finally:
            await conn.close()
            
    except Exception as e:
        print(f"❌ Error marking notification as read: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.put("/notifications/mark-all-read")
async def mark_all_notifications_read(token_data: dict = Depends(verify_token)):
    """Mark all notifications as read for the current user"""
    try:
        user_id = token_data["user_id"]
        print(f"👁️ Marking all notifications as read for user: {user_id}")
        
        conn = await get_db_connection()
        try:
            result = await conn.execute("""
                UPDATE notifications 
                SET is_read = true 
                WHERE user_id = $1 AND is_read = false
            """, user_id)
            
            # Extract count from result (format is "UPDATE n")
            count = int(result.split()[1]) if result.startswith("UPDATE") else 0
            
            print(f"✅ Marked {count} notifications as read")
            return {"message": f"Marked {count} notifications as read"}
        finally:
            await conn.close()
        
    except Exception as e:
        print(f"❌ Error marking all notifications as read: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/notifications/unread-count")
async def get_unread_notification_count(token_data: dict = Depends(verify_token)):
    """Get count of unread notifications"""
    try:
        user_id = token_data["user_id"]
        
        conn = await get_db_connection()
        try:
            count_row = await conn.fetchval("""
                SELECT COUNT(*) FROM notifications 
                WHERE user_id = $1 AND is_read = false
            """, user_id)
            
            count = count_row or 0
            return {"unread_count": count}
        finally:
            await conn.close()
        
    except Exception as e:
        print(f"❌ Error getting unread count: {e}")
        return {"unread_count": 0}

@app.delete("/admin/users/{google_id}")
async def delete_user_permanently(
    google_id: str,
    token_data: dict = Depends(admin_required)
):
    """Permanently delete a user and all their data (Admin only)"""
    try:
        print(f"🗑️ Admin permanently deleting user: {google_id}")
        
        conn = await get_db_connection()
        try:
            # Get user info before deletion
            user_row = await conn.fetchrow("SELECT * FROM users WHERE user_id = $1", google_id)
            
            if not user_row:
                raise HTTPException(status_code=404, detail=f"User {google_id} not found")
            
            user_name = user_row["name"]
            
            # Delete user's items
            deleted_items_result = await conn.execute("DELETE FROM items WHERE owner_id = $1", google_id)
            deleted_items = int(deleted_items_result.split()[1]) if deleted_items_result.startswith("DELETE") else 0
            
            # Delete user's chat messages
            await conn.execute("DELETE FROM chat_messages WHERE sender_id = $1", google_id)
            
            # Delete user's notifications
            await conn.execute("DELETE FROM notifications WHERE user_id = $1", google_id)
            
            # Delete user
            await conn.execute("DELETE FROM users WHERE user_id = $1", google_id)
            
            print(f"✅ User deleted: {user_name} (ID: {google_id})")
            print(f"📊 Also deleted {deleted_items} items belonging to user")
            
            return {
                "message": f"User {user_name} deleted permanently",
                "deleted_items": deleted_items,
                "user_name": user_name
            }
        finally:
            await conn.close()
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"❌ Error deleting user: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/admin/verify-password")
async def verify_current_password(request: dict, token_data: dict = Depends(admin_required)):
    """Verify admin's current password"""
    try:
        email = request.get("email")
        password = request.get("password")
        
        result = admin_manager.authenticate_admin(email, password)
        
        return {"success": result["success"]}
        
    except Exception as e:
        return {"success": False, "error": str(e)}

# Debug endpoints
@app.get("/debug/admin-items")
async def debug_admin_items():
    """Debug what admin sees in pending items"""
    try:
        conn = await get_db_connection()
        try:
            items_rows = await conn.fetch("SELECT * FROM items WHERE approved = false")
            
            items = []
            for item_row in items_rows:
                items.append({
                    "name": item_row["name"],
                    "item_id": item_row["item_id"],
                    "owner_name": item_row["owner_name"],
                    "approved": item_row["approved"],
                    "rejection_reason": item_row["rejection_reason"]
                })
            
            return {"pending_items": items}
        finally:
            await conn.close()
        
    except Exception as e:
        return {"error": str(e)}

@app.get("/debug/items-status")
async def debug_items_status():
    """Debug endpoint to check item approval status"""
    try:
        conn = await get_db_connection()
        try:
            items_rows = await conn.fetch("SELECT * FROM items")
            
            items_status = []
            for item_row in items_rows:
                items_status.append({
                    "name": item_row["name"],
                    "approved": item_row["approved"],
                    "status": item_row["status"],
                    "owner": item_row["owner_name"],
                    "created_at": item_row["created_at"].isoformat() if item_row["created_at"] else ""
                })
            
            return {
                "total_items": len(items_status),
                "items": items_status
            }
        finally:
            await conn.close()
        
    except Exception as e:
        return {"error": str(e)}

@app.get("/debug/items")
async def debug_items():
    """Debug endpoint to check items in database"""
    try:
        conn = await get_db_connection()
        try:
            items_rows = await conn.fetch("SELECT * FROM items")
            
            print(f"Found {len(items_rows)} items")
            for item_row in items_rows:
                print(f"Item: {dict(item_row)}")
                
            return {
                "count": len(items_rows),
                "items": [dict(item_row) for item_row in items_rows]
            }
        finally:
            await conn.close()
    except Exception as e:
        return {"error": str(e)}

@app.get("/debug/users")
async def debug_users():
    """Debug endpoint to check users in database"""
    try:
        conn = await get_db_connection()
        try:
            users_rows = await conn.fetch("SELECT * FROM users")
            
            print(f"Found {len(users_rows)} user profiles")
            for user_row in users_rows:
                print(f"User: {dict(user_row)}")
                
            return {
                "count": len(users_rows),
                "users": [dict(user_row) for user_row in users_rows]
            }
        finally:
            await conn.close()
    except Exception as e:
        return {"error": str(e)}

@app.get("/debug/table")
async def debug_table():
    """Debug endpoint to check table contents"""
    try:
        conn = await get_db_connection()
        try:
            # Get table names
            tables_rows = await conn.fetch("""
                SELECT table_name FROM information_schema.tables 
                WHERE table_schema = 'public'
            """)
            
            tables = [row["table_name"] for row in tables_rows]
            return {
                "tables": tables,
                "database_url": DATABASE_URL[:50] + "..." if DATABASE_URL else "Not set"
            }
        finally:
            await conn.close()
    except Exception as e:
        return {"error": str(e)}

# Health check
@app.get("/health")
async def health_check():
    return {"status": "healthy", "timestamp": datetime.utcnow().isoformat()}

# Startup event to initialize database
@app.on_event("startup")
async def startup_event():
    """Initialize database on startup"""
    try:
        await init_database()
        print("🚀 Application startup complete")
    except Exception as e:
        print(f"❌ Startup error: {e}")

if __name__ == "__main__":
    import uvicorn
    print("🚀 Starting server...")
    print(f"🌐 Server will run on port: {PORT}")
    uvicorn.run("main:app", host="0.0.0.0", port=PORT, reload=False)
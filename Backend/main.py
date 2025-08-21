from fastapi import FastAPI, HTTPException, Depends, UploadFile, File, Form, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, EmailStr
from typing import Optional, List, Dict, Any
import asyncpg
import json
import uuid
from datetime import datetime, timedelta
import base64
import aiofiles
import hashlib
from dotenv import load_dotenv
import jwt
import google.generativeai as genai
import os
import uuid
from pathlib import Path
import psycopg2
from psycopg2.extras import RealDictCursor

# Load environment variables
load_dotenv()

# Initialize FastAPI app
app = FastAPI(title="Eco Pantry API", version="1.0.0")

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",  # Local development
        "https://thegreenhouse-project.netlify.app",  # Your Netlify frontend
        "https://your-frontend-name.netlify.app",  # If different URL
        "https://pup-greenhouse-backend.onrender.com"  # Your Render backend URL
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# # === PostgreSQL Configuration (NO AWS) ===
# DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://greenhouse_user:greenhouse_password@localhost:5432/greenhouse_db")
# UPLOAD_DIR = Path("uploads")
# UPLOAD_DIR.mkdir(exist_ok=True)
# UPLOAD_BASE_URL = "http://localhost:8000/uploads"

# # Serve uploaded files statically
# app.mount("/uploads", StaticFiles(directory="uploads"), name="uploads")

SECRET_KEY = os.getenv("SECRET_KEY", "fallback-secret-key-for-development")
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
if not GEMINI_API_KEY:
    print("⚠️ GEMINI_API_KEY not found - AI features will be disabled")

# Security
security = HTTPBearer()
SECRET_KEY = os.getenv("SECRET_KEY", "eco-pantry-local-secret-key-2024")

# Google OAuth Config
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID", "740603627895-39r4nspre969ll50ehr4ele2isnn24du.apps.googleusercontent.com")

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

# === PostgreSQL Database initialization (NO AWS) ===
db_pool = None
admin_manager = None

class LocalAdminAuthManager:
    def __init__(self, db_pool):
        self.db_pool = db_pool
        self.smtp_username = os.getenv("SMTP_USERNAME")
        self.smtp_password = os.getenv("SMTP_PASSWORD")
        
    def hash_password(self, password: str) -> str:
        return hashlib.sha256(password.encode()).hexdigest()
    
    async def check_first_time_setup(self) -> bool:
        try:
            if self.db_pool:
                async with self.db_pool.acquire() as conn:
                    result = await conn.fetchval("SELECT COUNT(*) FROM admin_accounts")
                    return result == 0
            return True
        except Exception as e:
            print(f"Error checking first time setup: {e}")
            return True
    
    async def create_admin(self, name: str, email: str, password: str):
        try:
            if not await self.check_first_time_setup():
                return {"success": False, "error": "Admin already exists"}
            
            password_hash = self.hash_password(password)
            admin_id = str(uuid.uuid4())
            
            if self.db_pool:
                async with self.db_pool.acquire() as conn:
                    await conn.execute("""
                        INSERT INTO admin_accounts (user_id, name, email, password_hash, created_at)
                        VALUES ($1, $2, $3, $4, $5)
                    """, admin_id, name, email.lower(), password_hash, datetime.utcnow())
            
            return {"success": True, "message": "Admin account created successfully", "admin_id": admin_id}
            
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    async def authenticate_admin(self, email: str, password: str):
        try:
            if self.db_pool:
                async with self.db_pool.acquire() as conn:
                    admin = await conn.fetchrow("SELECT * FROM admin_accounts WHERE email = $1", email.lower())
                    
                    if not admin or not self.hash_password(password) == admin["password_hash"]:
                        return {"success": False, "error": "Invalid credentials"}
                    
                    await conn.execute("UPDATE admin_accounts SET last_login = $1 WHERE user_id = $2", datetime.utcnow(), admin["user_id"])
                    
                    return {
                        "success": True,
                        "admin": {
                            "user_id": admin["user_id"],
                            "name": admin["name"],
                            "email": admin["email"],
                            "is_admin": True
                        }
                    }
            return {"success": False, "error": "Invalid credentials"}
        except Exception as e:
            return {"success": False, "error": "Authentication failed"}

async def init_db():
    global db_pool, admin_manager
    try:
        print("🔌 Connecting to PostgreSQL...")
        db_pool = await asyncpg.create_pool(DATABASE_URL, min_size=1, max_size=10)
        print("✅ Database connection pool created")
        await create_tables()
        admin_manager = LocalAdminAuthManager(db_pool)
        print("✅ Admin manager initialized")
    except Exception as e:
        print(f"❌ Database initialization error: {e}")

async def create_tables():
    if not db_pool:
        return
    async with db_pool.acquire() as conn:
        print("📋 Creating database tables...")
        
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
            );
        """)
        
        # Admin accounts table
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS admin_accounts (
                user_id VARCHAR(255) PRIMARY KEY,
                name VARCHAR(255) NOT NULL,
                email VARCHAR(255) UNIQUE NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP
            );
        """)
        
        # Items table
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS items (
                item_id VARCHAR(255) PRIMARY KEY,
                name VARCHAR(255) NOT NULL,
                quantity INTEGER NOT NULL,
                category VARCHAR(255) NOT NULL,
                location VARCHAR(255) NOT NULL,
                owner_id VARCHAR(255) NOT NULL,
                owner_name VARCHAR(255),
                owner_email VARCHAR(255),
                expiry_date TIMESTAMP,
                duration_days INTEGER DEFAULT 7,
                comments TEXT,
                contact_info TEXT,
                image_urls TEXT[],
                status VARCHAR(50) DEFAULT 'available',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                approved BOOLEAN DEFAULT FALSE,
                claimed_by VARCHAR(255),
                claimant_email VARCHAR(255),
                claim_expires_at TIMESTAMP,
                rejection_reason TEXT,
                rejected_at TIMESTAMP,
                approved_at TIMESTAMP
            );
        """)
        
        # Locations table
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS locations (
                location_id VARCHAR(255) PRIMARY KEY,
                name VARCHAR(255) NOT NULL,
                address TEXT NOT NULL,
                description TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_active BOOLEAN DEFAULT TRUE
            );
        """)
        
        # Chat messages table
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS chat_messages (
                message_id VARCHAR(255) PRIMARY KEY,
                sender_id VARCHAR(255) NOT NULL,
                receiver_id VARCHAR(255) NOT NULL,
                message TEXT NOT NULL,
                item_id VARCHAR(255),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                read_at TIMESTAMP
            );
        """)
        
        # Notifications table
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS notifications (
                notification_id VARCHAR(255) PRIMARY KEY,
                user_id VARCHAR(255) NOT NULL,
                title VARCHAR(255) NOT NULL,
                message TEXT NOT NULL,
                type VARCHAR(50) DEFAULT 'info',
                read BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)
        
        # Settings table
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS settings (
                setting_key VARCHAR(255) PRIMARY KEY,
                setting_value TEXT,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)
        
        print("✅ Database tables created successfully!")
from contextlib import asynccontextmanager

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    print("🚀 Starting Eco Pantry Backend...")
    await init_db()
    yield
    # Shutdown
    if db_pool:
        await db_pool.close()

# Update your FastAPI app initialization (around line 27)
app = FastAPI(
    title="Eco Pantry API", 
    version="1.0.0",
    lifespan=lifespan  # ← Add this line
)

# Initialize Gemini AI model (NO AWS DEPENDENCIES)
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

# Helper Functions (NO AWS)
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

# LOCAL FILE UPLOAD (NO S3)
async def upload_to_local(file: UploadFile, folder: str) -> str:
    """Upload file to local storage instead of S3"""
    try:
        if not file.filename:
            raise ValueError("No filename provided")
            
        print(f"📸 Starting local upload: {file.filename}")
        
        # Create folder if it doesn't exist
        folder_path = UPLOAD_DIR / folder
        folder_path.mkdir(exist_ok=True)
        
        # Validate file
        content = await file.read()
        if len(content) == 0:
            raise ValueError("Empty file")
        
        if len(content) > 5 * 1024 * 1024:  # 5MB limit
            raise ValueError(f"File too large: {len(content)} bytes")
        
        # Generate unique filename with proper extension
        file_extension = file.filename.split('.')[-1].lower() if '.' in file.filename else 'jpg'
        if file_extension not in ['jpg', 'jpeg', 'png', 'gif']:
            file_extension = 'jpg'  # Default to jpg
            
        unique_filename = f"{uuid.uuid4()}.{file_extension}"
        file_path = folder_path / unique_filename
        
        # Save file
        async with aiofiles.open(file_path, 'wb') as f:
            await f.write(content)
        
        # Generate URL
        url = f"{UPLOAD_BASE_URL}/{folder}/{unique_filename}"
        print(f"✅ Local upload successful: {url}")
        
        return url
        
    except Exception as e:
        print(f"❌ Local upload error: {str(e)}")
        raise

async def create_notification(user_id: str, title: str, message: str, notification_type: str, 
                            related_item_id: str = None, action_url: str = None):
    """Create a new notification for a user using PostgreSQL"""
    try:
        notification_id = str(uuid.uuid4())
        
        if db_pool:
            async with db_pool.acquire() as conn:
                await conn.execute("""
                    INSERT INTO notifications (notification_id, user_id, title, message, type, related_item_id, action_url, created_at)
                    VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                """, notification_id, user_id, title, message, notification_type, related_item_id, action_url, datetime.utcnow())
        
        print(f"✅ Notification created for user {user_id}: {title}")
        return notification_id
        
    except Exception as e:
        print(f"❌ Error creating notification: {e}")
        return None

@app.get("/items")
async def get_items(
    category: Optional[str] = None,
    status: Optional[str] = None,
    approved_only: bool = True
):
    """Get all items (newsfeed)"""
    try:
        print(f"🔍 GET /items called with: category={category}, status={status}, approved_only={approved_only}")
        
        # Scan for all items
        response = table.scan(
            FilterExpression="begins_with(user_id, :item_prefix) AND item_id = :details",
            ExpressionAttributeValues={
                ":item_prefix": "ITEM#",
                ":details": "DETAILS"
            }
        )
        
        all_items = response.get("Items", [])
        print(f"📊 Found {len(all_items)} total items in database")
        
        items = []
        approved_count = 0
        
        for item in all_items:
            try:
                is_approved = item.get("approved", False)
                item_status = item.get("status", "unknown")
                item_name = item.get("name", "Unknown")
                
                print(f"📝 Processing item: {item_name} - approved: {is_approved}, status: {item_status}")
                
                # Apply approved filter
                if approved_only and not is_approved:
                    print(f"⏭️ Skipping {item_name} - not approved")
                    continue
                
                approved_count += 1
                print(f"✅ Including approved item: {item_name}")
                
                # Apply other filters
                if category and item.get("category") != category:
                    print(f"⏭️ Skipping {item_name} - category filter")
                    continue
                    
                if status and item.get("status") != status:
                    print(f"⏭️ Skipping {item_name} - status filter")
                    continue
                
                # Create item response
                item_response_data = {
                    "item_id": item.get("item_id_unique", item.get("user_id", "").replace("ITEM#", "")),
                    "name": item.get("name", ""),
                    "quantity": item.get("quantity", 0),
                    "category": item.get("category", ""),
                    "location": item.get("location", ""),
                    "owner_id": item.get("owner_id", ""),
                    "owner_name": item.get("owner_name", ""),
                    "owner_email": item.get("owner_email", ""),
                    "expiry_date": item.get("expiry_date"),
                    "duration_days": item.get("duration_days", 7),
                    "comments": item.get("comments"),
                    "contact_info": item.get("contact_info"),
                    "image_urls": item.get("image_urls", []),
                    "images": item.get("image_urls", []),
                    "status": item.get("status", "available"),
                    "created_at": item.get("created_at", ""),
                    "approved": item.get("approved", False),
                    "claimed_by": item.get("claimed_by"),
                    "claimant_email": item.get("claimant_email"),
                    "claim_expires_at": item.get("claim_expires_at")
                }
                
                items.append(item_response_data)
                print(f"✅ Added item to response: {item_name}")
                
            except Exception as e:
                print(f"❌ Error processing item: {e}")
                continue
        
        print(f"🎯 Final result: returning {len(items)} items to user (approved: {approved_count})")
        return items
        
    except Exception as e:
        print(f"❌ Error getting items: {e}")
        import traceback
        traceback.print_exc()
        return []

@app.post("/admin/login")
async def admin_login(login_data: AdminLogin):
    """Admin login with email/password"""
    try:
        print(f"🔐 Admin login attempt: {login_data.email}")
        
        if not admin_manager:
            raise HTTPException(status_code=500, detail="Admin manager not initialized")
        
        # Authenticate admin
        result = await admin_manager.authenticate_admin(login_data.email, login_data.password)
        
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


@app.post("/admin/login")
async def admin_login(login_data: AdminLogin):
    """Admin login with email/password"""
    try:
        print(f"🔐 Admin login attempt: {login_data.email}")
        
        if not admin_manager:
            raise HTTPException(status_code=500, detail="Admin manager not initialized")
        
        # Authenticate admin
        result = await admin_manager.authenticate_admin(login_data.email, login_data.password)
        
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


@app.get("/admin/setup/check")
async def check_admin_setup():
    """Check if admin setup is needed"""
    try:
        if admin_manager:
            is_first_time = await admin_manager.check_first_time_setup()
            return {
                "first_time_setup": is_first_time,
                "message": "Admin setup required" if is_first_time else "Admin already exists"
            }
        else:
            return {"first_time_setup": True, "error": "Admin manager not initialized"}
    except Exception as e:
        print(f"Error checking admin setup: {e}")
        return {"first_time_setup": True, "error": str(e)}

@app.get("/items/{item_id}")
async def get_item(item_id: str):
    """Get specific item details"""
    try:
        # Find item by item_id_unique
        response = table.scan(
            FilterExpression="begins_with(user_id, :item_prefix) AND item_id = :details",
            ExpressionAttributeValues={
                ":item_prefix": "ITEM#",
                ":details": "DETAILS"
            }
        )
        
        for item in response.get("Items", []):
            if item.get("item_id_unique") == item_id:
                return {
                    "item_id": item.get("item_id_unique"),
                    "name": item.get("name", ""),
                    "quantity": item.get("quantity", 0),
                    "category": item.get("category", ""),
                    "location": item.get("location", ""),
                    "owner_id": item.get("owner_id", ""),
                    "owner_name": item.get("owner_name", ""),
                    "owner_email": item.get("owner_email", ""),
                    "expiry_date": item.get("expiry_date"),
                    "duration_days": item.get("duration_days", 7),
                    "comments": item.get("comments"),
                    "contact_info": item.get("contact_info"),
                    "image_urls": item.get("image_urls", []),
                    "status": item.get("status", "available"),
                    "created_at": item.get("created_at", ""),
                    "approved": item.get("approved", False),
                    "claimed_by": item.get("claimed_by"),
                    "claimant_email": item.get("claimant_email"),
                    "claim_expires_at": item.get("claim_expires_at")
                }
        
        raise HTTPException(status_code=404, detail="Item not found")
        
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
        # Find item by item_id_unique
        response = table.scan(
            FilterExpression="begins_with(user_id, :item_prefix) AND item_id = :details",
            ExpressionAttributeValues={
                ":item_prefix": "ITEM#",
                ":details": "DETAILS"
            }
        )
        
        item_found = None
        for item in response.get("Items", []):
            if item.get("item_id_unique") == item_id:
                item_found = item
                break
        
        if not item_found:
            raise HTTPException(status_code=404, detail="Item not found")
        
        # Check ownership or admin
        if item_found["owner_id"] != token_data["user_id"] and not token_data.get("is_admin"):
            raise HTTPException(status_code=403, detail="Not authorized to update this item")
        
        # Update fields
        update_expression = "SET "
        expression_values = {}
        
        for field, value in item_update.dict(exclude_unset=True).items():
            if value is not None:
                update_expression += f"{field} = :{field}, "
                expression_values[f":{field}"] = value
        
        # Add approved = false if not admin (requires re-approval)
        if not token_data.get("is_admin"):
            update_expression += "approved = :approved, "
            expression_values[":approved"] = False
        
        update_expression = update_expression.rstrip(", ")
        
        table.update_item(
            Key={"user_id": item_found["user_id"], "item_id": "DETAILS"},
            UpdateExpression=update_expression,
            ExpressionAttributeValues=expression_values
        )
        
        return {"message": "Item updated successfully"}
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.delete("/items/{item_id}")
async def delete_item(item_id: str, token_data: dict = Depends(verify_token)):
    """Delete item (owner only)"""
    try:
        # Find item by item_id_unique
        response = table.scan(
            FilterExpression="begins_with(user_id, :item_prefix) AND item_id = :details",
            ExpressionAttributeValues={
                ":item_prefix": "ITEM#",
                ":details": "DETAILS"
            }
        )
        
        item_found = None
        for item in response.get("Items", []):
            if item.get("item_id_unique") == item_id:
                item_found = item
                break
        
        if not item_found:
            raise HTTPException(status_code=404, detail="Item not found")
        
        # Check ownership or admin
        if item_found["owner_id"] != token_data["user_id"] and not token_data.get("is_admin"):
            raise HTTPException(status_code=403, detail="Not authorized to delete this item")
        
        # Delete item
        table.delete_item(Key={"user_id": item_found["user_id"], "item_id": "DETAILS"})
        
        return {"message": "Item deleted successfully"}
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# Admin Item Management
@app.get("/admin/items/pending")
async def get_pending_items(token_data: dict = Depends(admin_required)):
    """Get pending items awaiting approval (Admin only)"""
    try:
        print("🔍 Getting pending items...")
        
        response = table.scan(
            FilterExpression="begins_with(user_id, :item_prefix) AND item_id = :details",
            ExpressionAttributeValues={
                ":item_prefix": "ITEM#",
                ":details": "DETAILS"
            }
        )
        
        items = []
        for item in response.get("Items", []):
            # ✅ FIXED LOGIC: Include items that are NOT approved AND have no rejection
            approved = item.get("approved", False)  # Default False for new items
            has_rejection = item.get("rejection_reason")  # None for new items
            
            print(f"📝 Item: {item.get('name')} - approved: {approved}, rejected: {bool(has_rejection)}")
            
            # Include if: NOT approved AND NOT rejected
            if not approved and not has_rejection:
                formatted_item = {
                    "item_id": item.get("item_id_unique", item.get("user_id", "").replace("ITEM#", "")),
                    "name": item.get("name"),
                    "quantity": item.get("quantity"),
                    "category": item.get("category"),
                    "location": item.get("location"),
                    "owner_email": item.get("owner_email"),
                    "owner_name": item.get("owner_name"),
                    "status": item.get("status"),
                    "created_at": item.get("created_at"),
                    "comments": item.get("comments"),
                    "images": item.get("image_urls", []),
                    "image_urls": item.get("image_urls", [])
                }
                items.append(formatted_item)
                print(f"✅ Including pending item: {item.get('name')}")
            else:
                print(f"⏭️ Skipping processed item: {item.get('name')} (approved: {approved}, rejected: {bool(has_rejection)})")
        
        print(f"📊 Returning {len(items)} pending items")
        return items
        
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
        
        response = table.scan(
            FilterExpression="begins_with(user_id, :item_prefix) AND item_id = :details AND approved = :approved",
            ExpressionAttributeValues={
                ":item_prefix": "ITEM#",
                ":details": "DETAILS",
                ":approved": True
            }
        )
        
        items = []
        for item in response.get("Items", []):
            formatted_item = {
                "item_id": item.get("item_id_unique", item.get("user_id", "").replace("ITEM#", "")),
                "name": item.get("name"),
                "quantity": item.get("quantity"),
                "category": item.get("category"),
                "location": item.get("location"),
                "owner_email": item.get("owner_email"),
                "owner_name": item.get("owner_name"),
                "status": item.get("status"),
                "approved": item.get("approved"),
                "created_at": item.get("created_at"),
                "images": item.get("image_urls", []),
                "image_urls": item.get("image_urls", [])
            }
            items.append(formatted_item)
        
        print(f"📊 Returning {len(items)} approved items")
        return items
        
    except Exception as e:
        print(f"❌ Error getting approved items: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/admin/items/rejected")
async def get_rejected_items(token_data: dict = Depends(admin_required)):
    """Get all rejected items (Admin only)"""
    try:
        print("❌ Getting rejected items...")
        
        # ✅ FIXED: Get all items first, then filter properly
        response = table.scan(
            FilterExpression="begins_with(user_id, :item_prefix) AND item_id = :details",
            ExpressionAttributeValues={
                ":item_prefix": "ITEM#",
                ":details": "DETAILS"
            }
        )
        
        items = []
        for item in response.get("Items", []):
            # ✅ KEY FIX: Only include items that have a rejection_reason
            rejection_reason = item.get("rejection_reason")
            if rejection_reason:  # This means it was explicitly rejected
                formatted_item = {
                    "item_id": item.get("item_id_unique", item.get("user_id", "").replace("ITEM#", "")),
                    "name": item.get("name"),
                    "quantity": item.get("quantity"),
                    "category": item.get("category"),
                    "location": item.get("location"),
                    "owner_email": item.get("owner_email"),
                    "owner_name": item.get("owner_name"),
                    "status": item.get("status"),
                    "approved": item.get("approved"),
                    "rejection_reason": rejection_reason,
                    "rejected_at": item.get("rejected_at"),
                    "created_at": item.get("created_at"),
                    "images": item.get("image_urls", []),
                    "image_urls": item.get("image_urls", [])
                }
                items.append(formatted_item)
                print(f"📝 Including rejected item: {item.get('name')} (reason: {rejection_reason})")
            else:
                print(f"⏭️ Skipping non-rejected item: {item.get('name')} (no rejection reason)")
        
        print(f"📊 Returning {len(items)} rejected items")
        return items
        
    except Exception as e:
        print(f"❌ Error getting rejected items: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.put("/admin/items/{item_id}/approve")
async def approve_item(item_id: str, token_data: dict = Depends(admin_required)):
    """Approve pending item (Admin only) - WITH NOTIFICATION"""
    try:
        print(f"✅ Admin approving item: {item_id}")
        
        # Find the item first
        response = table.scan(
            FilterExpression="begins_with(user_id, :item_prefix) AND item_id = :details",
            ExpressionAttributeValues={
                ":item_prefix": "ITEM#",
                ":details": "DETAILS"
            }
        )
        
        item_found = None
        for item in response.get("Items", []):
            if (item.get("item_id_unique") == item_id or 
                item.get("user_id", "").replace("ITEM#", "") == item_id):
                item_found = item
                break
        
        if not item_found:
            raise HTTPException(status_code=404, detail="Item not found")
        
        # Update the item to approved
        table.update_item(
            Key={"user_id": item_found["user_id"], "item_id": "DETAILS"},
            UpdateExpression="SET approved = :approved, approved_at = :timestamp",
            ExpressionAttributeValues={
                ":approved": True,
                ":timestamp": datetime.utcnow().isoformat()
            }
        )
        
        # 🔔 CREATE NOTIFICATION
        await create_notification(
            user_id=item_found["owner_id"],
            title="🎉 Item Approved!",
            message=f'Your item "{item_found.get("name")}" has been approved and is now live!',
            notification_type="item_approved",
            related_item_id=item_id,
            action_url=f"/dashboard"
        )
        
        print(f"✅ Item approved and notification sent: {item_found.get('name')}")
        return {"message": "Item approved successfully"}
        
    except Exception as e:
        print(f"❌ Error approving item: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    """Approve pending item (Admin only)"""
    try:
        print(f"✅ Admin approving item: {item_id}")
        
        # Handle wrong item_id format from frontend
        if item_id == "DETAILS":
            print("❌ Frontend sent 'DETAILS' as item_id - this is wrong")
            raise HTTPException(status_code=400, detail="Invalid item ID format")
        
        # Find the item using item_id_unique
        response = table.scan(
            FilterExpression="begins_with(user_id, :item_prefix) AND item_id = :details",
            ExpressionAttributeValues={
                ":item_prefix": "ITEM#",
                ":details": "DETAILS"
            }
        )
        
        item_found = None
        for item in response.get("Items", []):
            # Check both possible ID fields
            if (item.get("item_id_unique") == item_id or 
                item.get("user_id", "").replace("ITEM#", "") == item_id):
                item_found = item
                break
        
        if not item_found:
            print(f"❌ Item not found with ID: {item_id}")
            print("Available items:")
            for item in response.get("Items", []):
                print(f"  - {item.get('name')} (ID: {item.get('item_id_unique')}, user_id: {item.get('user_id')})")
            raise HTTPException(status_code=404, detail="Item not found")
        
        print(f"📝 Found item: {item_found.get('name')} by {item_found.get('owner_name')}")
        
        # Update the item to approved
        table.update_item(
            Key={"user_id": item_found["user_id"], "item_id": "DETAILS"},
            UpdateExpression="SET approved = :approved, approved_at = :timestamp",
            ExpressionAttributeValues={
                ":approved": True,
                ":timestamp": datetime.utcnow().isoformat()
            }
        )
        
        print(f"✅ Item approved successfully: {item_found.get('name')}")
        return {"message": "Item approved successfully"}
        
    except Exception as e:
        print(f"❌ Error approving item: {e}")
        import traceback
        traceback.print_exc()
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
        
        # Find the item
        response = table.scan(
            FilterExpression="begins_with(user_id, :item_prefix) AND item_id = :details",
            ExpressionAttributeValues={
                ":item_prefix": "ITEM#",
                ":details": "DETAILS"
            }
        )
        
        item_found = None
        for item in response.get("Items", []):
            item_uuid = item.get("item_id_unique", item.get("user_id", "").replace("ITEM#", ""))
            if item_uuid == item_id:
                item_found = item
                break
        
        if not item_found:
            raise HTTPException(status_code=404, detail="Item not found")
        
        # Update item as rejected
        table.update_item(
            Key={"user_id": item_found["user_id"], "item_id": "DETAILS"},
            UpdateExpression="SET approved = :approved, rejection_reason = :reason, rejected_at = :timestamp",
            ExpressionAttributeValues={
                ":approved": False,
                ":reason": reason,
                ":timestamp": datetime.utcnow().isoformat()
            }
        )
        
        # 🔔 CREATE NOTIFICATION
        await create_notification(
            user_id=item_found["owner_id"],
            title="❌ Item Rejected",
            message=f'Your item "{item_found.get("name")}" was rejected. Reason: {reason}',
            notification_type="item_rejected",
            related_item_id=item_id,
            action_url=f"/dashboard"
        )
        
        print(f"✅ Item rejected and notification sent: {item_found.get('name')}")
        return {"message": "Item rejected successfully"}
        
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
        
        # Find item
        response = table.scan(
            FilterExpression="begins_with(user_id, :item_prefix) AND item_id = :details",
            ExpressionAttributeValues={
                ":item_prefix": "ITEM#",
                ":details": "DETAILS"
            }
        )
        
        item_found = None
        for item in response.get("Items", []):
            if item.get("item_id_unique") == item_id:
                item_found = item
                break
        
        if not item_found:
            raise HTTPException(status_code=404, detail="Item not found")
        
        # Validation checks...
        if not item_found.get("approved", False):
            raise HTTPException(status_code=400, detail="Item not approved")
        
        if item_found.get("status") != "available":
            raise HTTPException(status_code=400, detail="Item not available")
        
        if item_found.get("owner_id") == token_data["user_id"]:
            raise HTTPException(status_code=400, detail="Cannot claim your own item")
        
        # Get claimant info
        user_response = table.get_item(
            Key={"user_id": token_data["user_id"], "item_id": "PROFILE"}
        )
        
        if "Item" not in user_response:
            raise HTTPException(status_code=404, detail="User not found")
        
        claimant = user_response["Item"]
        
        # Update item to claimed
        table.update_item(
            Key={"user_id": item_found["user_id"], "item_id": "DETAILS"},
            UpdateExpression="SET #status = :status, claimed_by = :claimed_by, claimant_email = :email, claim_expires_at = :expires",
            ExpressionAttributeNames={"#status": "status"},
            ExpressionAttributeValues={
                ":status": "claimed",
                ":claimed_by": token_data["user_id"],
                ":email": claimant.get("email"),
                ":expires": (datetime.utcnow() + timedelta(days=3)).isoformat()
            }
        )
        
        # 🔔 CREATE NOTIFICATION FOR ITEM OWNER
        await create_notification(
            user_id=item_found["owner_id"],
            title="🎯 Someone Claimed Your Item!",
            message=f'{claimant.get("name")} wants to claim your "{item_found.get("name")}". You can now chat with them!',
            notification_type="item_claimed",
            related_item_id=item_id,
            action_url=f"/dashboard"
        )
        
        print(f"✅ Item claimed and notification sent to owner")
        return {"message": "Item claimed successfully"}
        
    except Exception as e:
        print(f"❌ Error claiming item: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/my-claims")
async def get_my_claims(token_data: dict = Depends(verify_token)):
    """Get user's claims"""
    try:
        print(f"🔍 Getting claims for user: {token_data['user_id']}")
        
        # Find items claimed by this user
        response = table.scan(
            FilterExpression="begins_with(user_id, :item_prefix) AND item_id = :details AND claimed_by = :user_id",
            ExpressionAttributeValues={
                ":item_prefix": "ITEM#",
                ":details": "DETAILS",
                ":user_id": token_data["user_id"]
            }
        )
        
        claims = []
        for item in response.get("Items", []):
            try:
                claim_data = {
                    "claim_id": item.get("item_id_unique", ""),
                    "item_id": item.get("item_id_unique", ""),
                    "claimant_id": token_data["user_id"],
                    "status": item.get("status", "claimed"),
                    "created_at": item.get("claim_expires_at", ""),
                    "expires_at": item.get("claim_expires_at", ""),
                    "name": item.get("name", ""),
                    "owner_name": item.get("owner_name", ""),
                    "location": item.get("location", "")
                }
                claims.append(claim_data)
            except Exception as e:
                print(f"❌ Error processing claim: {e}")
                continue
        
        print(f"📊 Found {len(claims)} claims for user")
        return claims
        
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
        
        # Find item
        response = table.scan(
            FilterExpression="begins_with(user_id, :item_prefix) AND item_id = :details",
            ExpressionAttributeValues={
                ":item_prefix": "ITEM#",
                ":details": "DETAILS"
            }
        )
        
        item_found = None
        for item in response.get("Items", []):
            if item.get("item_id_unique") == item_id:
                item_found = item
                break
        
        if not item_found:
            raise HTTPException(status_code=404, detail="Item not found")
        
        # Check authorization
        if token_data["user_id"] not in [item_found["owner_id"], item_found.get("claimed_by")]:
            raise HTTPException(status_code=403, detail="Not authorized to chat for this item")
        
        # Get sender info
        user_response = table.get_item(
            Key={"user_id": token_data["user_id"], "item_id": "PROFILE"}
        )
        
        sender = user_response.get("Item", {}) if "Item" in user_response else {}
        
        # Create message
        message_id = str(uuid.uuid4())
        message_data = {
            "user_id": f"CHAT#{item_id}",
            "item_id": f"MSG#{datetime.utcnow().isoformat()}#{message_id}",
            "message_id": message_id,
            "chat_item_id": item_id,
            "sender_id": token_data["user_id"],
            "sender_email": sender.get("email", ""),
            "sender_name": sender.get("name", ""),
            "message": message.message,
            "timestamp": datetime.utcnow().isoformat(),
            "created_at": datetime.utcnow().isoformat()
        }
        
        table.put_item(Item=message_data)
        
        # 🔔 NOTIFY THE OTHER PERSON (not the sender)
        recipient_id = item_found.get("claimed_by") if token_data["user_id"] == item_found["owner_id"] else item_found["owner_id"]
        
        if recipient_id:
            await create_notification(
                user_id=recipient_id,
                title="💬 New Message",
                message=f'{sender.get("name")} sent you a message about "{item_found.get("name")}"',
                notification_type="new_message",
                related_item_id=item_id,
                action_url=f"/dashboard"
            )
        
        print(f"✅ Message sent and notification created")
        return {"message": "Message sent successfully", "message_id": message_id}
        
    except Exception as e:
        print(f"❌ Error sending message: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/items/{item_id}/chat/messages")
async def get_chat_messages(item_id: str, token_data: dict = Depends(verify_token)):
    """Get chat messages for item (only owner and claimant)"""
    try:
        print(f"💬 Getting messages for item: {item_id}")
        
        # Find item by item_id_unique
        response = table.scan(
            FilterExpression="begins_with(user_id, :item_prefix) AND item_id = :details",
            ExpressionAttributeValues={
                ":item_prefix": "ITEM#",
                ":details": "DETAILS"
            }
        )
        
        item_found = None
        for item in response.get("Items", []):
            if item.get("item_id_unique") == item_id:
                item_found = item
                break
        
        if not item_found:
            raise HTTPException(status_code=404, detail="Item not found")
        
        # Check if user is owner or claimant
        if token_data["user_id"] not in [item_found["owner_id"], item_found.get("claimed_by")]:
            raise HTTPException(status_code=403, detail="Not authorized to view chat for this item")
        
        # Get messages
        messages_response = table.scan(
            FilterExpression="begins_with(user_id, :chat_prefix) AND begins_with(item_id, :msg_prefix)",
            ExpressionAttributeValues={
                ":chat_prefix": f"CHAT#{item_id}",
                ":msg_prefix": "MSG#"
            }
        )
        
        messages = []
        for msg in messages_response.get("Items", []):
            messages.append({
                "message_id": msg.get("message_id", ""),
                "sender_id": msg.get("sender_id", ""),
                "sender_email": msg.get("sender_email", ""),
                "sender_name": msg.get("sender_name", ""),
                "message": msg.get("message", ""),
                "timestamp": msg.get("timestamp", ""),
                "created_at": msg.get("created_at", "")
            })
        
        # Sort by timestamp
        messages.sort(key=lambda x: x.get("timestamp", ""))
        
        print(f"📊 Found {len(messages)} messages")
        return messages
        
    except Exception as e:
        print(f"❌ Error getting messages: {e}")
        return []

@app.put("/items/{item_id}/complete")
async def complete_transaction(item_id: str, token_data: dict = Depends(verify_token)):
    """Mark item as completed (owner or claimant)"""
    try:
        # Find item by item_id_unique
        response = table.scan(
            FilterExpression="begins_with(user_id, :item_prefix) AND item_id = :details",
            ExpressionAttributeValues={
                ":item_prefix": "ITEM#",
                ":details": "DETAILS"
            }
        )
        
        item_found = None
        for item in response.get("Items", []):
            if item.get("item_id_unique") == item_id:
                item_found = item
                break
        
        if not item_found:
            raise HTTPException(status_code=404, detail="Item not found")
        
        # Check if user is owner or claimant
        if token_data["user_id"] not in [item_found["owner_id"], item_found.get("claimed_by")]:
            raise HTTPException(status_code=403, detail="Not authorized to complete this transaction")
        
        # Update item status
        table.update_item(
            Key={"user_id": item_found["user_id"], "item_id": "DETAILS"},
            UpdateExpression="SET #status = :status, completed_at = :completed_at",
            ExpressionAttributeValues={
                ":status": "completed",
                ":completed_at": datetime.utcnow().isoformat()
            },
            ExpressionAttributeNames={"#status": "status"}
        )
        
        return {"message": "Transaction completed successfully"}
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# Location Management
@app.get("/locations")
async def get_locations():
    """Get all available locations"""
    try:
        # Simple scan without complex filters first
        response = table.scan(
            FilterExpression="begins_with(user_id, :user_id)",
            ExpressionAttributeValues={":user_id": "LOCATION#"}
        )
        
        locations = []
        for item in response.get("Items", []):
            if item.get("item_id") == "DETAILS":
                # Only include active locations (default to True if field missing)
                if item.get("is_active", True):
                    locations.append({
                        "location_id": item.get("location_id", "unknown"),
                        "name": item.get("name", "Unknown"),
                        "description": item.get("description", "")
                    })
        
        print(f"Found {len(locations)} locations")
        return locations
        
    except Exception as e:
        print(f"Error in get_locations: {e}")
        import traceback
        traceback.print_exc()
        # Return empty array instead of error to prevent frontend crashes
        return []

@app.post("/admin/locations")
async def create_location(location: LocationCreate, token_data: dict = Depends(admin_required)):
    """Create new location (Admin only)"""
    try:
        location_id = str(uuid.uuid4())
        location_data = {
            "user_id": f"LOCATION#{location_id}",
            "item_id": "DETAILS",
            "location_id": location_id,
            "name": location.name,
            "description": location.description,
            "is_active": True,  # Set to True by default
            "created_at": datetime.utcnow().isoformat()
        }
        
        print(f"Creating location: {location_data}")
        response = table.put_item(Item=location_data)
        print(f"Location created successfully: {response}")
        
        return {"message": "Location created successfully", "location_id": location_id}
        
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
        
        # Delete from DynamoDB
        response = table.delete_item(
            Key={
                "user_id": f"LOCATION#{location_id}",
                "item_id": "DETAILS"
            },
            ReturnValues="ALL_OLD"
        )
        
        if "Attributes" not in response:
            raise HTTPException(status_code=404, detail="Location not found")
        
        print(f"✅ Location deleted: {response['Attributes'].get('name')}")
        return {"message": "Location deleted successfully"}
        
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
        
        # Try to get from database first
        response = table.get_item(
            Key={"user_id": "SETTINGS", "item_id": "TERMS_CONTENT"}
        )
        
        if "Item" in response:
            content = response["Item"].get("content", "")
            print(f"✅ Found custom terms content ({len(content)} chars)")
            return {"content": content}
        else:
            # Return default terms if none set
            print("📝 Using default terms content")
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

Last updated: July 2025"""
            
            return {"content": default_terms}
            
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
        print(f"📝 Admin updating terms content ({len(content)} chars)")
        
        terms_data = {
            "user_id": "SETTINGS",
            "item_id": "TERMS_CONTENT", 
            "content": content,
            "updated_at": datetime.utcnow().isoformat(),
            "updated_by": token_data["user_id"]
        }
        
        table.put_item(Item=terms_data)
        
        print("✅ Terms content updated successfully")
        return {"message": "Terms content updated successfully"}
        
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
        user_response = table.get_item(Key={"user_id": token_data["user_id"], "item_id": "PROFILE"})
        user_name = "Friend"
        if "Item" in user_response:
            user_name = user_response["Item"].get("name", "Friend").split()[0]
        
        # Get current approved items (NO LIMIT!)
        response = table.scan(
            FilterExpression="begins_with(user_id, :item_prefix) AND item_id = :details AND approved = :approved",
            ExpressionAttributeValues={":item_prefix": "ITEM#", ":details": "DETAILS", ":approved": True}
        )
        
        current_items = response.get("Items", [])
        
        # Create materials context with ALL items (not just 15)
        materials_context = "\n".join([f"- {item.get('name', '')} ({item.get('category', '')})" for item in current_items])
        
        # Calculate suggestions count based on items (but reasonable limits)
        items_count = len(current_items)
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
        
        # Make sure you're using the correct model name here
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
            "available_items_count": len(current_items),
            "suggestions_count": suggestions_count
        }
        
    except Exception as e:
        print(f"❌ AI error: {e}")
        return {"success": False, "error": str(e)}

# Debug endpoints
@app.get("/debug/admin-items")
async def debug_admin_items():
    """Debug what admin sees in pending items"""
    try:
        response = table.scan(
            FilterExpression="begins_with(user_id, :item_prefix) AND item_id = :details",
            ExpressionAttributeValues={
                ":item_prefix": "ITEM#",
                ":details": "DETAILS"
            }
        )
        
        items = []
        for item in response.get("Items", []):
            if not item.get("approved", False):
                items.append({
                    "name": item.get("name"),
                    "item_id": item.get("item_id"),  # This is probably "DETAILS"
                    "item_id_unique": item.get("item_id_unique"),  # This is the real ID
                    "user_id": item.get("user_id"),  # This is "ITEM#{uuid}"
                    "owner_name": item.get("owner_name")
                })
        
        return {"pending_items": items}
        
    except Exception as e:
        return {"error": str(e)}

@app.get("/debug/items-status")
async def debug_items_status():
    """Debug endpoint to check item approval status"""
    try:
        response = table.scan(
            FilterExpression="begins_with(user_id, :item_prefix) AND item_id = :details",
            ExpressionAttributeValues={
                ":item_prefix": "ITEM#",
                ":details": "DETAILS"
            }
        )
        
        items_status = []
        for item in response.get("Items", []):
            items_status.append({
                "name": item.get("name", "Unknown"),
                "approved": item.get("approved", False),
                "status": item.get("status", "unknown"),
                "owner": item.get("owner_name", "Unknown"),
                "created_at": item.get("created_at", "")
            })
        
        return {
            "total_items": len(items_status),
            "items": items_status
        }
        
    except Exception as e:
        return {"error": str(e)}

@app.get("/debug/items")
async def debug_items():
    """Debug endpoint to check items in database"""
    try:
        response = table.scan(
            FilterExpression="begins_with(user_id, :item_prefix)",
            ExpressionAttributeValues={":item_prefix": "ITEM#"}
        )
        
        print(f"Found {len(response.get('Items', []))} items")
        for item in response.get("Items", []):
            print(f"Item: {item}")
            
        return {
            "count": len(response.get("Items", [])),
            "items": response.get("Items", [])
        }
    except Exception as e:
        return {"error": str(e)}

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


@app.get("/notifications")
async def get_user_notifications(token_data: dict = Depends(verify_token)):
    """Get all notifications for the current user"""
    try:
        user_id = token_data["user_id"]
        print(f"📬 Getting notifications for user: {user_id}")
        
        # Get notifications for this user
        response = table.scan(
            FilterExpression="begins_with(user_id, :notification_prefix) AND target_user_id = :user_id",
            ExpressionAttributeValues={
                ":notification_prefix": f"NOTIFICATION#{user_id}",
                ":user_id": user_id
            }
        )
        
        notifications = []
        for item in response.get("Items", []):
            notification = {
                "notification_id": item.get("notification_id"),
                "user_id": item.get("target_user_id"),
                "title": item.get("title"),
                "message": item.get("message"),
                "type": item.get("type"),
                "related_item_id": item.get("related_item_id"),
                "action_url": item.get("action_url"),
                "is_read": item.get("is_read", False),
                "created_at": item.get("created_at")
            }
            notifications.append(notification)
        
        # Sort by created_at (newest first)
        notifications.sort(key=lambda x: x.get("created_at", ""), reverse=True)
        
        print(f"📨 Found {len(notifications)} notifications")
        return notifications
        
    except Exception as e:
        print(f"❌ Error getting notifications: {e}")
        return []
    


@app.put("/notifications/{notification_id}/read")
async def mark_notification_read(notification_id: str, token_data: dict = Depends(verify_token)):
    """Mark a notification as read"""
    try:
        user_id = token_data["user_id"]
        print(f"👁️ Marking notification as read: {notification_id}")
        
        # Find the notification
        response = table.scan(
            FilterExpression="begins_with(user_id, :notification_prefix) AND notification_id = :notif_id",
            ExpressionAttributeValues={
                ":notification_prefix": f"NOTIFICATION#{user_id}",
                ":notif_id": notification_id
            }
        )
        
        if response.get("Items"):
            notification = response["Items"][0]
            # Update to read
            table.update_item(
                Key={"user_id": notification["user_id"], "item_id": notification["item_id"]},
                UpdateExpression="SET is_read = :read",
                ExpressionAttributeValues={":read": True}
            )
            print(f"✅ Notification marked as read")
            return {"message": "Notification marked as read"}
        else:
            raise HTTPException(status_code=404, detail="Notification not found")
            
    except Exception as e:
        print(f"❌ Error marking notification as read: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.put("/notifications/mark-all-read")
async def mark_all_notifications_read(token_data: dict = Depends(verify_token)):
    """Mark all notifications as read for the current user"""
    try:
        user_id = token_data["user_id"]
        print(f"👁️ Marking all notifications as read for user: {user_id}")
        
        # Get all unread notifications
        response = table.scan(
            FilterExpression="begins_with(user_id, :notification_prefix) AND is_read = :unread",
            ExpressionAttributeValues={
                ":notification_prefix": f"NOTIFICATION#{user_id}",
                ":unread": False
            }
        )
        
        # Mark each as read
        for notification in response.get("Items", []):
            table.update_item(
                Key={"user_id": notification["user_id"], "item_id": notification["item_id"]},
                UpdateExpression="SET is_read = :read",
                ExpressionAttributeValues={":read": True}
            )
        
        count = len(response.get("Items", []))
        print(f"✅ Marked {count} notifications as read")
        return {"message": f"Marked {count} notifications as read"}
        
    except Exception as e:
        print(f"❌ Error marking all notifications as read: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/notifications/unread-count")
async def get_unread_notification_count(token_data: dict = Depends(verify_token)):
    """Get count of unread notifications"""
    try:
        user_id = token_data["user_id"]
        
        response = table.scan(
            FilterExpression="begins_with(user_id, :notification_prefix) AND is_read = :unread",
            ExpressionAttributeValues={
                ":notification_prefix": f"NOTIFICATION#{user_id}",
                ":unread": False
            },
            Select="COUNT"
        )
        
        count = response.get("Count", 0)
        return {"unread_count": count}
        
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
        
        # ✅ CORRECT KEY FORMAT based on your debug data
        user_response = table.delete_item(
            Key={"user_id": google_id, "item_id": "PROFILE"},
            ReturnValues="ALL_OLD"
        )
        
        if "Attributes" not in user_response:
            raise HTTPException(status_code=404, detail=f"User {google_id} not found")
        
        user_name = user_response["Attributes"].get("name", "Unknown")
        
        # Delete user's items
        items_response = table.scan(
            FilterExpression="begins_with(user_id, :item_prefix) AND owner_id = :owner_id",
            ExpressionAttributeValues={
                ":item_prefix": "ITEM#",
                ":owner_id": google_id
            }
        )
        
        deleted_items = 0
        for item in items_response.get("Items", []):
            table.delete_item(
                Key={"user_id": item["user_id"], "item_id": item["item_id"]}
            )
            deleted_items += 1
        
        print(f"✅ User deleted: {user_name} (ID: {google_id})")
        print(f"📊 Also deleted {deleted_items} items belonging to user")
        
        return {
            "message": f"User {user_name} deleted permanently",
            "deleted_items": deleted_items,
            "user_name": user_name
        }
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"❌ Error deleting user: {e}")
        raise HTTPException(status_code=500, detail=str(e)) 
    


@app.get("/users")
async def get_users(token_data: dict = Depends(admin_required)):
    """Get all users (Admin only)"""
    try:
        print("🔍 Admin getting users...")
        
        if not db_pool:
            raise HTTPException(status_code=500, detail="Database not connected")
        
        async with db_pool.acquire() as conn:
            users = await conn.fetch("SELECT * FROM users WHERE email IS NOT NULL")
        
        user_list = []
        for user in users:
            user_data = {
                "user_id": user.get("user_id"),
                "google_id": user.get("google_id"),
                "name": user.get("name"),
                "email": user.get("email"),
                "profile_picture": user.get("profile_picture"),
                "is_active": user.get("is_active", True),
                "created_at": user.get("created_at").isoformat() if user.get("created_at") else None,
                "last_login": user.get("last_login").isoformat() if user.get("last_login") else None
            }
            user_list.append(user_data)
            print(f"✅ Added user: {user.get('name')}")
        
        print(f"🎯 Returning {len(user_list)} users to admin")
        return user_list
        
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
        
        if not db_pool:
            raise HTTPException(status_code=500, detail="Database not connected")
        
        async with db_pool.acquire() as conn:
            await conn.execute(
                "UPDATE users SET is_active = $1 WHERE google_id = $2",
                is_active, google_id
            )
        
        print(f"✅ User status updated successfully")
        return {"message": "User status updated successfully"}
        
    except Exception as e:
        print(f"❌ Error updating user status: {e}")
        raise HTTPException(status_code=500, detail=str(e))





@app.get("/debug/users")
async def debug_users():
    """Debug endpoint to check users in database"""
    try:
        response = table.scan(
            FilterExpression="item_id = :profile",
            ExpressionAttributeValues={":profile": "PROFILE"}
        )
        
        print(f"Found {len(response.get('Items', []))} user profiles")
        for item in response.get("Items", []):
            print(f"User: {item}")
            
        return {
            "count": len(response.get("Items", [])),
            "users": response.get("Items", [])
        }
    except Exception as e:
        return {"error": str(e)}

@app.get("/debug/table")
async def debug_table():
    """Debug endpoint to check table contents"""
    try:
        response = table.scan(Limit=10)
        return {
            "count": response.get("Count", 0),
            "items": response.get("Items", [])
        }
    except Exception as e:
        return {"error": str(e)}

# Health check
@app.get("/health")
async def health_check():
    return {"status": "healthy", "timestamp": datetime.utcnow().isoformat()}



# if __name__ == "__main__":
#     import uvicorn
#     print("🚀 Starting local development server...")
#     print("📍 Your app will run at: http://localhost:8000")
#     uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True) 

# Update the port configuration for Render
if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))  # Render provides PORT env var
    print(f"🚀 Starting server on port {port}")
    uvicorn.run("main:app", host="0.0.0.0", port=port, reload=False)
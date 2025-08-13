from fastapi import FastAPI, HTTPException, Depends, UploadFile, File, Form, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
from typing import Optional, List, Dict, Any
import boto3
import json
import uuid
from datetime import datetime, timedelta
import base64
from botocore.exceptions import ClientError
import hashlib
from dotenv import load_dotenv
from mangum import Mangum
import jwt
from botocore.config import Config
import google.generativeai as genai
import os
import admin_auth
import uuid
from typing import List, Optional


# Load environment variables
load_dotenv()


# Initialize FastAPI app
app = FastAPI(title="Eco Pantry API", version="1.0.0")
# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "https://thegreenhouse-project.netlify.app"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
# AWS Configuration - FIXED
AWS_REGION = "ap-northeast-1"
DYNAMODB_TABLE = "aws-fb-db-dynamo"
S3_BUCKET = "aws-fb-db-s3"



# Correct config without use_ssl
config = Config(
    signature_version='v4',
    retries={'max_attempts': 3},
    region_name=AWS_REGION
)

# Security
security = HTTPBearer()
SECRET_KEY = "your-secret-key-here"  # Change this in production

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

# Initialize AWS clients with config
try:
    dynamodb = boto3.resource('dynamodb', region_name=AWS_REGION, config=config)
    s3_client = boto3.client('s3', region_name=AWS_REGION, config=config)
    table = dynamodb.Table(DYNAMODB_TABLE)
    print("✅ AWS clients initialized successfully")
    
    # Initialize admin manager AFTER table is created
    try:
        from admin_auth import AdminAuthManager
        admin_manager = AdminAuthManager(table)
        print("✅ Admin manager initialized successfully")
    except ImportError:
        print("⚠️ admin_auth.py not found - admin features will not work")
        admin_manager = None
    
except Exception as e:
    print(f"❌ Error initializing AWS clients: {e}")
    admin_manager = None

# Initialize Gemini AI model
try:
    GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")  # Get from .env file
    
    if GEMINI_API_KEY:
        genai.configure(api_key=GEMINI_API_KEY)
        model = genai.GenerativeModel('gemini-pro')
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

async def upload_to_s3(file: UploadFile, folder: str) -> str:
    """Upload file to S3 bucket"""
    try:
        if not file.filename:
            raise ValueError("No filename provided")
            
        print(f"📸 Starting S3 upload: {file.filename}")
        
        # Generate unique filename
        file_extension = file.filename.split('.')[-1] if '.' in file.filename else ''
        unique_filename = f"{folder}/{uuid.uuid4()}.{file_extension}"
        
        # Read file content
        file_content = await file.read()
        print(f"📄 File size: {len(file_content)} bytes")
        
        # Upload to S3
        s3_client.put_object(
            Bucket=S3_BUCKET,
            Key=unique_filename,
            Body=file_content,
            ContentType=file.content_type or 'image/jpeg'
        )
        
        # Generate public URL
        url = f"https://{S3_BUCKET}.s3.{AWS_REGION}.amazonaws.com/{unique_filename}"
        print(f"✅ S3 upload successful: {url}")
        
        return url
        
    except Exception as e:
        print(f"❌ S3 upload error: {str(e)}")
        print(f"❌ Error type: {type(e).__name__}")
        import traceback
        traceback.print_exc()
        # Return empty string instead of failing - item can still be created without image
        return ""

async def create_notification(user_id: str, title: str, message: str, notification_type: str, 
                            related_item_id: str = None, action_url: str = None):
    """Create a new notification for a user"""
    try:
        notification_id = str(uuid.uuid4())
        notification_data = {
            "user_id": f"NOTIFICATION#{user_id}",
            "item_id": f"NOTIF#{datetime.utcnow().isoformat()}#{notification_id}",
            "notification_id": notification_id,
            "target_user_id": user_id,
            "title": title,
            "message": message,
            "type": notification_type,
            "related_item_id": related_item_id,
            "action_url": action_url,
            "is_read": False,
            "created_at": datetime.utcnow().isoformat()
        }
        
        table.put_item(Item=notification_data)
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
        
        # Check if user exists (using your table structure: user_id/item_id)
        print(f"🔍 Checking for existing user with google_id: {user_data.google_id}")
        response = table.get_item(Key={"user_id": user_data.google_id, "item_id": "PROFILE"})
        
        if "Item" in response:
            print(f"✅ Found existing user")
            user = response["Item"]
            if not user.get("is_active", True):
                raise HTTPException(status_code=403, detail="Account suspended")
            
            # Update last login
            table.update_item(
                Key={"user_id": user_data.google_id, "item_id": "PROFILE"},
                UpdateExpression="SET last_login = :timestamp",
                ExpressionAttributeValues={":timestamp": datetime.utcnow().isoformat()}
            )
        else:
            print(f"❌ User not found, creating new user...")
            # Create new user (using your table structure: user_id/item_id)
            user = {
                "user_id": user_data.google_id,      # Partition key
                "item_id": "PROFILE",                # Sort key
                "google_id": user_data.google_id,
                "email": user_data.email,
                "name": user_data.name,
                "profile_picture": user_data.profile_picture,
                "is_admin": False,
                "is_active": True,
                "created_at": datetime.utcnow().isoformat(),
                "last_login": datetime.utcnow().isoformat()
            }
            
            print(f"💾 Saving new user: {user_data.name}")
            put_response = table.put_item(Item=user)
            print(f"✅ User saved successfully!")
        
        # Generate token using google_id as user_id
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
        print(f"🔐 Admin login attempt: {login_data.email}")
        
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
        response = table.get_item(
            Key={"user_id": "ADMIN", "item_id": "PROFILE"}
        )
        
        if "Item" not in response:
            raise HTTPException(status_code=404, detail="Admin profile not found")
        
        admin = response["Item"]
        return {
            "name": admin.get("name"),
            "email": admin.get("email"),
            "created_at": admin.get("created_at"),
            "last_login": admin.get("last_login")
        }
        
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
        print(f"📝 Admin updating profile: {profile_data.current_email}")
        
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
            # IMPORTANT: Return the actual error to frontend for blocked emails
            return {
                "success": False, 
                "error": result["error"]  # This will show the security block message
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
        print(f"🔑 Password reset attempt with token")
        
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
        print(f"🔄 Legacy admin login attempt: {username}")
        
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
    """Get all users (Admin only) - FIXED VERSION"""
    try:
        print("🔍 Admin getting users...")
        
        # Scan for user profiles with correct structure
        response = table.scan(
            FilterExpression="item_id = :profile AND attribute_exists(email)",
            ExpressionAttributeValues={
                ":profile": "PROFILE"
            }
        )
        
        users = []
        for item in response.get("Items", []):
            user_data = {
                "user_id": item.get("user_id"),
                "google_id": item.get("user_id"),  # Same as user_id in your structure
                "name": item.get("name"),
                "email": item.get("email"),
                "profile_picture": item.get("profile_picture"),
                "is_active": item.get("is_active", True),
                "created_at": item.get("created_at"),
                "last_login": item.get("last_login")
            }
            users.append(user_data)
            print(f"✅ Added user: {item.get('name')}")
        
        print(f"🎯 Returning {len(users)} users to admin")
        return users
        
    except Exception as e:
        print(f"❌ Error getting users: {e}")
        raise HTTPException(status_code=500, detail=str(e))


    """Get all users (Admin only) - DEBUG VERSION"""
    try:
        print("🔍 Admin getting users...")
        
        # First, let's see ALL items that might be users
        response = table.scan()
        
        print(f"📊 Total items in database: {len(response.get('Items', []))}")
        
        all_users = []
        user_like_items = []
        
        for item in response.get("Items", []):
            user_id = item.get("user_id", "")
            item_id = item.get("item_id", "")
            
            # Look for anything that might be a user
            if "USER#" in user_id or "email" in item or "google_id" in item:
                user_like_items.append({
                    "user_id": user_id,
                    "item_id": item_id,
                    "name": item.get("name"),
                    "email": item.get("email"),
                    "google_id": item.get("google_id")
                })
                print(f"🔍 Found user-like item: user_id={user_id}, item_id={item_id}, name={item.get('name')}, email={item.get('email')}")
        
        print(f"📋 Found {len(user_like_items)} user-like items")
        
        # Now try to build proper user list
        seen_emails = set()
        
        for item in user_like_items:
            email = item.get("email")
            if email and email not in seen_emails:
                seen_emails.add(email)
                
                user_data = {
                    "user_id": item.get("user_id"),
                    "google_id": item.get("google_id"),
                    "name": item.get("name"),
                    "email": email,
                    "profile_picture": item.get("profile_picture"),
                    "is_active": item.get("is_active", True),
                    "created_at": item.get("created_at"),
                    "last_login": item.get("last_login")
                }
                
                all_users.append(user_data)
                print(f"✅ Added user: {item.get('name')} ({email})")
        
        print(f"🎯 Returning {len(all_users)} users to admin")
        return all_users
        
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
        
        # Update using the actual structure (no USER# prefix)
        table.update_item(
            Key={"user_id": google_id, "item_id": "PROFILE"},
            UpdateExpression="SET is_active = :status",
            ExpressionAttributeValues={":status": is_active}
        )
        
        print(f"✅ User status updated successfully")
        return {"message": "User status updated successfully"}
        
    except Exception as e:
        print(f"❌ Error updating user status: {e}")
        raise HTTPException(status_code=500, detail=str(e))

def generate_signed_url(key: str, expiration: int = 3600):
    return s3_client.generate_presigned_url(
        'get_object',
        Params={'Bucket': S3_BUCKET, 'Key': key},
        ExpiresIn=expiration
    )
# Item Management Endpoints
@app.post("/items")
async def create_item(
    name: str = Form(...),
    quantity: int = Form(...),
    category: str = Form(...),
    location: str = Form(...),
    expiry_date: str = Form(...),  # ✅ NOW REQUIRED
    duration_days: int = Form(7),
    comments: str = Form(...),     # ✅ NOW REQUIRED
    contact_info: str = Form(...), # ✅ NOW REQUIRED
    images: List[UploadFile] = File(...),  # ✅ NOW REQUIRED
    token_data: dict = Depends(verify_token)
):
    """Create new item for donation - ALL FIELDS REQUIRED"""
    try:
        print(f"🔍 Creating item for user: {token_data.get('user_id', 'Unknown')}")
        print(f"📝 Item data: name={name}, quantity={quantity}, category={category}, location={location}")
        
        # ✅ VALIDATE REQUIRED FIELDS
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
        user_response = table.get_item(
            Key={"user_id": token_data["user_id"], "item_id": "PROFILE"}
        )
        
        if "Item" not in user_response:
            print(f"❌ User not found: {token_data['user_id']}")
            raise HTTPException(status_code=404, detail="User not found")
        
        user = user_response["Item"]
        print(f"✅ Found user: {user.get('name', 'Unknown')}")
        
        # ✅ UPLOAD IMAGES TO S3 (MANDATORY)
        image_urls = []
        print(f"📸 Uploading {len(images)} images...")
        
        for i, image in enumerate(images):
            try:
                print(f"📸 Uploading image {i+1}/{len(images)}: {image.filename}")
                url = await upload_to_s3(image, "items")  # Use "items" folder
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
        
        # Clean and prepare data
        item_data = {
            "user_id": f"ITEM#{item_id}",
            "item_id": "DETAILS",
            "item_id_unique": item_id,
            "name": name.strip(),
            "quantity": quantity,
            "category": category.strip(),
            "location": location.strip(),
            "owner_id": token_data["user_id"],
            "owner_name": user.get("name", "Unknown"),
            "owner_email": user.get("email", ""),
            "expiry_date": expiry_date,  # Use provided expiry date
            "duration_days": duration_days,
            "comments": comments.strip(),
            "contact_info": contact_info.strip(),
            "image_urls": image_urls,
            "images": image_urls,  # Compatibility field
            "status": "available",
            "created_at": datetime.utcnow().isoformat(),
            "approved": False,  # Requires admin approval
            "claimed_by": None,
            "claimant_email": None,
            "claim_expires_at": None
        }
        
        print(f"💾 Saving item: {item_data['name']}")
        table.put_item(Item=item_data)
        print(f"✅ Item saved successfully: {item_id}")
        
        return {
            "success": True,
            "message": "Item created successfully",
            "item_id": item_id,
            "item": {
                "item_id": item_id,
                "name": item_data["name"],
                "quantity": item_data["quantity"],
                "category": item_data["category"],
                "location": item_data["location"],
                "status": item_data["status"],
                "image_count": len(image_urls),
                "created_at": item_data["created_at"]
            }
        }
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"❌ Error creating item: {e}")
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Failed to create item: {str(e)}")

# ✅ ALSO UPDATE YOUR UPLOAD_TO_S3 FUNCTION FOR BETTER ERROR HANDLING
async def upload_to_s3(file: UploadFile, folder: str) -> str:
    """Upload file to S3 bucket with enhanced error handling"""
    try:
        if not file.filename:
            raise ValueError("No filename provided")
            
        print(f"📸 Starting S3 upload: {file.filename}")
        
        # Validate file
        if file.size and file.size > 5 * 1024 * 1024:  # 5MB limit
            raise ValueError(f"File too large: {file.size} bytes")
        
        # Generate unique filename with proper extension
        file_extension = file.filename.split('.')[-1].lower() if '.' in file.filename else 'jpg'
        if file_extension not in ['jpg', 'jpeg', 'png', 'gif']:
            file_extension = 'jpg'  # Default to jpg
            
        unique_filename = f"{folder}/{uuid.uuid4()}.{file_extension}"
        
        # Read file content
        file_content = await file.read()
        print(f"📄 File size: {len(file_content)} bytes")
        
        if len(file_content) == 0:
            raise ValueError("Empty file")
        
        # Upload to S3
        s3_client.put_object(
            Bucket=S3_BUCKET,
            Key=unique_filename,
            Body=file_content,
            ContentType=file.content_type or f'image/{file_extension}',
            CacheControl='max-age=31536000',  # Cache for 1 year
            # ACL='public-read'  # Make publicly readable
        )
        
        # Generate public URL
        url = f"https://{S3_BUCKET}.s3.{AWS_REGION}.amazonaws.com/{unique_filename}"
        print(f"✅ S3 upload successful: {url}")
        
        return url
        
    except Exception as e:
        print(f"❌ S3 upload error: {str(e)}")
        print(f"❌ Error type: {type(e).__name__}")
        import traceback
        traceback.print_exc()
        raise  # Re-raise the error instead of returning empty string

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
Group similar materials together and suggest combination projects when possible.
Be specific about which items from the list to use for each suggestion.

Use simple, clean formatting - no asterisks, no bold markers, just clear numbered lists."""
        
        response = model.generate_content(
            prompt,
            generation_config={
                'max_output_tokens': 2000,
                'temperature': 0.8,
            }
        )
        
        # Clean up the formatting
        ai_text = response.text
        ai_text = ai_text.replace('**', '')   # Remove double asterisks
        ai_text = ai_text.replace('***', '')  # Remove triple asterisks
        ai_text = ai_text.replace('*', '')    # Remove single asterisks
        
        return {
            "success": True,
            "recommendations": ai_text,  # Use cleaned text instead of response.text
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



# Lambda handler (for production deployment)
handler = Mangum(app)

if __name__ == "__main__":
    import uvicorn
    print("🚀 Starting local development server...")
    print("📍 Your app will run at: http://localhost:8000")
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True) 
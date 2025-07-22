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
import os
from mangum import Mangum
import jwt
from botocore.config import Config

# Initialize FastAPI app
app = FastAPI(title="Eco Pantry API", version="1.0.0")

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "https://yourdomain.com"],
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

# Initialize AWS clients with config
try:
    dynamodb = boto3.resource('dynamodb', region_name=AWS_REGION, config=config)
    s3_client = boto3.client('s3', region_name=AWS_REGION, config=config)
    table = dynamodb.Table(DYNAMODB_TABLE)
    print("✅ AWS clients initialized successfully")
except Exception as e:
    print(f"❌ Error initializing AWS clients: {e}")

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

@app.post("/auth/admin/login")
async def admin_login(username: str = Form(), password: str = Form()):
    """Admin login with username/password"""
    try:
        print(f"🔍 Admin login attempt: {username}")
        
        if username != "admin" or password != "1admin@123!":
            print("❌ Invalid admin credentials")
            raise HTTPException(status_code=401, detail="Invalid credentials")
        
        # Create admin token
        admin_id = "admin-user-001"
        token = generate_token(admin_id, is_admin=True)
        
        print("✅ Admin login successful")
        return {
            "access_token": token,  # Frontend expects this field name
            "user": {
                "user_id": admin_id,
                "name": "Administrator",
                "email": "admin@ecopantry.com",
                "is_admin": True
            }
        }
    except HTTPException:
        raise
    except Exception as e:
        print(f"❌ Admin login error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# User Management Endpoints
@app.get("/users")
async def get_users(token_data: dict = Depends(admin_required)):
    """Get all users (Admin only)"""
    try:
        print("🔍 Admin getting users...")
        
        # Look for users with item_id = "PROFILE" (no USER# prefix)
        response = table.scan(
            FilterExpression="item_id = :profile",
            ExpressionAttributeValues={":profile": "PROFILE"}
        )
        
        print(f"📊 Found {len(response.get('Items', []))} user records")
        
        users = []
        for item in response.get("Items", []):
            print(f"👤 Processing user: {item.get('name', 'Unknown')}")
            try:
                user_data = {
                    "google_id": item.get("google_id", item.get("user_id")),
                    "user_id": item.get("user_id", item.get("google_id")),
                    "email": item.get("email", ""),
                    "name": item.get("name", ""),
                    "profile_picture": item.get("profile_picture"),
                    "is_admin": item.get("is_admin", False),
                    "is_active": item.get("is_active", True),
                    "created_at": item.get("created_at", ""),
                    "last_login": item.get("last_login", "")
                }
                users.append(user_data)
                print(f"✅ Added user: {user_data['name']}")
                
            except Exception as e:
                print(f"❌ Error processing user: {e}")
                continue
        
        print(f"🎯 Returning {len(users)} users to admin")
        return users
        
    except Exception as e:
        print(f"❌ Error getting users: {e}")
        import traceback
        traceback.print_exc()
        return []

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

# Item Management Endpoints
@app.post("/items")
async def create_item(
    name: str = Form(...),
    quantity: int = Form(...),
    category: str = Form(...),
    location: str = Form(...),
    expiry_date: Optional[str] = Form(None),
    duration_days: int = Form(7),
    comments: Optional[str] = Form(None),
    contact_info: Optional[str] = Form(None),
    images: List[UploadFile] = File([]),
    token_data: dict = Depends(verify_token)
):
    """Create new item for donation"""
    try:
        print(f"🔍 Creating item for user: {token_data.get('user_id', 'Unknown')}")
        print(f"📝 Item data: name={name}, quantity={quantity}, category={category}, location={location}")
        
        # Get user info
        user_response = table.get_item(
            Key={"user_id": token_data["user_id"], "item_id": "PROFILE"}
        )
        
        if "Item" not in user_response:
            print(f"❌ User not found: {token_data['user_id']}")
            raise HTTPException(status_code=404, detail="User not found")
        
        user = user_response["Item"]
        print(f"✅ Found user: {user.get('name', 'Unknown')}")
        
        # Upload images to S3 (if any)
        image_urls = []
        if images:
            for image in images:
                if image.filename:  # Check if file was actually uploaded
                    try:
                        print(f"📸 Uploading image: {image.filename}")
                        url = await upload_to_s3(image, "items")
                        if url:  # Only add if upload was successful
                            image_urls.append(url)
                            print(f"✅ Image uploaded: {url}")
                    except Exception as e:
                        print(f"❌ Error uploading image: {e}")
        
        # Create item
        item_id = str(uuid.uuid4())
        
        # Handle expiry date
        if expiry_date:
            expiry_date_final = expiry_date
        else:
            expiry_date_final = (datetime.utcnow() + timedelta(days=duration_days)).isoformat()
        
        item_data = {
            "user_id": f"ITEM#{item_id}",
            "item_id": "DETAILS",
            "item_id_unique": item_id,  # For easier reference
            "name": name,
            "quantity": quantity,
            "category": category,
            "location": location,
            "owner_id": token_data["user_id"],
            "owner_name": user.get("name", "Unknown"),
            "owner_email": user.get("email", ""),
            "expiry_date": expiry_date_final,
            "duration_days": duration_days,
            "comments": comments or "",
            "contact_info": contact_info or "",
            "image_urls": image_urls,
            "images": image_urls,  # Add both field names for compatibility
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
            "message": "Item created successfully",
            "item_id": item_id,
            "item": item_data
        }
        
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
    """Get items pending approval (Admin only)"""
    try:
        print("🔍 Getting pending items...")
        
        response = table.scan(
            FilterExpression="begins_with(user_id, :user_id) AND item_id = :details AND approved = :approved",
            ExpressionAttributeValues={
                ":user_id": "ITEM#", 
                ":details": "DETAILS",
                ":approved": False
            }
        )
        
        items = []
        for item in response.get("Items", []):
            try:
                formatted_item = {
                    "item_id": item.get("item_id_unique", item.get("user_id", "").replace("ITEM#", "")),
                    "name": item.get("name", ""),
                    "quantity": item.get("quantity", 0),
                    "category": item.get("category", ""),
                    "location": item.get("location", ""),
                    "owner_email": item.get("owner_email", ""),
                    "owner_name": item.get("owner_name", ""),
                    "comments": item.get("comments"),
                    "image_urls": item.get("image_urls", []),
                    "images": item.get("image_urls", []),
                    "created_at": item.get("created_at", ""),
                    "status": item.get("status", "available")
                }
                items.append(formatted_item)
                
            except Exception as e:
                print(f"❌ Error processing item: {e}")
                continue
        
        print(f"📊 Returning {len(items)} pending items")
        return items
        
    except Exception as e:
        print(f"❌ Error getting pending items: {e}")
        return []

@app.put("/admin/items/{item_id}/approve")
async def approve_item(item_id: str, token_data: dict = Depends(admin_required)):
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
async def reject_item(item_id: str, reason: str, token_data: dict = Depends(admin_required)):
    """Reject item (Admin only)"""
    try:
        print(f"❌ Admin rejecting item: {item_id}, reason: {reason}")
        
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
            if item.get("item_id_unique") == item_id:
                item_found = item
                break
        
        if not item_found:
            print(f"❌ Item not found: {item_id}")
            raise HTTPException(status_code=404, detail="Item not found")
        
        print(f"📝 Found item: {item_found.get('name')} by {item_found.get('owner_name')}")
        
        # Delete the rejected item
        table.delete_item(
            Key={"user_id": item_found["user_id"], "item_id": "DETAILS"}
        )
        
        print(f"✅ Item rejected and deleted: {item_found.get('name')}")
        return {"message": "Item rejected successfully"}
        
    except Exception as e:
        print(f"❌ Error rejecting item: {e}")
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))

# Claims System
@app.post("/items/{item_id}/claim")
async def claim_item(item_id: str, token_data: dict = Depends(verify_token)):
    """Claim an available item"""
    try:
        print(f"🎯 User {token_data['user_id']} attempting to claim item: {item_id}")
        
        # Handle wrong item_id format from frontend
        if item_id == "DETAILS":
            print("❌ Invalid item_id: DETAILS")
            raise HTTPException(status_code=400, detail="Invalid item ID")
        
        # Search for item by item_id_unique
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
            print(f"❌ Item not found: {item_id}")
            raise HTTPException(status_code=404, detail="Item not found")
        
        print(f"✅ Found item: {item_found.get('name')} by {item_found.get('owner_name')}")
        
        # Check if item is claimable
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
        
        print(f"✅ Item claimed successfully by {claimant.get('name')}")
        return {"message": "Item claimed successfully"}
        
    except Exception as e:
        print(f"❌ Error claiming item: {e}")
        import traceback
        traceback.print_exc()
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
    """Send chat message (only between owner and claimant)"""
    try:
        print(f"💬 Sending message for item: {item_id}")
        
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
        
        print(f"✅ Message sent successfully")
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

# Lambda handler
handler = Mangum(app)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
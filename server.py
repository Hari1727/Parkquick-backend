from fastapi import FastAPI, APIRouter, HTTPException, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
from pydantic import BaseModel, Field
from typing import List, Optional
from datetime import datetime, timedelta
from jose import JWTError, jwt
import os
import logging
from pathlib import Path
import math

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# MongoDB connection
mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

# JWT Configuration
SECRET_KEY = os.getenv("SECRET_KEY")
if not SECRET_KEY:
    raise ValueError("SECRET_KEY environment variable is required")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30 * 24 * 60  # 30 days

# Create the main app
app = FastAPI()
api_router = APIRouter(prefix="/api")
security = HTTPBearer()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# ==================== MODELS ====================

class UserRole(str):
    USER = "user"
    LENDER = "lender"

class User(BaseModel):
    phone: str
    name: str
    role: str  # "user" or "lender"
    created_at: datetime = Field(default_factory=datetime.utcnow)
    location: Optional[dict] = None  # {lat, lng, address}

class UserCreate(BaseModel):
    phone: str
    name: str
    role: str

class LoginRequest(BaseModel):
    phone: str

class OTPVerifyRequest(BaseModel):
    phone: str
    otp: str

class TokenResponse(BaseModel):
    access_token: str
    token_type: str
    user: dict

class ParkingSpace(BaseModel):
    owner_id: str
    owner_name: str
    title: str
    description: str
    address: str
    location: dict  # {lat, lng}
    price_per_hour: float
    photos: List[str] = []  # base64 encoded images
    amenities: List[str] = []
    availability_status: bool = True
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)

class ParkingSpaceCreate(BaseModel):
    title: str
    description: str
    address: str
    location: dict
    price_per_hour: float
    photos: List[str] = []
    amenities: List[str] = []

class ParkingSpaceUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    address: Optional[str] = None
    location: Optional[dict] = None
    price_per_hour: Optional[float] = None
    photos: Optional[List[str]] = None
    amenities: Optional[List[str]] = None
    availability_status: Optional[bool] = None

class Booking(BaseModel):
    user_id: str
    user_name: str
    parking_space_id: str
    parking_title: str
    parking_address: str
    start_time: datetime
    end_time: datetime
    total_hours: float
    total_price: float
    status: str = "pending"  # pending, confirmed, completed, cancelled
    created_at: datetime = Field(default_factory=datetime.utcnow)

class BookingCreate(BaseModel):
    parking_space_id: str
    start_time: datetime
    end_time: datetime

# ==================== HELPER FUNCTIONS ====================

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        token = credentials.credentials
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        phone: str = payload.get("sub")
        if phone is None:
            raise HTTPException(status_code=401, detail="Invalid authentication credentials")
        
        user = await db.users.find_one({"phone": phone})
        if user is None:
            raise HTTPException(status_code=401, detail="User not found")
        
        user["_id"] = str(user["_id"])
        return user
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid authentication credentials")

def calculate_distance(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Calculate distance between two coordinates using Haversine formula (in km)"""
    R = 6371  # Earth's radius in kilometers
    
    lat1_rad = math.radians(lat1)
    lat2_rad = math.radians(lat2)
    delta_lat = math.radians(lat2 - lat1)
    delta_lon = math.radians(lon2 - lon1)
    
    a = math.sin(delta_lat/2)**2 + math.cos(lat1_rad) * math.cos(lat2_rad) * math.sin(delta_lon/2)**2
    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1-a))
    
    distance = R * c
    return round(distance, 2)

# ==================== AUTHENTICATION ENDPOINTS ====================

@api_router.post("/auth/send-otp")
async def send_otp(request: LoginRequest):
    """Mock OTP send - in prototype, any phone number works"""
    try:
        # In real app, this would call Twilio
        # For prototype, we just log and return success
        logger.info(f"Mock OTP sent to {request.phone}: 123456")
        return {
            "success": True,
            "message": "OTP sent successfully (use 123456 for testing)",
            "phone": request.phone
        }
    except Exception as e:
        logger.error(f"Error sending OTP: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to send OTP")

@api_router.post("/auth/verify-otp", response_model=TokenResponse)
async def verify_otp(request: OTPVerifyRequest):
    """Mock OTP verification - accepts 123456 or any 6-digit code"""
    try:
        # In prototype, accept any 6-digit OTP
        if len(request.otp) != 6 or not request.otp.isdigit():
            raise HTTPException(status_code=400, detail="Invalid OTP format")
        
        # Check if user exists
        user = await db.users.find_one({"phone": request.phone})
        
        if user:
            user["_id"] = str(user["_id"])
            access_token = create_access_token(data={"sub": user["phone"]})
            return {
                "access_token": access_token,
                "token_type": "bearer",
                "user": user
            }
        else:
            # New user - return token but indicate registration needed
            return {
                "access_token": "",
                "token_type": "bearer",
                "user": {"phone": request.phone, "new_user": True}
            }
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error verifying OTP: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to verify OTP")

@api_router.post("/auth/register", response_model=TokenResponse)
async def register_user(user_data: UserCreate):
    """Register new user after OTP verification"""
    try:
        # Check if user already exists
        existing_user = await db.users.find_one({"phone": user_data.phone})
        if existing_user:
            raise HTTPException(status_code=400, detail="User already exists")
        
        # Create new user
        user_dict = user_data.dict()
        user_dict["created_at"] = datetime.utcnow()
        
        result = await db.users.insert_one(user_dict)
        user_dict["_id"] = str(result.inserted_id)
        
        # Create access token
        access_token = create_access_token(data={"sub": user_data.phone})
        
        return {
            "access_token": access_token,
            "token_type": "bearer",
            "user": user_dict
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error registering user: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to register user")

@api_router.get("/auth/me")
async def get_me(current_user: dict = Depends(get_current_user)):
    """Get current user profile"""
    return current_user

@api_router.put("/auth/profile")
async def update_profile(
    location: Optional[dict] = None,
    current_user: dict = Depends(get_current_user)
):
    """Update user profile"""
    try:
        update_data = {}
        if location:
            update_data["location"] = location
        
        if update_data:
            await db.users.update_one(
                {"phone": current_user["phone"]},
                {"$set": update_data}
            )
        
        updated_user = await db.users.find_one({"phone": current_user["phone"]})
        updated_user["_id"] = str(updated_user["_id"])
        return updated_user
    except Exception as e:
        logger.error(f"Error updating profile: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to update profile")

# ==================== PARKING SPACE ENDPOINTS ====================

@api_router.post("/parking-spaces")
async def create_parking_space(
    space_data: ParkingSpaceCreate,
    current_user: dict = Depends(get_current_user)
):
    """Create new parking space (lenders only)"""
    try:
        if current_user.get("role") != "lender":
            raise HTTPException(status_code=403, detail="Only lenders can create parking spaces")
        
        space_dict = space_data.dict()
        space_dict["owner_id"] = current_user["phone"]
        space_dict["owner_name"] = current_user["name"]
        space_dict["created_at"] = datetime.utcnow()
        space_dict["updated_at"] = datetime.utcnow()
        space_dict["availability_status"] = True
        
        result = await db.parking_spaces.insert_one(space_dict)
        space_dict["_id"] = str(result.inserted_id)
        
        return space_dict
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error creating parking space: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to create parking space")

@api_router.get("/parking-spaces/nearby")
async def get_nearby_parking_spaces(
    lat: float,
    lng: float,
    max_distance: float = 10,  # km
    current_user: dict = Depends(get_current_user)
):
    """Get parking spaces near user's location"""
    try:
        # Optimized query with projection and limit
        projection = {
            "_id": 1,
            "owner_id": 1,
            "owner_name": 1,
            "title": 1,
            "description": 1,
            "address": 1,
            "location": 1,
            "price_per_hour": 1,
            "photos": 1,
            "amenities": 1,
            "availability_status": 1
        }
        
        all_spaces = await db.parking_spaces.find(
            {"availability_status": True},
            projection
        ).limit(100).to_list(100)
        
        # Calculate distance for each space
        spaces_with_distance = []
        for space in all_spaces:
            space["_id"] = str(space["_id"])
            space_lat = space["location"]["lat"]
            space_lng = space["location"]["lng"]
            
            distance = calculate_distance(lat, lng, space_lat, space_lng)
            
            if distance <= max_distance:
                space["distance"] = distance
                spaces_with_distance.append(space)
        
        # Sort by distance
        spaces_with_distance.sort(key=lambda x: x["distance"])
        
        return spaces_with_distance
    except Exception as e:
        logger.error(f"Error fetching nearby parking spaces: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to fetch parking spaces")

@api_router.get("/parking-spaces/my-spaces")
async def get_my_parking_spaces(current_user: dict = Depends(get_current_user)):
    """Get parking spaces owned by current user (lenders only)"""
    try:
        if current_user.get("role") != "lender":
            raise HTTPException(status_code=403, detail="Only lenders can view their spaces")
        
        spaces = await db.parking_spaces.find({"owner_id": current_user["phone"]}).to_list(1000)
        
        for space in spaces:
            space["_id"] = str(space["_id"])
        
        return spaces
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error fetching my parking spaces: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to fetch parking spaces")

@api_router.get("/parking-spaces/{space_id}")
async def get_parking_space(space_id: str, current_user: dict = Depends(get_current_user)):
    """Get parking space by ID"""
    try:
        from bson import ObjectId
        space = await db.parking_spaces.find_one({"_id": ObjectId(space_id)})
        
        if not space:
            raise HTTPException(status_code=404, detail="Parking space not found")
        
        space["_id"] = str(space["_id"])
        return space
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error fetching parking space: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to fetch parking space")

@api_router.put("/parking-spaces/{space_id}")
async def update_parking_space(
    space_id: str,
    space_update: ParkingSpaceUpdate,
    current_user: dict = Depends(get_current_user)
):
    """Update parking space (owner only)"""
    try:
        from bson import ObjectId
        
        # Check if space exists and user is owner
        space = await db.parking_spaces.find_one({"_id": ObjectId(space_id)})
        if not space:
            raise HTTPException(status_code=404, detail="Parking space not found")
        
        if space["owner_id"] != current_user["phone"]:
            raise HTTPException(status_code=403, detail="Not authorized to update this space")
        
        # Update only provided fields
        update_data = {k: v for k, v in space_update.dict().items() if v is not None}
        update_data["updated_at"] = datetime.utcnow()
        
        await db.parking_spaces.update_one(
            {"_id": ObjectId(space_id)},
            {"$set": update_data}
        )
        
        updated_space = await db.parking_spaces.find_one({"_id": ObjectId(space_id)})
        updated_space["_id"] = str(updated_space["_id"])
        
        return updated_space
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating parking space: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to update parking space")

@api_router.delete("/parking-spaces/{space_id}")
async def delete_parking_space(
    space_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Delete parking space (owner only)"""
    try:
        from bson import ObjectId
        
        # Check if space exists and user is owner
        space = await db.parking_spaces.find_one({"_id": ObjectId(space_id)})
        if not space:
            raise HTTPException(status_code=404, detail="Parking space not found")
        
        if space["owner_id"] != current_user["phone"]:
            raise HTTPException(status_code=403, detail="Not authorized to delete this space")
        
        await db.parking_spaces.delete_one({"_id": ObjectId(space_id)})
        
        return {"message": "Parking space deleted successfully"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting parking space: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to delete parking space")

# ==================== BOOKING ENDPOINTS ====================

@api_router.post("/bookings")
async def create_booking(
    booking_data: BookingCreate,
    current_user: dict = Depends(get_current_user)
):
    """Create new booking"""
    try:
        from bson import ObjectId
        
        # Get parking space details
        space = await db.parking_spaces.find_one({"_id": ObjectId(booking_data.parking_space_id)})
        if not space:
            raise HTTPException(status_code=404, detail="Parking space not found")
        
        if not space.get("availability_status"):
            raise HTTPException(status_code=400, detail="Parking space is not available")
        
        # Calculate total hours and price
        duration = booking_data.end_time - booking_data.start_time
        total_hours = duration.total_seconds() / 3600
        total_price = total_hours * space["price_per_hour"]
        
        # Create booking
        booking_dict = {
            "user_id": current_user["phone"],
            "user_name": current_user["name"],
            "parking_space_id": booking_data.parking_space_id,
            "parking_title": space["title"],
            "parking_address": space["address"],
            "start_time": booking_data.start_time,
            "end_time": booking_data.end_time,
            "total_hours": round(total_hours, 2),
            "total_price": round(total_price, 2),
            "status": "confirmed",
            "created_at": datetime.utcnow()
        }
        
        result = await db.bookings.insert_one(booking_dict)
        booking_dict["_id"] = str(result.inserted_id)
        
        return booking_dict
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error creating booking: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to create booking")

@api_router.get("/bookings/my-bookings")
async def get_my_bookings(current_user: dict = Depends(get_current_user)):
    """Get bookings made by current user"""
    try:
        bookings = await db.bookings.find({"user_id": current_user["phone"]}).to_list(1000)
        
        for booking in bookings:
            booking["_id"] = str(booking["_id"])
        
        # Sort by created_at descending
        bookings.sort(key=lambda x: x["created_at"], reverse=True)
        
        return bookings
    except Exception as e:
        logger.error(f"Error fetching bookings: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to fetch bookings")

@api_router.get("/bookings/space/{space_id}")
async def get_space_bookings(
    space_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Get bookings for a specific parking space (owner only)"""
    try:
        from bson import ObjectId
        
        # Verify ownership
        space = await db.parking_spaces.find_one({"_id": ObjectId(space_id)})
        if not space:
            raise HTTPException(status_code=404, detail="Parking space not found")
        
        if space["owner_id"] != current_user["phone"]:
            raise HTTPException(status_code=403, detail="Not authorized to view these bookings")
        
        bookings = await db.bookings.find({"parking_space_id": space_id}).to_list(1000)
        
        for booking in bookings:
            booking["_id"] = str(booking["_id"])
        
        bookings.sort(key=lambda x: x["created_at"], reverse=True)
        
        return bookings
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error fetching space bookings: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to fetch bookings")

@api_router.put("/bookings/{booking_id}/cancel")
async def cancel_booking(
    booking_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Cancel a booking"""
    try:
        from bson import ObjectId
        
        booking = await db.bookings.find_one({"_id": ObjectId(booking_id)})
        if not booking:
            raise HTTPException(status_code=404, detail="Booking not found")
        
        if booking["user_id"] != current_user["phone"]:
            raise HTTPException(status_code=403, detail="Not authorized to cancel this booking")
        
        await db.bookings.update_one(
            {"_id": ObjectId(booking_id)},
            {"$set": {"status": "cancelled"}}
        )
        
        updated_booking = await db.bookings.find_one({"_id": ObjectId(booking_id)})
        updated_booking["_id"] = str(updated_booking["_id"])
        
        return updated_booking
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error cancelling booking: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to cancel booking")

# ==================== STATS ENDPOINTS ====================

@api_router.get("/stats/dashboard")
async def get_dashboard_stats(current_user: dict = Depends(get_current_user)):
    """Get dashboard statistics for lenders"""
    try:
        if current_user.get("role") != "lender":
            return {"message": "Stats only available for lenders"}
        
        # Get all parking spaces owned by user
        spaces = await db.parking_spaces.find({"owner_id": current_user["phone"]}).to_list(1000)
        space_ids = [str(space["_id"]) for space in spaces]
        
        # Get all bookings for these spaces
        bookings = await db.bookings.find({"parking_space_id": {"$in": space_ids}}).to_list(1000)
        
        total_earnings = sum(booking["total_price"] for booking in bookings if booking["status"] == "confirmed")
        total_bookings = len(bookings)
        active_bookings = len([b for b in bookings if b["status"] == "confirmed"])
        
        return {
            "total_spaces": len(spaces),
            "total_bookings": total_bookings,
            "active_bookings": active_bookings,
            "total_earnings": round(total_earnings, 2)
        }
    except Exception as e:
        logger.error(f"Error fetching dashboard stats: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to fetch statistics")

# Include the router in the main app
app.include_router(api_router)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()

import os
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from typing import List, Optional
from pydantic import BaseModel, Field, EmailStr
from datetime import datetime, timedelta
from jose import JWTError, jwt

# --- CONFIGURATION ---

JWT_SECRET_KEY = os.environ.get("JWT_SECRET_KEY", "supersecretkey")  # Should be in .env
JWT_ALGORITHM = "HS256"
JWT_EXPIRE_MINUTES = 60 * 24  # 1 day

# --- APP INITIALIZATION ---

app = FastAPI(
    title="SkillSync API",
    description="API for SkillSync - Collaborative Learning Platform",
    version="1.0.0",
    openapi_tags=[
        {"name": "auth", "description": "User registration and authentication"},
        {"name": "profiles", "description": "Learner and mentor profiles"},
        {"name": "sessions", "description": "Learning session management"},
        {"name": "progress", "description": "Progress tracking"},
        {"name": "feedback", "description": "Feedback system"},
        {"name": "recommendation", "description": "Smart recommendations"},
    ],
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/token")

# --- MOCK IN-MEMORY DATABASE (replace with real DB integration) ---

users_db = {}
sessions_db = {}
feedback_db = {}
progress_db = {}

# --- Pydantic MODELS ---

# User and Auth Models
class UserBase(BaseModel):
    email: EmailStr = Field(..., description="User email address")
    full_name: str = Field(..., description="User full name")
    role: str = Field(..., description="Role of user - learner or mentor")

class UserCreate(UserBase):
    password: str = Field(..., description="User password")

class UserProfile(UserBase):
    bio: Optional[str] = Field("", description="Bio for user")
    skills: List[str] = Field(default_factory=list, description="Skills list")

class UserLogin(BaseModel):
    email: EmailStr = Field(..., description="User email")
    password: str = Field(..., description="User password")

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    email: Optional[str] = None
    role: Optional[str] = None

# Session Models
class SessionCreate(BaseModel):
    topic: str = Field(..., description="Session topic")
    description: str = Field("", description="Description of the session")
    mentor_email: EmailStr = Field(..., description="Mentor's email")
    scheduled_time: datetime = Field(..., description="Scheduled datetime")

class SessionInfo(BaseModel):
    session_id: str
    topic: str
    mentor_email: str
    learners: List[str]
    scheduled_time: datetime

# Progress Models
class ProgressRecord(BaseModel):
    user_email: str
    session_id: str
    progress: float = Field(..., description="Progress as percentage 0-100")
    last_updated: datetime = Field(default_factory=datetime.utcnow)

# Feedback Models
class FeedbackSubmit(BaseModel):
    session_id: str
    from_email: str
    to_email: str
    rating: int = Field(..., description="Rating (1-5)")
    comment: Optional[str] = Field("", description="Feedback comment")

class FeedbackEntry(BaseModel):
    session_id: str
    from_email: str
    to_email: str
    rating: int
    comment: str
    timestamp: datetime

# Recommendation Models
class Recommendation(BaseModel):
    type: str = Field(..., description="Type: mentor/topic")
    recommended: List[str] = Field(..., description="List of recommendations")

# --- UTILS (Auth) ---

def fake_hash_password(password: str) -> str:
    return "fakehashed" + password

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    """Creates JWT token with expiration."""
    data = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=JWT_EXPIRE_MINUTES))
    data.update({"exp": expire})
    encoded_jwt = jwt.encode(data, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
    return encoded_jwt

# PUBLIC_INTERFACE
async def get_current_user(token: str = Depends(oauth2_scheme)) -> UserProfile:
    """Get the current user from token or raise 401."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
        user = users_db.get(email)
        if user is None:
            raise credentials_exception
        return UserProfile(**user)
    except JWTError:
        raise credentials_exception

# --- ROUTES ---

@app.get("/", tags=["health"])
def health_check():
    """Health check endpoint."""
    return {"message": "Healthy"}

# -------- AUTHENTICATION --------

# PUBLIC_INTERFACE
@app.post("/auth/register", response_model=UserProfile, tags=["auth"], summary="Register a new user")
def register_user(user: UserCreate):
    """Register a new user account."""
    if user.email in users_db:
        raise HTTPException(status_code=400, detail="Email already registered")
    user_dict = user.dict()
    user_dict["password"] = fake_hash_password(user.password)
    users_db[user.email] = user_dict
    return UserProfile(**user_dict)

# PUBLIC_INTERFACE
@app.post("/auth/token", response_model=Token, tags=["auth"], summary="Obtain JWT token using email and password")
def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    """Authenticate user and return JWT token."""
    # You can replace with proper DB lookup & password hash check!
    user = users_db.get(form_data.username)
    if not user or user["password"] != fake_hash_password(form_data.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    token_data = {"sub": user["email"], "role": user["role"]}
    access_token = create_access_token(data=token_data)
    return {"access_token": access_token, "token_type": "bearer"}

# PUBLIC_INTERFACE
@app.get("/profiles/me", response_model=UserProfile, tags=["profiles"], summary="Get current user profile")
def get_my_profile(current_user: UserProfile = Depends(get_current_user)):
    """Returns the profile of the currently authenticated user."""
    return current_user

# PUBLIC_INTERFACE
@app.put("/profiles/me", response_model=UserProfile, tags=["profiles"], summary="Update current user profile")
def update_my_profile(profile_update: UserProfile, current_user: UserProfile = Depends(get_current_user)):
    """Update the authenticated user's profile."""
    users_db[current_user.email].update(profile_update.dict())
    return UserProfile(**users_db[current_user.email])

# PUBLIC_INTERFACE
@app.get("/profiles/{email}", response_model=UserProfile, tags=["profiles"], summary="Get profile by email")
def get_profile(email: str):
    """Get the user profile by email."""
    user = users_db.get(email)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return UserProfile(**user)

# -------- SESSIONS --------

# PUBLIC_INTERFACE
@app.post("/sessions/create", response_model=SessionInfo, tags=["sessions"], summary="Create a new learning session")
def create_session(session: SessionCreate, current_user: UserProfile = Depends(get_current_user)):
    """Create a new learning session (mentor only)."""
    if current_user.role != "mentor":
        raise HTTPException(status_code=403, detail="Only mentors can create sessions")
    session_id = f"session_{len(sessions_db) + 1}"
    session_info = {
        "session_id": session_id,
        "topic": session.topic,
        "mentor_email": session.mentor_email,
        "learners": [],
        "scheduled_time": session.scheduled_time,
    }
    sessions_db[session_id] = session_info
    return SessionInfo(**session_info)

# PUBLIC_INTERFACE
@app.post("/sessions/join/{session_id}", tags=["sessions"], summary="Join a learning session as learner")
def join_session(session_id: str, current_user: UserProfile = Depends(get_current_user)):
    """Join a learning session as a learner."""
    session = sessions_db.get(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    if current_user.email in session["learners"]:
        raise HTTPException(status_code=409, detail="Already joined")
    session["learners"].append(current_user.email)
    return {"joined": True, "session_id": session_id}

# PUBLIC_INTERFACE
@app.get("/sessions/my", response_model=List[SessionInfo], tags=["sessions"], summary="Get sessions for current user")
def my_sessions(current_user: UserProfile = Depends(get_current_user)):
    """Get all sessions for the current user (as mentor or learner)."""
    result = []
    for s in sessions_db.values():
        if (
            current_user.role == "mentor" and s["mentor_email"] == current_user.email
        ) or (current_user.email in s["learners"]):
            result.append(SessionInfo(**s))
    return result

# -------- PROGRESS TRACKING --------

# PUBLIC_INTERFACE
@app.post("/progress/update", tags=["progress"], summary="Update learner's progress in a session")
def update_progress(record: ProgressRecord, current_user: UserProfile = Depends(get_current_user)):
    """Update or insert a learner's progress for a session."""
    key = (record.user_email, record.session_id)
    progress_db[key] = record.dict()
    return {"status": "updated"}

# PUBLIC_INTERFACE
@app.get("/progress/{session_id}/{user_email}", response_model=ProgressRecord, tags=["progress"], summary="Get progress for a user in a session")
def get_progress(session_id: str, user_email: str, current_user: UserProfile = Depends(get_current_user)):
    """Get progress record for a user in a session."""
    record = progress_db.get((user_email, session_id))
    if not record:
        raise HTTPException(status_code=404, detail="Progress not found")
    return ProgressRecord(**record)

# -------- FEEDBACK --------

# PUBLIC_INTERFACE
@app.post("/feedback/submit", tags=["feedback"], summary="Submit feedback for a user in a session")
def submit_feedback(feedback: FeedbackSubmit, current_user: UserProfile = Depends(get_current_user)):
    """Submit feedback after a session."""
    entry = {
        "session_id": feedback.session_id,
        "from_email": feedback.from_email,
        "to_email": feedback.to_email,
        "rating": feedback.rating,
        "comment": feedback.comment,
        "timestamp": datetime.utcnow(),
    }
    feedback_db.setdefault(feedback.session_id, []).append(entry)
    return {"status": "feedback_submitted"}

# PUBLIC_INTERFACE
@app.get("/feedback/{session_id}", response_model=List[FeedbackEntry], tags=["feedback"], summary="Get feedback for a session")
def get_feedback(session_id: str, current_user: UserProfile = Depends(get_current_user)):
    """Get all feedback submitted for a particular session."""
    entries = feedback_db.get(session_id, [])
    return [FeedbackEntry(**entry) for entry in entries]

# -------- RECOMMENDATIONS --------

# PUBLIC_INTERFACE
@app.get("/recommendation", response_model=Recommendation, tags=["recommendation"], summary="Get smart recommendations")
def smart_recommendations(current_user: UserProfile = Depends(get_current_user)):
    """Basic recommendation system stub: suggest available mentors or topics."""
    if current_user.role == "learner":
        # Recommend mentors (just a stub)
        mentors = [u["email"] for u in users_db.values() if u["role"] == "mentor"]
        return Recommendation(type="mentor", recommended=mentors)
    else:
        # Recommend topics (stub)
        topics = list({s["topic"] for s in sessions_db.values()})
        return Recommendation(type="topic", recommended=topics)

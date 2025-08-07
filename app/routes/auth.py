from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from app.services.auth import auth
from app.repositories import db
from app.schemas import LoginRequest

router = APIRouter()

class LoginRequest(BaseModel):
    email: str
    password: str

@router.post("/login")
def login(request: LoginRequest, database: Session = Depends(db.get_db)):
    user = auth.authenticate_user(database, request.email, request.password)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Identifiants invalides")
    
    token = auth.create_access_token({"sub": user.email})
    return {"access_token": token, "token_type": "bearer"}

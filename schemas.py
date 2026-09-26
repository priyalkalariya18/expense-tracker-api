from datetime import date, datetime
from decimal import Decimal
from pydantic import BaseModel, EmailStr, Field, ConfigDict

# ---------- Users ----------
class UserCreate(BaseModel):
    name: str = Field(min_length=2, max_length=100)
    email: EmailStr
    password: str = Field(min_length=6, max_length=72)

class UserOut(BaseModel):
    id: int
    name: str
    email: EmailStr
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)

class Token(BaseModel):
    access_token: str
    token_type: str

# ---------- Expenses ----------
class ExpenseCreate(BaseModel):
    amount: Decimal = Field(gt=0, max_digits=10, decimal_places=2)
    category: str = Field(min_length=1, max_length=50)
    description: str | None = Field(default=None, max_length=255)
    expense_date: date

class ExpenseUpdate(BaseModel):
    amount: Decimal | None = Field(default=None, gt=0, max_digits=10, decimal_places=2)
    category: str | None = Field(default=None, min_length=1, max_length=50)
    description: str | None = Field(default=None, max_length=255)
    expense_date: date | None = None

class ExpenseOut(BaseModel):
    id: int
    amount: Decimal
    category: str
    description: str | None
    expense_date: date
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)

class CategoryTotal(BaseModel):
    category: str
    total: Decimal
    count: int

class MonthlyReport(BaseModel):
    year: int
    month: int
    total_spent: Decimal
    categories: list[CategoryTotal]

class GoogleLogin(BaseModel):
    credential: str    
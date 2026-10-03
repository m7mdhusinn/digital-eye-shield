from sqlalchemy import Column, Integer, String, Float, DateTime
from datetime import datetime
from database import Base

class ScanLog(Base):
    __tablename__ = "scan_logs"
    __table_args__ = {'extend_existing': True}  # حل مشكلة إعادة تعريف الجدول

    id = Column(Integer, primary_key=True, index=True)
    target_type = Column(String, index=True) # "url", "document", أو "contact"
    target_value = Column(String, index=True)
    risk_score = Column(Float)
    status = Column(String) # "Safe", "Suspicious", "Dangerous"
    created_at = Column(DateTime, default=datetime.utcnow)
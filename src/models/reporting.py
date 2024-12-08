from sqlalchemy import Column, Integer, String
from .base import Base

class Report(Base):
    __tablename__ = 'report'
    id = Column(Integer, primary_key=True)
    target = Column(String)
    html_report = Column(String)
    json_report = Column(String)

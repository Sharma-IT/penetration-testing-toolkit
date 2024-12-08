from sqlalchemy import Column, Integer, String, Text
from .base import Base

class InformationGathering(Base):
    __tablename__ = 'information_gathering'
    id = Column(Integer, primary_key=True)
    target = Column(String)
    target_ip = Column(String)
    http_header = Column(Text)
    html_source = Column(Text)

class VulnerabilityScan(Base):
    __tablename__ = 'vulnerability_scan'
    id = Column(Integer, primary_key=True)
    target = Column(String)
    vulnerability = Column(String)
    result = Column(Text)

class ManualTesting(Base):
    __tablename__ = 'manual_testing'
    id = Column(Integer, primary_key=True)
    target = Column(String)
    test_name = Column(String)
    result = Column(Text)

class Exploitation(Base):
    __tablename__ = 'exploitation'
    id = Column(Integer, primary_key=True)
    target = Column(String)
    exploit_name = Column(String)
    result = Column(Text)

class PostExploitation(Base):
    __tablename__ = 'post_exploitation'
    id = Column(Integer, primary_key=True)
    target = Column(String)
    action_name = Column(String)
    result = Column(Text)

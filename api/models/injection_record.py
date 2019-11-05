from initiate_database import *
import binascii
import bcrypt
import os

class Injection(Base):
    __tablename__ = 'injections'

    id = Column(String(100), primary_key=True)
    type = Column(String(100)) # JavaScript/Image
    injection_timestamp = Column(Integer())
    vulnerable_page = Column(String(3000))
    vulnerable_domain = Column(String(300))
    document_body = Column(Boolean(), default=False, nullable=False)
    victim_ip = Column(String(100))
    referer = Column(String(3000))
    user_agent = Column(String(3000))
    cookies = Column(String(5000))
    dom = Column(Text())
    origin = Column(String(300))
    screenshot = Column(String(300))
    owner_id = Column(String(100))
    browser_time = Column(BigInteger())
    correlated_request = Column(Text())

    def generate_injection_id( self ):
        self.id = binascii.hexlify(os.urandom(50))

    def get_injection_blob( self ):
        exposed_attributes = [ "id", "document_body", "vulnerable_domain", "vulnerable_page", "victim_ip", "referer", "user_agent", "cookies", "dom", "origin", "screenshot", "injection_timestamp", "correlated_request", "browser_time" ]
        return_dict = {}

        for attribute in exposed_attributes:
            return_dict[ attribute ] = getattr( self, attribute )

        return return_dict

    def __str__( self ):
        return self.vulnerable_page

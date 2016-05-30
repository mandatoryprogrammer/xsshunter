from initiate_database import *
import binascii
import bcrypt
import time
import os

class InjectionRequest(Base):
    __tablename__ = 'injection_requests'

    id = Column(String(100), primary_key=True)
    request = Column(Text())
    injection_key = Column(String(100))
    owner_correlation_key = Column(String(100))
    timestamp = Column(Integer())

    def __init__( self ):
        self.generate_injection_id()
        self.timestamp = int( time.time() )

    def generate_injection_id( self ):
        self.id = binascii.hexlify(os.urandom(50))

    def get_injection_blob( self ):
        exposed_attributes = [ "request", "injection_key" ]
        return_dict = {}

        for attribute in exposed_attributes:
            return_dict[ attribute ] = getattr( self, attribute )

        return return_dict

    def __str__( self ):
        return self.id

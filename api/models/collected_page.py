from initiate_database import *
import binascii
import bcrypt
import os

class CollectedPage(Base):
    __tablename__ = 'collected_pages'

    id = Column(String(100), primary_key=True)
    uri = Column(Text())
    page_html = Column(Text())
    owner_id = Column(String(100))
    timestamp = Column(Integer())

    def __init__( self ):
        self.generate_injection_id()

    def generate_injection_id( self ):
        self.id = binascii.hexlify(os.urandom(50))

    def to_dict( self ):
        exposed_attributes = [ "uri", "id", "page_html", "timestamp" ]
        return_dict = {}

        for attribute in exposed_attributes:
            return_dict[ attribute ] = getattr( self, attribute )

        return return_dict

    def __str__( self ):
        return self.id

from initiate_database import *
from urlparse import urlparse
import binascii
import bcrypt
import os
import re

class User(Base):
    __tablename__ = 'users'

    id = Column(String(100), primary_key=True)
    full_name = Column(String(120))
    username = Column(String(80))
    password = Column(String(120))
    email = Column(String(120))
    domain = Column(String(120))
    pgp_key = Column(Text())
    password_reset_token = Column(String(120))
    is_premium = Column(Boolean())
    email_enabled = Column(Boolean())
    chainload_uri = Column(Text())
    owner_correlation_key = Column(String(100))
    page_collection_paths_list = Column(Text()) # Done this way to allow users to just paste and share relative page lists

    def __init__( self ):
        self.generate_user_id()
        self.generate_owner_correlation_key()

    def set_fullname( self, in_fullname ):
        self.full_name = str( in_fullname ).strip()
        return True

    def set_username( self, in_username ):
        self.username = str( in_username ).strip()
        return True

    def set_password( self, in_password ):
        self.password = self._get_bcrypt_hash( in_password )
        return True

    def set_pgp_key( self, in_pgp_key ):
        self.pgp_key = str( in_pgp_key ).strip()
        return True

    def set_email( self, in_email ):
        in_email = str( in_email ).strip()
        if bool( re.search( r"^[A-Za-z0-9\.\+_-]+@[A-Za-z0-9\._-]+\.[a-zA-Z]*$", in_email, flags=0 ) ):
            self.email = in_email
            return True
        return False

    def set_domain( self, set_domain ):
        if self.domain == set_domain:
            return True

        if not bool( re.search( r"^[A-Za-z0-9]+$", set_domain, flags=0 ) ):
            return False

        set_domain = str( set_domain ).strip()
        domain_exists = session.query( User ).filter_by( domain=set_domain ).first()

        if domain_exists == None:
            self.domain = set_domain
            return True
        return False

    def set_email_enabled( self, in_email_enabled ):
        self.email_enabled = in_email_enabled
        return True

    def set_chainload_uri( self, in_chainload_uri ):
        parsed_url = urlparse( in_chainload_uri )
        if bool( parsed_url.scheme ) or in_chainload_uri == "":
            self.chainload_uri = in_chainload_uri
            return True
        return False

    def set_page_collection_paths_list( self, in_paths_list_text ):
        self.page_collection_paths_list = in_paths_list_text.strip()
        return True

    def set_attribute( self, attribute, value ):
        if attribute == "password":
            return self.set_password( value )
        if attribute == "full_name":
            return self.set_fullname( value )
        if attribute == "username":
            return self.set_username( value )
        if attribute == "email":
            return self.set_email( value )
        if attribute == "domain":
            return self.set_domain( value )
        if attribute == "pgp_key":
            return self.set_pgp_key( value )
        if attribute == "email_enabled":
            return self.set_email_enabled( value )
        if attribute == "chainload_uri":
            return self.set_chainload_uri( value )
        if attribute == "page_collection_paths_list":
            return self.set_page_collection_paths_list( value )

    def get_page_collection_path_list( self ):
        if self.page_collection_paths_list == None:
            return []

        tmp_pages_list = self.page_collection_paths_list.split( "\n" )
        page_list = []

        for page in tmp_pages_list:
            page = page.strip()
            if page != "":
                page_list.append( page )

        return page_list

    def get_user_blob( self ):
        exposed_attributes = [ "full_name", "email", "username", "pgp_key", "domain", "email_enabled", "chainload_uri", "owner_correlation_key", "page_collection_paths_list" ]
        return_dict = {}

        for attribute in exposed_attributes:
            return_dict[ attribute ] = getattr( self, attribute )

        return return_dict

    def generate_user_id( self ):
        self.id = binascii.hexlify(os.urandom(50))

    def generate_password_reset_key( self ):
        self.password_reset_token = binascii.hexlify(os.urandom(60))

    def generate_owner_correlation_key( self ):
        self.owner_correlation_key = binascii.hexlify(os.urandom(50))

    def compare_password( self, in_password ):
        return ( bcrypt.hashpw( str( in_password.encode( 'utf-8' ) ), str( self.password.encode( 'utf-8' ) ) ) == self.password )

    def update( self ):
        session.commit()

    def _get_bcrypt_hash( self, input_string ):
        return bcrypt.hashpw( str( input_string ), bcrypt.gensalt( 10 ) )

    def __str__(self):
        return self.username + " - ( " + self.full_name + " )"

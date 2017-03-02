import http
import string
import random
import socketserver
import requests
import time

from multiprocessing import Process, Pipe
from http.server import SimpleHTTPRequestHandler

class WebServer:
    """
    The source for the SimpleHTTPRequestHandler is at:
        /usr/lib/python3.5/http/server.py
    The source for the socketserver module is at:
        /usr/lib/python3.5/socketserver.py
    """
    def __init__(self, handler=None, port=None):
        if port:
            self._port = port
        else:
            self._port = int(random.uniform(3000, 4000))
        self._redirect_uri = 'http://127.0.0.1:' + str(self._port)
        if handler:
            self.handler = handler
        else:
            self.handler = Handler
        self.auth_code = None
        self.nonce = self._Nonce()

    # method to generate nonce:
    def _Nonce(self, size=10, chars=string.ascii_uppercase + string.digits):
        return ''.join(random.choice(chars) for _ in range(size))


    def serve_html(self):
        """
        This method starts a basic web server that listens on self._port, to accept the HTTP request from Google's oauth server that contains the authorization code.
        As the auth code is in the actual HTTP request, we use a custom handler (myGetHandler) which intercepts the actual HTTP request, and stores it in memory.
        """
        # the port that the web server will listen on
        PORT = self._port
        # the custom handler that intercepts and parses the auth code:
        #Handler = self.handler
        # define the web server and the request handler that will be called for each HTTP request:
        httpd = socketserver.TCPServer(("", PORT), self.handler)
        print("serving at port", PORT)
        # start the web server and listen for one request:
        httpd.handle_request()
        # "path" is the attribute that contains the path that was requested in the http request:
        path = Handler.path
        print('this is the path: ', path)
        # trying different approaches for storing the request:
        #path2 = Handler.get_path()
        ## ### NEW
        ## # Parse the response (**I thought it was a request??) for auth_code and state (state should return self.nonce):
        ## response = urllib.parse.urlparse(path)
        ## for element in response.query.split(sep='&'):
        ##     if element.startswith('state'):
        ##         state = element.split(sep='=')[1] 
        ##     if element.startswith('code'):
        ##         code = element.split(sep='=')[1] 

        ## # if the nonces match, call swap_code, else print error:
        ## if self._nonce == state:
        ##     self.swap_code(code)
        ## else:
        ##     print("The sent nonce does not match the return nonce.")
        ##     # it would be better to raise an Exception:
        ##     # raise Exception("The sent nonce does not match the return nonce.")
        ## # debugging..
        ## print("THIS IS THE PATH: ", path, "THIS IS PATH2: ", path2)
        ## # I wanted to return a some value that we could test against, but I'm not sure if it is required???
        ## return 0

class Handler(SimpleHTTPRequestHandler):
    path = ''
    def set_path(data):
        Handler.path = data

    def get_path():
        return Handler.path

    def do_GET(self):
        print("THIS IS THE FULL RESPONSE: ", self.headers)
        print("THIS IS THE path: ", self.path)
        Handler.path = self.path
        http.server.SimpleHTTPRequestHandler.do_GET(self)

    #def call_get_request(self):
    #    answer = super().get_request(self)
    #    return answer
class Testing:
    """
    For testing if this module works..
    """

    def __init__(self):
        self.wl = WebServer()
        self.port1 = self.wl._port
        print('the port is: ', self.port1)
        self.p1 = Process(target=self.wl.serve_html)
        self.conn_in, self.conn_out = Pipe()
        self.p2 = Process(target=self.request, args=(self.port1, self.conn_in,))

    def request(self, port, conn):
        s = 'http://127.0.0.1:' + str(port)
        r = requests.get(s)
        print('this is the status_code: ', r.status_code)
        conn.send(r.text)
        if r.status_code == 200:
            return True
        else:
            return False

    def test(self):
        self.p1.start()
        x = 0
        while x < 3:
            try:
                print('in loop ', x)
                time.sleep(3)
                self.p2.start()
                self.p2.join()
                print('p2 has started')
                if 'INDEX.HTML FILE' in self.conn_out.recv():
                    print("PASS: Oauth.Webserver works!")
                    break
                print('this is the pipe output: ', self.conn_out.recv())
                if t.exitcode is None:
                    break
            except Exception:
                print('there was an error')
            x += 1
        print('loop finished')

if __name__ == '__main__':
    t = Testing()
    t.test()

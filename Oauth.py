import http.server
import socketserver
import requests
import json
import time
import random
import os
import string
import webbrowser
import urllib

###     START NEW           ###

class Oauth:
    """
    This class contains the methods for handling Google authentication with Oauth2.0.
    """
    def __init__(self, credentials_file='credentials.json'):
        """
        Create an instance of the Oauth class.
        """
        self._scope = 'https://www.googleapis.com/auth/drive'
        self._nonce = Oauth.nonce(self, size=136)
        self._port = int(random.uniform(3000, 4000))
        self._redirect_uri = 'http://127.0.0.1:' + str(self._port)
        self._credentials_file = credentials_file
        self._code = None       # this is not required and should be retrieved via an accessor method, or return value but could be useful for debugging.

    # these are the class attributes:
    _server = 'https://www.googleapis.com/auth/drive'           # this should be embedded in the method.
    _client_id = '696694623422-rte0oijs03i83paq0efj7m46nvqphuuj.apps.googleusercontent.com'
    _client_secret = 'irLCJ9OakyQ0Z-u5u1RfR6Zn'
        
    def auth_in_browser(self, params=None, url=None):
        """
        This function opens up the web browser to authenticate with oauth2.
        So, this should be called just before the web server has started up, so it can catch the response from this.
        
        url     -           the base url to open up in browser

        params (optional) can be the following keys, in the form of a dict:
        
        scope           -   the oauth2 scope
        redirect_uri    -   the local web server
        response_type   -   always 'code'
        client_id       -   the app id (from Google)

        TODO:
        add 'hint' parameter: this allows the user to enter their email address, so Google knows who to authenticate with.
        """
        if url is None:
            url = 'https://accounts.google.com/o/oauth2/token' + '?'
        if not isinstance(params, dict):
            params = {
            'redirect_uri': self._redirect_uri, 
            'scope': self._scope, 
            'client_id': '696694623422-rte0oijs03i83paq0efj7m46nvqphuuj.apps.googleusercontent.com', 
            'state' : self._nonce,
            'response_type': 'code'}

        target = 'https://accounts.google.com/o/oauth2/v2/auth' 
        url = target + '?' + urllib.parse.urlencode(params)
        webbrowser.open_new_tab(url)

    # method to generate nonce:
    def nonce(self, size=10, chars=string.ascii_uppercase + string.digits):
        return ''.join(random.choice(chars) for _ in range(size))

    def serve_html(self):
        """
        This is the web server that receives the HTTP response with the credentials, from Google.
        """
        PORT = self._port
        Handler = myGetHandler
        httpd = socketserver.TCPServer(("", PORT), Handler)
        print("serving at port", PORT)
        httpd.handle_request()
        path = Handler.path
        path2 = Handler.get_path()
        ### NEW
        # Parse the response for auth_code and state
        response = urllib.parse.urlparse(path)
        for element in response.query.split(sep='&'):
            if element.startswith('state'):
                state = element.split(sep='=')[1] 
            if element.startswith('code'):
                code = element.split(sep='=')[1] 

        ### OLD
        """
        if path:
            try:
                if Handler.path.split(sep='&')[0].index('state') > 0:
                    state = Handler.path.split(sep='&')[0].split(sep='=')[1]
                    code = Handler.path.split(sep='&')[1].split(sep='=')[1]
                elif Handler.path.split(sep='&')[0].index('code') > 0:
                    code = Handler.path.split(sep='&')[0].split(sep='=')[1]
                    state = Handler.path.split(sep='&')[1].split(sep='=')[1]

            except ValueError:
                print('Response did not contain a code.')
            print("THIS IS THE CODE: ", code)
            print("THIS IS THE STATE: ", state)
        """
        if self._nonce == state:
            self.swap_code(code)
        else:
            print("The sent nonce does not match the return nonce.")
        print("THIS IS THE PATH: ", path, "THIS IS PATH2: ", path2)
        return 0


    def swap_code(self, code, params=None, creds_file=None):
        """
        This method swaps the auth code, from self.serve_html(), for the oauth tokens. 
        It should store the oauth tokens, from the HTTP response, in a credentials file, and get_token() should actually get the token.

        - TARGET URL 
            (https://accounts.google.com/o/oauth2/v2/auth) + '?'
        REQUIRED HTTP PARAMETERS:
        - SCOPE
            https://www.googleapis.com/auth/drive
        - REDIRECT URI
            'http://127.0.0.1:' + self._port
        - RESPONSE_TYPE
            'code'
        - CLIENT_ID
            '696694623422-rte0oijs03i83paq0efj7m46nvqphuuj.apps.googleusercontent.com
        *** PARAMS ARE DELIMITED WITH '&'   ***
        """
        if not isinstance(params, dict):
            params = {
            'client_id' : self._client_id,
            'client_secret' : self._client_secret,
            'redirect_uri' : self._redirect_uri,
            'grant_type' : 'authorization_code'
            }

        params['code'] = code
        try:
            oauth_request = requests.post('https://accounts.google.com/o/oauth2/token', data=params)
            print("THIS IS THE RESPONSE TEXT: ", oauth_request.text)
            # oauth_response = json.dumps(oauth_request.json())       # This stores the json response as a json string.
            oauth_response = oauth_request.json()       # This stores the json response as a json string.
        except ValueError as e:
            print("THE RESPONSE DID NOT CONTAIN ANY VALID JSON: ", e)
            return 'NO JSON IN RESPONSE'
        oauth_response['time_received'] = int(time.time())
        print("Here is the full credentials dict, that should have a time_received key: ", oauth_response)
        response = json.dumps(oauth_response)
        with open(self._credentials_file, 'w') as credentials:
            credentials.writelines(response)
        # return oauth_request.json()['access_token']   <- this shouldn't be required, as it should only store the access/refresh token in a file, then get_tokem() can actually get the access token. TIMESTAMP NEEDED?

    def authorize(self):
        """
        This function just calls the functions required to initially grant permission for Google drive.
        """
        print("Please grant application permission in browser...")
        self.auth_in_browser()
        self.serve_html()


    def get_token(self, creds_file=None):
        """
        This method returns either the access_token (if it hasn't expired), or will refresh the token if the access token has expired.
        Either way, it returns a valid access token.
        """
        if creds_file is None:
            creds_file = self._credentials_file
            if not os.path.exists(self._credentials_file):
                self.authorize()
                #print("""There is no credentials file.
                #Please use self.authorize to create a credentials file and pass it as an argument to creds_file=""") 
                #return -1
        creds = json.load(open(creds_file))
        if (int(time.time()) - creds['time_received']) > 3580:
            new_token = self.refresh_token()
            # new_token['time_received'] = time.time() <- NOT NECESSARY, AS IT IS HANDLED BY refresh_token.
            with open(creds_file, 'w') as credentials:
                # update new token
                credentials.writelines(json.dumps(new_token))   # json.dumps(object) serializes object into type(str)
            return new_token['access_token']
        else:
            return creds['access_token']
           

    def refresh_token(self, credentials_file='credentials.json'):
        """
        This method return a refresh_token (which should be a json response) as a dict. IT DOES NOT UPDATE THE CREDENTIALS_FILE! <- this should be handled by the caller.
        So the items required to get a refresh token are:
        - client_id             CONSTANT
        - client_secret         CONSTANT
        - refresh_token         VARIABLE?
        - grant_type            CONSTANT
        - URL                   CONSTANT
        - And it uses the POST method.
        """
        refresh_url = 'https://accounts.google.com/o/oauth2/token'
        params = {
            'client_id' : Oauth._client_id,
            'client_secret' : self._client_secret,
            'grant_type' : 'refresh_token',
            'refresh_token' : json.load(open(credentials_file))['refresh_token']
            }
    
        try:
            oauth_refresh = requests.post(refresh_url, data=params)
        except ValueError as e:
            print("REFRESH HTTP RESPONSE DID NOT CONTAIN VALID JSON: ", e)
        answer = oauth_refresh.json()
        answer['time_received'] = time.time()
        return answer

class myGetHandler(http.server.SimpleHTTPRequestHandler):

    

    path = ''

    def set_path(data):
        """
        This method fetches the Handler.path.
        It is called by do_GET().
        """
        myGetHandler.path = data       # TODO: THIS METHOD SHOULD BE USED TO STORE THE AUTH CODE, AND EXCHANGE IT FOR AN ACCESS TOKEN.

    def do_GET(self):
        print("THIS IS THE FULL RESPONSE: ", self.headers)
        myGetHandler.set_path(self.path)
        http.server.SimpleHTTPRequestHandler.do_GET(self)

    def get_path():
        """
        This method gets Handler.path.
        """
        return myGetHandler.path


if __name__ == '__main__':
    # NEW CODE:
    # this is to test the get_token() method.
    #   Since I should already have the refresh_token stored in self._credentials_file, get_token() should automatically decide whether it requires a new token, or not, depending on the time:
    
    oauth = Oauth('credentials.json')
    oauth.authorize()

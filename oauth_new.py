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
    """
    #   Start nested classes    #

    class ClientCredentials:
        """
        This is the credentials of the application (client) that is requesting access to the protected resource, on behalf of the user.
        """
        def __init__(self, client_file=None, **kwargs):
            """
            This sets the client credentials, so that the oauth provider can identify who is requesting access to the protected user resources.

            The following parameters are required for Oauth2.0:
                    - 'client_id'	the ID of the application that is requesting access on behalf of the user.
                    - 'client_secret'	a unique string that further identifies the application.
            
            These are the optional parameters:
                    - client_file   If you would like to pass the parameters as a json encoded, text file, use this to set the path. The file will be parsed into a dict, and the mandatory args above will have to be in the file, or an exception will be raised.
                    - 'scope'		the scope is what resource, and actions to the resource are being requested.
            
                The params are expected as key:value pairs.
                    client_creds = ClientCredentials('client_id' : 'gagargfr....')
                Or you can pass a dict:
                    client_creds = ClientCredentials(**dict)
                Or a file:
                    client_creds = ClientCredentials(client_file='/path/to/file')
                
            """
        def __init__(self, **kwargs):
            if 'filepath' in kwargs.keys():
                self.path = kwargs['filepath']
            else:
                req_params = [
                    'client_id',
                    'client_secret',
                    'scope'
                    ]
                for param in req_params:
                    if param not in kwargs.keys()
                    raise Exception(param, " parameter required!"


        def get_key(self, obj, key):
            """
            Utility method to return the value of key. If there is a key called 'key' in obj's keys, it will return its value, else, it will test if any of obj.keys() are dict, and look for the key there, it will recursively test each item of any nested dicts, to see if it contains the key, else return an error if the key is not found.

            EG:
                obj = {'key1' : 'val1', 'nested_dict' : 
                        {'n_key1': 'n_val1', 'n_key2' : 'n_val2'}
                        }
                ^ get_key(obj, 'n_key2')
                  'n_val2'
            """	
            if key in obj.keys():
                return obj[key]
            else:
                for item in obj.keys():
                    print('this is in the loop: ', item)
                    if isinstance(obj[item], dict):
                        return get_key(obj[item], key)
            raise KeyError(key, ' value not found')

        def get(self, attr):
            """
            """
            pass

        def set(self, attr):
            """
            """
            pass

    class WebServer:
        """
        """
        def __init__(self, port?, handler?):
            self.port = port
            self.handler = handler
            self.auth_code = None

        def serve_html(self, port, handler):
            pass

    class UserToken:
        def __init__(self, path):
            self.path = path

        def get(self, key):
            return self[key]

        def set(self, key, value):
            self[key] = value

    class myGetHandler(http.server.SimpleHTTPRequestHandler):
        def set_code(self, code):
            self.code = code

        def get_code(self):
            return self.code

    #   End nested classes    #

    def __init__(self, user_path, client_creds=None, **kwargs):
        """
        Initialize Oauth object.
        The client (the app that is requesting access to the user (user=resource owner) resources on behalf of user.

		Mandatory args:
		user_file_path	-	the path to where the user's access/refresh tokens will be stored.
        
        Optional
        TODO:
        - chmod 600 user_path
        """
        self._user_path = user_path
        # Test if a path to the app client_id has been passed to init, else, the client params should be passed as key:value pairs to kwargs, which will then be returned as a dict. kwargs.keys() will be tested to ensure that the right values have been passed or an exception will be raised.
        if client_creds = None
            #if 'filepath' in kwargs.keys():
            #    self.path = kwargs['filepath']
            #else:
                req_params = [
                    'client_id',
                    'client_secret',
                    'scope'
                    ]
                for param in req_params:
                    if param not in kwargs.keys()
                    raise Exception(param, " parameter required!"
                self.Cred
                self.scope = kwargs['scope']
                self.client_id = kwargs['client_id']
                self.client_secret = kwargs['client_secret']
 

    # old get_key()
    def get_key(self, obj, key):
        """
        Utility method to return the value of key. If there is a key called 'key' in obj's keys, it will return its value, else, it will test if any of obj.keys() are dict, and look for the key there. It only tests one level down.

        EG:
            obj = {'key1' : 'val1', 'nested_dict' : 
                    {'n_key1': 'n_val1', 'n_key2' : 'n_val2'}
                    }
            ^ get_key(obj, 'n_key2')
              'n_val2'
        """
        if not isinstance(obj, dict):
		     raise Exception("object must be dict")
    	if val in obj.keys():
    	    return obj[val]
    	else:
    	    for item in obj.keys():
    	        print(item)
    	        if isinstance(obj[item], dict):
    	            if val in obj[item].keys():
    	                return obj[item][val]
    	            else:
    	                raise Exception("key not found")


###     END  NEW           ###

class Oauth:
    """
    This class lets the user use Google's oauth2.0 authentication.
    To use just create an instance; call self.authorize; then self.get_token will return a valid access_token.


    This class contains the methods for handling Google authentication with Oauth2.0.
    The idea with this class is that it should be initialized with a credentials_file and the only method that the user calls will be self.authorize(), which stores the access and refresh token in the credentials_file.
    The self.get_token should also be a public method, so the user can get a token.
    E.G:
        oauth = Oauth('./credentials.json')
        oauth.authorize()
        token = oauth.get_token()
        api_call(token....

    Ideally, self.authorize() would be called with by __init__() so the user doesn't even have to call it at all:
    E.G:
        oauth = Oauth('./credentials.json')
        # user asked to authorize in browser...
        token = oauth.get_token()...
    
    So after I have ironed out the bugs, I should be able to hide the implementation details in non-public methods, so the user is only provided with only the required methods.
    I also want to eventually refactor this code so that it can be used with any oauth2.0 compliant service.

    """
    def __init__(self, credentials_file='credentials.json'):
        """
        Create an instance of the Oauth class.

        TO-DO:
        - refactor __init__() so that it accepts **kwargs as a param:
            def __init__(self, credentials_file=None, client-id=None):
                if client-id is not None:
                    self.client_credentials_as_dict = json.load(open(client-id))
        This will allow us to instantiate an Oauth object by passing "key=value" pairs:
            oauth = Oauth(json.load(open('google-clientid.json'))
        		EG:
				def __init__(self, **kwargs):
    				self.redirect_uris = kwargs['redirect_uris']
    				self.client_id = kwargs['client_id']
    				self.token_uri = kwargs['token_uri']
    				self.client_secret = kwargs['client_secret']
    				self.auth_uri = kwargs['auth_uri']
    				self.project_id = kwargs['project_id']

        - get client-id.json for Google Contacts API
        """
        self._scope = 'https://www.googleapis.com/auth/drive'
        self._nonce = Oauth.nonce(self, size=136)
        self._port = int(random.uniform(3000, 4000))
        self._redirect_uri = 'http://127.0.0.1:' + str(self._port)
        self._credentials_file = credentials_file
        self._code = None       # this is not required and should be retrieved via an accessor method, or return value but could be useful for debugging.
        # for testing:
        self.token_age = None

    # these are the class attributes:
    _server = 'https://www.googleapis.com/auth/drive'           # this should be embedded in the method.
    _client_id = '696694623422-rte0oijs03i83paq0efj7m46nvqphuuj.apps.googleusercontent.com'
    _client_secret = 'irLCJ9OakyQ0Z-u5u1RfR6Zn'
        
    def auth_in_browser(self, params=None, url=None):
        """
        This method opens up the web browser to authenticate with Google's oauth2, using paramaters that specify the app that's requesting access to the resource. 
        If the user grants permission to the app, Google's oauth2.0 server makes an HTTP request to the specified redirect_uri on port self._port. 
        The HTTP request contains an "authorization code" that will be exchanged for access tokens, which can then be used to access a user resource.
        So after this method is called, self.serve_html is called to start a basic web server that intercepts and stores the auth code, so it can be passed as a parameter to self.swap_code, which is called by self.serve_html.
        This method shouldn't have to be called by the user, so it should be a non-public method.
        The user should only have to call the self.authorize method, which makes the necessary calls to aquire the access tokens.
        This should be called just before the web server has started up, so it can catch the response from this.
        
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
        This method starts a basic web server that listens on self._port, to accept the HTTP request from Google's oauth server that contains the authorization code.
        As the auth code is in the actual HTTP request, we use a custom handler (myGetHandler) which intercepts the actual HTTP request, and stores it in memory.
        """
        # the port that the web server will listen on
        PORT = self._port
        # the custom handler that intercepts and parses the auth code:
        Handler = myGetHandler
        # define the web server and the request handler that will be called for each HTTP request:
        httpd = socketserver.TCPServer(("", PORT), Handler)
        print("serving at port", PORT)
        # start the web server and listen for one request:
        httpd.handle_request()
        # "path" is the attribute that contains the path that was requested in the http request:
        path = Handler.path
        # trying different approaches for storing the request:
        path2 = Handler.get_path()
        ### NEW
        # Parse the response (**I thought it was a request??) for auth_code and state (state should return self.nonce):
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
        # if the nonces match, call swap_code, else print error:
        if self._nonce == state:
            self.swap_code(code)
        else:
            print("The sent nonce does not match the return nonce.")
            # it would be better to raise an Exception:
            # raise Exception("The sent nonce does not match the return nonce.")
        # debugging..
        print("THIS IS THE PATH: ", path, "THIS IS PATH2: ", path2)
        # I wanted to return a some value that we could test against, but I'm not sure if it is required???
        return 0


    def swap_code(self, code, params=None, creds_file=None):
        """
        This method swaps the auth code, from self.serve_html(), for the oauth tokens. 
        It should store the oauth tokens, from the HTTP response, in a credentials file, and get_token() should actually get the token.
        This method should not be called by the user as it is called by other methods (serve_html) and should be non-public.
        Eventually, the creds_file param should be removed as well as it is defined with __init__, and the user should only have to call self.authorize(), but until I've got this class where I want it, creds_file will remain for debugging...

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
        This function just calls the methods required to initially grant permission for Google.
        """
        print("Please grant application permission in browser...")
        self.auth_in_browser()
        self.serve_html()


    def get_token(self, creds_file=None):
        """
        This method returns either the access_token (if it hasn't expired), or will refresh the token if the access token has expired, either way, it returns a valid access token.
        """
        # check that there is a credentials file, raise exception:
        if creds_file is None:
            creds_file = self._credentials_file
            if not os.path.exists(self._credentials_file):
                #self.authorize()       # I decided that this could lead to undefined behaviour..
                raise Exception("This app has not yet been granted permission. \
                Please call self.authorize() needs to grant permission to this app and to get an authorization code.")
                #print("""There is no credentials file.
                #Please use self.authorize to create a credentials file and pass it as an argument to creds_file=""") 
                #return -1
        # load credentials:
        creds = json.load(open(creds_file))
        # check if the tokens are under 3600 seconds old:
        # for testing:
        # if the token is older than 3600s, refresh the token:
        #if (int(time.time()) - creds['time_received']) > 3580:
            # store the existing refresh_token, as the json returned from refresh_token() does not have one:
        self.token_age = age = int(time.time()) - creds['time_received']
        if age > 3580:
            print(int(time.time()), '  ', creds['time_received'], '  should == ', age)
            print("Refreshing token...")
            # store existing refresh_token:
            temp_refresh_token = creds['refresh_token']
            # refresh_token() returns a dict:
            new_token = self.refresh_token()        
            print("New token:\t", new_token)
            # create 'refresh_token' key in the new token, so new_token.keys() should == access_token, token_type, expires_in, refresh_token: plus 'time_received' which I defined:
            new_token['refresh_token'] = temp_refresh_token
            # new_token['time_received'] = time.time() <- NOT NECESSARY, AS IT IS HANDLED BY refresh_token.
            if len(new_token.keys()) == 5:
                # update creds_file with new access_token:
                json.dump(new_token, open(creds_file, 'w'))         #json.dump(obj, fp)
            else:
                raise Exception("The refresh token should have 5 keys, but there isn't...")
            """
            with open(creds_file, 'w') as credentials:
                credentials.writelines(json.dumps(new_token))   # json.dumps(object) serializes object into type(str)
            """
            return new_token['access_token']
        else:
            return creds['access_token']
           

    def refresh_token(self, creds_file=None):
        """
        This method returns the refresh_token as a dict. It DOES NOT UPDATE THE CREDS FILE! That should be handled by the caller.
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
        # check that there is a credentials file, raise exception:
        if creds_file is None:
            creds_file = self._credentials_file
            if not os.path.exists(self._credentials_file):
                #self.authorize()       # I decided that this could lead to undefined behaviour..
                raise Exception("This app has not yet been granted permission. \
                Please call self.authorize() needs to grant permission to this app and to get an authorization code.")
        params = {
            'client_id' : Oauth._client_id,
            'client_secret' : self._client_secret,
            'grant_type' : 'refresh_token',
            'refresh_token' : json.load(open(creds_file))['refresh_token']
            }
    
        try:
            oauth_refresh = requests.post(refresh_url, data=params)
        except ValueError as e:
            print("REFRESH HTTP RESPONSE DID NOT CONTAIN VALID JSON: ", e)
        answer = oauth_refresh.json()
        # testing
        answer['time_received'] = int(time.time())
        return answer

    def is_valid(self, token):
        print("Checking if token is valid...")
        target = 'https://www.googleapis.com/oauth2/v1/tokeninfo'
        r = requests.get(target, params={'access_token':token})
        if r.status_code == 200:
            return True
        else:
            return False

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
    
    oauth = Oauth('/home/justin/tmp/credentials.json')
    # step 1)
    #oauth.authorize()
    # the above completed successfully, and created the self.credentials_file, with the initial access_token[s]
    ## step 2)
    #token = oauth.get_token()
    #print("access token:\t", token)
    #print("age of token:\t", oauth.token_age)
    # step 2 seemed to return a valid access_token, but I did NOT actually test it with an API call..
    ## step 3) test what, and what type self.refresh_token() returns:
    # I also have to test if changing the default arg of creds_file=None works:
    #refresh_token = oauth.refresh_token()
    #print("The type returned  by refresh_token() is: \t", type(refresh_token))
    #print("The actual content returned by refresh_token() is: \t", refresh_token)
    # refresh_token seems to work, but I haven't validated it yet... with is_valid...
    ## step 3) test get_token()
    token = oauth.get_token()
    print("This is the token returned by get_token:\t", token)
    if oauth.is_valid(token):
        print("the token works")
    else:
        print("the token is INVALID")
    #target = 'https://www.googleapis.com/drive/v2/files'
    #r = requests.get(target, params={'access_token':token})
    #print(r.text)
    # the above code has been tested and is working correctly!
    # TODO: define self.is_valid(token) method to test if the token is valid
    # TODO: clean up the comments
    # make it so that the app credentials are parameters, and be used by anyone's app

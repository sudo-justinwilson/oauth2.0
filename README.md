# oauth2.0

This is a __Python3__ library that was written for installed, Linux applications to make oauth2.0 authorized API calls.

There are multiple varieties of what are called oauth2.0 "flows", which specify _the type of app_ that is requesting access to a service that offers oauth2.0 authorization (EG: web-apps, phone apps..). As mentioned above, this is for applications that are __installed__ on a local computer. The main difference with this flow is that the client app requests a refresh token, which can be used indefinitely (or at least until the user revokes permission to the app), as opposed to _web-apps_ which would only have short-term access to the resources.

It was originally written to authorize with Google's oauth2.0 implementation, but should be able (or at least be easy to port) to be used with any oauth2.0 compliant service provider.

## Tutorial:
As mentioned above this is for client-side applications installed on Linux (it might work on any POSIX system, but it depends on if the Python "os" module).

### Oauth2.0 basics:
A quick high level view of how oauth2.0 works. There are plenty of resources if you look for it. In this example, let's say that I have a Google Drive client for Linux, that would like to manage a user's Google Drive files, so that it can sync the files with the desktop.
Our main objective is to get a valid __access token__ which can be put with restful API, http requests:

1. The developer of the _client_ (the installed application) would need to register the client with the oauth2.0 provider, with the right __scope__. The scope is the level of access that is requested by the client app. Once registered, the app will be provided with credentials that can identify the app to the oauth2.0 server.
2. Once the client has credentials (namely the client id & client secret), they can be passed to the Oauth module's initializer:
  * As a string which is a path to the client credentials as a json file:
    oauth = Oauth(user_path, client_creds='/path/to/file', scope=None)
  * As a dict which contains the client id & secret:
    oauth = Oauth(user_path, client_creds={'client_id':'xxx', 'client_secret':'xxxx'}, scope=None)
  * Or as key=value pairs:
    oauth = Oauth(user_path, scope=None, client_id='xxx', client_secret='xxx')
  * __user path__: This is the path to the file where the user's tokens will be stored.
  * __scope__: As explained above, this is what level of access is requested by the client app. It is optional because some Oauth2.0 providers (like GitHub) do have API calls which do not require a scope, but it is usually required by most services...
3. Once you have an Oauth object, call oauth.authorize() which will start the authentication flow:
  1. The user's web browser will open and ask if the user grants authorization to the client app for the specified scope[s].
  2. Assuming the user consents, you can then get a valid access token like so:
    token = oauth.get_token()

The code is well commented, and it is written with builtin modules (except for the *requests* module.

## Oauth2.0 Resources:
I have found that the best resource to learn how auth2.0 works is the oauth2.0 playground, provided by Google at: 
    https://developers.google.com/oauthplayground/

## ISSUES:
- I get a "sandbox" error when using a web proxy.
- Fedora 25: The firewall blocks the random port.

## TODO:
- 



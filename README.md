# oauth2.0

I wrote this module to use oauth2.0 to authenticate with Google. It was initially meant for Google drive, but I thought that I should make it more general...

It is written in Python3, but shouldn't be too hard to port. Just need to change the print() statements, and change the builtin modules so that it uses the py2 equivalent..

The best resource is the oauth2.0 playground, provided by Google at: 
    https://developers.google.com/oauthplayground/

## UP TO
Ironed out the bugs so that oauth.get_token() returns a valid access_token.
I have also added a method that returns True if the token is valid.

- The next thing on the to-do list is to change init so that you can pass the credentials.json file to the constructor, and it will parse the client-id from the file.This will allow the module to be used for any Google service.
- I have also been checking out the other Oauth2.0 providers (GitHub, etc..) and it looks like it shouldn't be too hard to use this module to authenticate with any Oauth2.0 service.
- I have defined the ClientCredentials.get\_key() method, now I have to use it with init.



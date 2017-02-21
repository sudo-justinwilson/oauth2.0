# oauth2.0
<<<<<<< HEAD
This is a Python library for authenticating with oauth2.0 (namely Google), but it should be able to work with any oauth2.0 provider...

I wrote it to use for Linux, and don't think it would work on other platforms, but it shouldn't be too hard to port...

I pretty much wrote it from scratch using mostly built-in Python modules. I think the "requests" module is the only one that I installed with pip.
=======

I wrote this module to use oauth2.0 to authenticate with Google. It was initially meant for Google drive, but I thought that I should make it more general...

## UP TO
I am up to testing and debugging if the refresh token method is working correctly. I suspect that the refresh token that is returned is in a different format to the token that is initially swapped, and currently, so I need to change the way I handle the refresh token..

The best resource is the oauth2.0 playground, provided by Google at: 
    https://developers.google.com/oauthplayground/
>>>>>>> fix

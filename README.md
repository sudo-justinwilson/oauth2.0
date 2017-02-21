# oauth2.0

I wrote this module to use oauth2.0 to authenticate with Google. It was initially meant for Google drive, but I thought that I should make it more general...

## UP TO
I am up to testing and debugging if the refresh token method is working correctly. I suspect that the refresh token that is returned is in a different format to the token that is initially swapped, and currently, so I need to change the way I handle the refresh token..

The best resource is the oauth2.0 playground, provided by Google at: 
    https://developers.google.com/oauthplayground/

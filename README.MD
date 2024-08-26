# Shibboleth Intercept
(See below, no longer functional) Authenticates with the UCI Shibboleth IDP programmatically with interactive DUO 2FA security support to authenticate and access information on other affiliated websites behind SSO authentication pages.

## Future endeavours
No longer functional, UCI has moved to redirecting the user to Duo to finalize 2FA instead of an embedded page/iFrame, further work on this requires either REing the Duo page to simulate it's requests, follow the auth-flow on the server-side and forwarding the prompts to the user.

## Purpose
For developing applications that require authentication with the SSO provider at UCI to develop applications using data from several sources behind 2FA.

This project is not meant to evade or hide any security features and does not remove the requirement of 2FA. The user is still prompted with the iFrame that is usually presented on the login page, and this tool only facilitates the retrieval of the authentication token that is usually forwarded to the service the user is accessing. 

## TODO:
Handle errors.

## Usage
POST: `/login` (x-www-form-urlencoded)
 or
GET: `/login` (query)
* This is an interactive process in order to authenticate with Duo 2FA.
- `url`: SAML Redirect URL
- `callback`: Page to callback to
- `user`: Username
- `pass`: Password

## Additional Endpoints
POST `/idp/profile/SAML2/Redirect/SSO*`
* Reads Duo data when authentication when 2FA is complete.

POST `/callback`
* Test endpoint to see callback data.

POST `/callback_interactive`
* Test endpoint to see callback data and submit it to destination.

# Creating your application
1. Identify the Login endpoint that will 3xx until reaching SSO.
2. Authenticate users by logging them in via `/login` with their username, password, url of the login endpoint, and your callback URL.
3. When users complete, your application will receive data at the callback URL.
```json
{
    "response": "raw html element with shib auth keys and data here",
    "extracted": {
        "main": {
            "name": "SAMLResponse",
            "value": "..."
        },
        "fields": [
            {
                "tag": "input",
                "name": "other-attributes",
                "value": "etc..."
            },
            {
                "expect": "expect incomplete fields, this is a primitive extraction of the data from the response from SSO",
                "data is usually in": "objects with 'tag': 'input'",
                "typically": "all that's really needed is the SAMLResponse"
            },
        ]
    }
}
```

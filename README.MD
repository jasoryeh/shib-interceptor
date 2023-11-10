# Shibboleth Intercept
Authenticates with the UCI Shibboleth IDP programmatically with interactive DUO 2FA security support to authenticate and access information on other affiliated websites behind SSO authentication pages.

## Purpose
For developing applications that require authentication with a SSO provider to develop applications using data from several sources behind 2FA.

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
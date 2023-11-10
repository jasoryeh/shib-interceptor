# UCI Shibboleth Intercept
Authenticates with the Shibboleth IDP at UCI programmatically with interactive DUO 2FA security support to access information on other affiliated websites behind SSO authentication pages.

## Purpose
For developing applications that require authentication with the UCI SSO provider to develop applications using data from several sources behind 2FA.

## TODO:
Handle errors.

## Usage
POST: `/login` (x-www-form-urlencoded)
 or
GET: `/login` (query)
* This is an interactive process, in order to authenticate with Duo 2FA.
- `url`: SAML Redirect URL
- `callback`: Page to callback to
- `user`: Username
- `pass`: Password

## Additional Endpoints
POST `/idp/profile/SAML2/Redirect/SSO*`
* Reads Duo data when authentication with 2FA is complete.

POST `/callback`
* Test endpoint to see callback data.

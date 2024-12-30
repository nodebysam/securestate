# Secure State - CSRF Protection Library

**Secure State** is a robust Node.js library designed to provide protection against Cross-Site Request Forgery (CSRF) attacks. It helps developers add CSRF security to their web applications easily by generating, validating, and managing CSRF tokens with built-in middleware.

## Features
- **Generate and validate CSRF tokens**: Ensures safe requests by verifying tokens.
- **Cookie-based token storage**: Tokens are stored in secure cookies to prevent unauthorized access.
- **Origin and expiration checks**: Configurable to check the origin of requests and token expiration.
- **Debugging support**: Provides detailed debug information (disabled in production).

## Table of Contents
1. [Installation](#installation)
2. [Usage](#usage)
   - [Middleware](#middleware)
   - [CSRF Token Handling](#csrf-token-handling)
3. [Configuration](#configuration)
4. [API Documentation](#api-documentation)
5. [License](#license)

## Installation

Install Secure State via npm:

```bash
npm install secure-state
```

# Usage
## Middleware
1. __secureStateMiddleware:__ This middleware generates and sets a CSRF token if not already set in the cookies. It should be used in routes where CSRF protection is needed.

```node
const { secureStateMiddleware } = require('secure-state');

// Use this middleware on routes that require CSRF protection
app.use(secureStateMiddleware);
```

2. __verifyCsrf:__ This middleware verifies that the CSRF token in the request matches the token stored in the cookies. It should be applied to routes that modify server-side state (e.g., POST, PUT, DELETE).

```node
const { verifyCsrf } = require('secure-state');

// Use this middleware to verify CSRF tokens before handling sensitive actions
app.use('/sensitive-route', verifyCsrf, (req, res) => {
    // Handle the request if CSRF is valid
    res.send('CSRF verified!');
});
```

## CSRF Token Handling
* __Generating a token:__ Use __generateToken__ to manually generate a CSRF token.

```node
const { generateToken } = require('secure-state');

const token = generateToken(req, res);
console.log(token);  // The CSRF token generated
```

* __Validating a Token:__ Use __validateToken__ to check if the incoming token is valid.

```node
const { validateToken } = require('secure-state');

const isValid = validateToken(incomingToken, storedToken);
console.log(isValid);  // Returns true if valid, false if invalid
```

## Configuration
The __Secure State__ library is highly configurable via the __config__ file.

## Available Options:

```javascript
const config = {
    regenerateToken: false,        // Whether to regenerate token on every request
    tokenExpires: false,           // Whether the token should expire
    tokenExpiration: 0,            // Token expiration time in seconds (0 = no expiration)
    checkOrigin: false,            // Whether to check the origin of requests
    debug: false,                  // Enable debug logs (not recommended for production)
    tokenLength: 32,               // Length of the generated token
    cookieOptions: {
        cookieName: '_csrfToken',       // Cookie name to store the CSRF token
        httpOnly: true,            // Prevent access via JavaScript
        sameSite: 'Strict',        // Restrict cross-site cookie sharing
        secure: process.env.NODE_ENV === 'production',  // Secure cookies in production
        path: '/',                 // Cookie path (root of site)
        domain: '',                // Cookie domain
    }
};
```

## Example:
You can modify the __config.js__ file to adjust the CSRF protection according to your needs, such as enabling token expiration or debugging mode.

# API Documentation
### __generateToken(req, res, length)__
* Generates a new CSRF token and stores it in the response cookie.
* __Paramaters:__
    * __req:__ The HTTP request object.
    * __res:__ The HTTP response object.
    * __length:__ Length of the token. Default is 32.
* __Returns:__ The generated CSRF token string.

### __validateToken(incomingToken, storedToken, req)__
* Validates the CSRF token sent by the client.
* __Parameters:__
    * __incomingToken:__ The token received in the request (usually in the __x-csrf-token__ header).
    * __storedToken:__ The token stored in the cookie.
    * __req:__ The HTTP response object (optional).
* __Returns:__ __true__ if the token is valid, __false__ otherwise.

### __secureStateMiddleware(req, res, next)__
* Middleware that generates and sets a CSRF token for incoming requests.
* __Parameters:__
    * __req:__ The HTTP request object.
    * __res:__ The HTTP response object.
    * __next:__ The next middleware function.

### __verifyCsrf(req, res, next)__
* Middleware to verify the CSRF token sent by the client.
* __Parameters:__
    * __req:__ The HTTP request object.
    * __res:__ The HTTP response object.
    * __next:__ The next middleware function.

# License
This library is licensed under the __GPL v3.0__ license. See the [LICENSE](./LICENSE) file for more details.

__Created By:__ Sam Wilcox [wilcox.sam@gmail.com](mailto:wilcox.sam@gmail.com)
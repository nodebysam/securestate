# Secure State

**Secure State** is a robust and easy-to-use CSRF (Cross-Site Request Forgery) protection library for Node.js, built on top of Express.js. It provides developers with the ability to secure their web applications against CSRF attacks by generating, validating, and managing CSRF tokens. 

With the ability to support token expiration and regeneration, Secure State ensures that your application's security is kept up-to-date and resistant to various attack vectors.

## Features

- **CSRF Token Generation**: Automatically generates CSRF tokens on requests and stores them in cookies.
- **Token Validation**: Verifies the CSRF token on each request to ensure it matches the token stored in the cookies.
- **Token Expiration**: Tokens can be configured to expire after a set period, further enhancing security.
- **Token Regeneration**: Option to regenerate tokens on each request to minimize risk.
- **Configurable Options**: Easily configurable through environment variables or configuration files.

## Installation

### 1. Install Secure State

You can install Secure State via npm:

```bash
npm install securestate
```

### 2. Include Secure State in Your Application

In your Express app, include the CSRF protection middleware.

```node
const express = require('express');
const { csrfMiddleware, verifyCsrf } = require('securestate');

const app = express();

// Set up the CSRF middleware to protect routes
app.use(csrfMiddleware);

// Define routes that require CSRF protection
app.post('/sensitive-action', verifyCsrf, (req, res) => {
  res.send('Action performed successfully');
});
```

### Configuration

You can customize Secure State's behavior by modifying the configuration options. Configuration is handled via the config object.

Here are some key configuration options you can use:

* __cookieName:__ Name of the cookie where the CSRF token will be stored. Default is 'csrfToken'.
* __tokenLength:__ The length of the CSRF token. Default is 64.
* __cookieOptions:__ Options for cookie storage, such as __httpOnly__, __secure__, __sameSite__, and __maxAge__.
* __regenerateToken:__ Boolean option to regenerate the CSRF token on every request. Default is false.
* __tokenExpiration:__ Expiration time for the CSRF token in milliseconds. If __null__, tokens do not expire. Default is __null__.

To modify the configuration, create a config.js file in your project, or use environment variables:

```node
module.exports = {
  cookieOptions: {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production', // Secure cookies in production
    sameSite: 'Strict',
    maxAge: 3600000, // 1 hour
  },
};
```

### Using Environment Variables

You can slo use environment variables to configure Secure State:

```env
CSRF_TOKEN_NAME=csrfToken
CSRF_TOKEN_LENGTH=64
CSRF_COOKIE_MAXAGE=3600000
CSRF_REGENERATE_TOKEN=true
CSRF_TOKEN_EXPIRATION=3600000
CSRF_CHECK_ORIGIN=false
CSRF_DEBUG=false
```

### Usage

Once you've set up Secure State and configured it, you're ready to use it in your application. Here's how to handle CSRF protection:

1. __Generate the CSRF token:__ The __csrfMiddleware__ will automatically generate a CSRF token on each request.
2. __Send the CSRF token:__ The token will be set in the response cookies.
3. __Verify the CSRF token:__ On subsequent requests, you must send the CSRF token in the __x-csrf-token__ header. The __verifyCsrf__ middleware will validate the token against the one stored in the cookie.

### Example of a Full Flow

```node
const express = require('express');
const { csrfMiddleware, verifyCsrf } = require('securestate');

const app = express();

// Middleware to enable CSRF protection
app.use(csrfMiddleware);

// Route to perform a sensitive action
app.post('/sensitive-action', verifyCsrf, (req, res) => {
  res.send('Action performed successfully');
});

// Example route to get CSRF token and send it in the response
app.get('/csrf-token', (req, res) => {
  res.json({ csrfToken: req.csrfToken });
});

// Start the app
app.listen(3000, () => {
  console.log('Server running on port 3000');
});
```

### Handling Missing or Mistmatched CSRF Tokens

If the CSRF token is missing or doesn't match, the __verifyCsrf__ middleware will send a __403 Forbidden__ response:

```json
{
  "error": "CSRF token missing."
}
```

or

```json
{
  "error": "CSRF token mismatch."
}
```

### Debugging

To enable debugging, set the __debug__ flag in the configuration:

```node
module.exports = {
  debug: true,
};
```

This will log useful information about token generation and validation to the console.

### Token Expiration

You can set tokens to expire after a certain time. This helps to further protect against misuse of old CSRF tokens. Set the expiration time in the configuration:

```node
module.exports = {
  tokenExpiration: 3600000, // Token expires after 1 hour
};
```

### License

Secure State is licensed under the __GPL-3.0-Only__ license. See [LICENSE](./LICENSE) file for more information.

### Contributing

Contributions are welcome! Please fork the repository, make your changes, and submit a pull request. If you're planning to make a significant change, please open an issue first to discuss your ideas.

### Authors

* __Sam Wilcox:__ Initial development and maintenance

### Thank You

Thank you for using Secure State. We hope it provides the security you need for your web applications!
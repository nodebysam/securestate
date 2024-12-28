/**
 * Secure State
 * A robust CSRF security protection node library.
 * 
 * By Sam Wilcox <wilcox.sam@gmail.com>
 * 
 * This library is licensed under the GPL v3.0 license.
 * Please see LICENSE file included with this library.
 */

/**
 * Secure State library configurations.
 */
const config = {
    // Length of the CSRF token in bytes (32 bytes = 62 hex characters)
    tokenLength: 32,

    // The name of the cookie used to store the CSRF token
    cookieName: 'csrfToken',

    // Options to set when the CSRF token cookie is created
    cookieOptions: {
        // Ensures the cookie can't be accessed via JavaScript (helps prevent XSS attacks)
        httpOnly: true,

        // Prevents the cookie from being sent with cross-site requests (protects against CSRF)
        sameSite: 'Strict',

        // Ensures the cookie is only sent over HTTPS in a production environments
        secure: process.env.NODE_ENV === 'production',

        // The path where the cookie is available (root of the site in this case)
        path: '/',
    },

    // Option to decide if a new token should be generated for each request, or use the same token
    regenerateToken: false,

    // Option to enable or disable the check for the token's origin (IP address and user-agent)
    checkOrigin: false,

    // Option to enable debug mode - be sure to turn off during production
    debug: false,
};

module.exports = config;
/**
 * SECURE STATE
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
    // Whether to regenerate the CSRF token on each request.
    regenerateToken: false,

    // Whether the token will expire after a set period of time.
    tokenExpires: false,

    // The expiration time for the the token in seconds.
    tokenExpiration: 0,

    // Whether to check the origin of the token.
    checkOrigin: false,

    // Debug mode for detailed debug information; not recommended for production.
    debug: false,

    // The length of the token.
    tokenLength: 32,

    // Options to set when the CSRF token cookie is created.
    cookieOptions: {
        // The name of the cookie to store the CSRF token in.
        cookieName: '_csrfToken',

        // Ensures the cookie cannot be accessed via JavaScript (helps prevent XSS attacks).
        httpOnly: true,

        // Prevents the cookie from being sent with cross-site requests (protects against CSRF).
        sameSite: 'Strict',

        // Ensures the cookie is only sent over HTTPS in a production environment.
        secure: process.env.NODE_ENV === 'production',

        // The path where the cookie is available (root of site use '/').
        path: '/',

        // The domain where the cookie is available.
        domain: '',
    },
};

/**
 * Update the library configurations dynamically.
 * 
 * @param {Object} newConfig - An object containing the updated configuration values.
 */
function setConfig(newConfig) {
    for (const key in newConfig) {
        if (config.hasOwnProperty(key)) {
            if (typeof config[key] === 'object' && typeof newConfig[key] === 'object') {
                Object.assign(config[key], newConfig[key]);
            } else {
                config[key] = newConfig[key];
            }
        }
    }

    if (config.debug && process.env.NODE_ENV !== 'test') {
        console.log('[SECURESTATE DEBUG] Updated configuration:', config);
    }
}

module.exports = { config, setConfig };
/**
 * SECURE STATE
 * A robust CSRF security protection node library.
 * 
 * By Sam Wilcox <wilcox.sam@gmail.com>
 * 
 * This library is licensed under the GPL v3.0 license.
 * Please see LICENSE file included with this library.
 */

const config = require('./config');
const { secureStateMiddleware, verifyCsrf } = require('./middleware/csrf');
const { generateToken, validateToken } = require('./lib/token');
const { getCookie, setCookie } = require('./lib/cookies');

/**
 * Export all the neccessary components of Secure State.
 */
module.exports = {
    // Middleware that sets the token.
    secureStateMiddleware,

    // Middleware that verifies token for sensitive actions.
    verifyCsrf,

    // Token library functions.
    generateToken,
    validateToken,

    // Cookie library functions.
    getCookie,
    setCookie,

    // Secure State user configurations object.
    config,
};
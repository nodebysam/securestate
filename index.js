/**
 * Secure State
 * A robust CSRF security protection node library.
 * 
 * By Sam Wilcox <wilcox.sam@gmail.com>
 * 
 * This library is licensed under the GPL v3.0 license.
 * Please see LICENSE file included with this library.
 */

require('dotenv').config();
const config = require('./config');
const { csrfMiddleware, verifyCsrf } = require('./middleware/csrf');
const { generateToken, validateToken } = require('./utils/token');
const { getCookie, setCookie } = require('./utils/cookies');

/**
 * Export all neccessary components of Secure State.
 */
module.exports = {
    // CSRF middleware to set the token for the user
    csrfMiddleware,

    // CSRF middleware to verify the token for sensitive actions
    verifyCsrf,

    // Token utility functions
    generateToken,
    validateToken,

    // Cookie utility functions
    getCookie,
    setCookie,

    // Secure State user configurations object
    config,
};
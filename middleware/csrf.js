/**
 * Secure State
 * A robust CSRF security protection node library.
 * 
 * By Sam Wilcox <wilcox.sam@gmail.com>
 * 
 * This library is licensed under the GPL v3.0 license.
 * Please see LICENSE file included with this library.
 */

const config = require('../config');
const { generateToken, validateToken } = require('../utils/token');
const { getCookie, setCookie } = require('../utils/cookies');

/**
 * Middleware to generate and set a CSRF token in the response cookies.
 * If it doesn't already exist. Adds the token to the req.csrfToken' property.
 * 
 * - If 'config.regenerateToken' is true, generates a new token for every request.
 * - If no token is found in the cookies, generates a new token.
 * 
 * This middleware should be used on all routes that require CSRF protection (e.g., POST,
 * PUT, DELETE, or any method that alters server-side state).
 * 
 * @param {Object} req - The HTTP request object.
 * @param {Object} res - The HTTP response object.
 * @param {Object} next - The next middleware in the stack.
 */
function csrfMiddleware(req, res, next) {
    let csrfToken = getCookie(req, process.env.CSRF_TOKEN_NAME);

    // If token regeneration is enabled, generate a new token for each request.
    if (process.env.CSRF_REGENERATE_TOKEN === 'true' || !csrfToken) {
        csrfToken = generateToken(parseInt(process.env.CSRF_TOKEN_LENGTH, 10), req, res);
        setCookie(res, process.env.CSRF_TOKEN_NAME, csrfToken, config.cookieOptions);

        if (process.env.CSRF_DEBUG === 'true' && process.env.NODE_ENV !== 'test') {
            console.log(`[DEBUG] CSRF token generated: ${csrfToken}`);
        }
    }

    req.csrfToken = csrfToken;
    next();
}

/**
 * Middleware to verify that the CSRF token sent by the client matches the one
 * stored in the server-side cookie. This protects against CSRF attacks.
 * The incoming token should be in the 'x-csrf-token' header.
 * 
 * @param {Object} req - The HTTP request object.
 * @param {Object} res - The HTTP response object.
 * @param {Object} next - The next middleware in the stack.
 */
function verifyCsrf(req, res, next) {
    const csrfHeaderToken = req.headers['x-csrf-token'];
    const csrfCookieToken = getCookie(req, process.env.CSRF_TOKEN_NAME);

    if (!csrfHeaderToken || !csrfCookieToken) {
        if (process.env.CSRF_DEBUG === 'true' && process.env.NODE_ENV !== 'test') {
            console.warn(`[DEBUG] CSRF token missing. Header: ${csrfHeaderToken}, Cookie: ${csrfCookieToken}`);
        }

        return res.status(403).json({ error: 'CSRF token missing.' });
    }

    if (!validateToken(csrfHeaderToken, csrfCookieToken, req)) {
        if (process.env.CSRF_DEBUG === 'true' && process.env.NODE_ENV !== 'test') {
            config.warn(`[DEBUG] CSRF token mismatch. Header: ${csrfHeaderToken}, Cookie: ${csrfCookieToken}`);
        }

        return res.status(403).json({ error: 'CSRF token mismatch.' });
    }

    next();
}

module.exports = { csrfMiddleware, verifyCsrf };
/**
 * SECURE STATE
 * A robust CSRF security protection node library.
 * 
 * By Sam Wilcox <wilcox.sam@gmail.com>
 * 
 * This library is licensed under the GPL v3.0 license.
 * Please see LICENSE file included with this library.
 */

const config = require('../config');
const { generateToken, validateToken } = require('../lib/token');
const { getCookie } = require('../lib/cookies');

/**
 * Middleware to generate and set a CSRF token in the response cookies.
 * If it doesn't already exist. Adds the token to the req._csrfToken property.
 * 
 * - If 'config.regenerateToken' is true, generates a new token every request.
 * - If no token is found in the cookies, generates a new token.
 * 
 * This middleware should be used on all routes that require CSRF protection (e.g., POST,
 * PUT, DELETE, or any method that alters server-side state).
 * 
 * @param {Object} req - The HTTP request object.
 * @param {Object} res  - The HTTP response object.
 * @param {Object} next - The next middleware to execute.
 */
function secureStateMiddleware(req, res, next) {
    try {
        let token = getCookie(req, config.cookieOptions.cookieName);

        if (config.regenerateToken || !token) {
            token = generateToken(req, res, config.tokenLength);

            if (config.debug && process.env.NODE_ENV !== 'test') {
                console.log(`[SECURESTATE DEBUG] CSRF token generated: ${token}`);
            }
        }

        req._csrfToken = token;
        next();
    } catch (err) {
        console.error('Error in secureStateMiddleware:', err);
        next(err);
    }
}

/**
 * Middleware to verify the CSRF token sent by the client matches the one
 * stored in the server-side cookie. This protects against CSRF attacks.
 * The incoming token should be in the 'x-csrf-token' header.
 * 
 * @param {Object} req - The HTTP request object.
 * @param {Object} res  - The HTTP response object.
 * @param {Object} next - The next middleware to execute.
 */
function verifyCsrf(req, res, next) {
    try {
        const bodyToken = req.body[config.cookieOptions.cookieName];
        const headerToken = req.headers['x-csrf-token'];
        const cookieToken = getCookie(req, config.cookieOptions.cookieName);

        if (bodyToken && cookieToken) {
            if (!validateToken(bodyToken, cookieToken, req)) {
                if (config.debug && process.env.NODE_ENV !== 'test') {
                    console.warn(`[SECURESTATE DEBUG] CSRF token mismatch. Body: ${bodyToken}, Cookie: ${cookieToken}`);
                }

                return res.status(403).json({ error: 'CSRF token mismatch.'});
            }
        } else if (headerToken && cookieToken) {
            if (!validateToken(headerToken, cookieToken, req)) {
                if (config.debug && process.env.NODE_ENV !== 'test') {
                    console.warn(`[SECURESTATE DEBUG] CSRF token mismatch. Header: ${headerToken}, Cookie: ${cookieToken}`);
                }

                return res.status(403).json({ error: 'CSRF token mismatch.' })
            }
        } else {
            if (config.debug && process.env.NODE_ENV !== 'test') {
                console.warn(`[SECURESTATE DEBUG] CSRF token missing.`);
            }

            return res.status(403).json({ error: 'CSRF token missing.' });
        }

        next();
    } catch (err) {
        console.error('Error in verifyCsrf:', err);
        next(err);
    }
}

module.exports = { secureStateMiddleware, verifyCsrf };
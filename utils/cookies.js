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
 * Extracts the value of a specific cookie from the request headers.
 * 
 * @param {Object} req - The HTTP request object.
 * @param {string} name - The name of the cookie to retrieve.
 * @returns {string|null} The cookie value if found, or 'null' if not found.
 */
function getCookie(req, name) {
    const cookieHeader = req.headers.cookie;
    if (!cookieHeader) return null;

    const cookies = cookieHeader
        .split(';')
        .reduce((acc, cookie) => {
            const [key, value] = cookie
                .split('=')
                .map(p => p.trim());

            if (key && value !== undefined) {
                acc[key] = decodeURIComponent(value);
            }
            return acc;
        }, {});

        return cookies[name] || null;
}

/**
 * Sets a cookie in the response with the specified parameters.
 * 
 * @param {Object} res - The HTTP response object.
 * @param {string} name - The name of the cookie to set.
 * @param {string} value - The value of the cookie to set.
 * @param {Object} [options={}] - Optional cookie options such as 'maxAge', 'httpOnly', etc.
 * @param {number} [options.maxAge] - The max age lifetime of the cookie.
 * @param {boolean} [options.httpOnly] - True if HTTP only, false if not just HTTP only.
 * @param {string} [options.sameSite] - The same site string.
 * @param {boolean} [options.secure] - True for secure cookies, false for non-secure cookies.
 * @param {string} [options.path] - The cookie path (e.g., '/').
 * @param {string} [options.domain] - The cookie domain (e.g., 'example.com').
 */
function setCookie(res, name, value, options = {}) {
    let cookie = `${name}=${encodeURIComponent(value)}`;
    if (options.maxAge) cookie += `; Max-Age=${options.maxAge}`;
    if (options.httpOnly) cookie += `; HttpOnly`;
    if (options.sameSite) cookie += `; SameSite=${options.sameSite}`;
    if (options.path) cookie += `; Path=${options.path}`;
    if (options.domain) cookie += `; Domain=${options.domain}`;

    if (options.secure && process.env.NODE_ENV === 'production') {
        cookie += `; Secure`;
    }

    res.setHeader('Set-Cookie', cookie);
}

module.exports = { getCookie, setCookie };
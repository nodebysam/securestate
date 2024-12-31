/**
 * SECURE STATE
 * A robust CSRF security protection node library.
 * 
 * By Sam Wilcox <wilcox.sam@gmail.com>
 * 
 * This library is licensed under the GPL v3.0 license.
 * Please see LICENSE file included with this library.
 */

const { config } = require('../config');
const { cookieOptions } = config;

/**
 * Get a cookie.
 * 
 * @param {Object} req - The HTTP request object.    
 * @param {string} name - The name of the cookie to get.
 * @returns {any} The value for the given key. 
 */
function getCookie(req, name) {
    const cookies = req.headers.cookie;

    if (!cookies) {
        return null;
    }

    const cookieArray = cookies.split('; ').map(cookie => cookie.split('='));
    const cookie = cookieArray.find(([key]) => key === name);
    return cookie ? decodeURIComponent(cookie[1]) : null;
}

/**
 * Set a cookie.
 * 
 * @param {Object} res - The HTTP response object.
 * @param {string} name - The name of the cookie to set.
 * @param {any} value - The value of the cookie to set.
 */
function setCookie(res, name, value) {
    if (res.headersSent) {
        console.warn('Headers already sent, cannot modify cookies.');
        return;
    }

    res.cookie(name, value, cookieOptions);
}

/**
 * Check if a cookie exists.
 * 
 * @param {Object} req - The HTTP request object.
 * @param {string} name - The name of the cookie to check.
 * @returns {boolean} True if cookie exists, false if it does not exist.
 */
function cookieExists(req, name) {
    const cookies = req.headers.cookie;

    if (!cookies) {
        return null;
    }

    const cookieArray = cookies.split('; ').map(cookie => cookie.split('='));
    const cookie = cookieArray.find(([key]) => key === name);

    if (cookie) {
        return true;
    }

    return false;
}

/**
 * Delete a cookie.
 * 
 * @param {Object} res - The HTTP response object.
 * @param {string} name - The name of the cookie to delete.
 */
function deleteCookie(res, name) {
    if (res.headersSent) {
        console.warn('Headers already sent, cannot modify cookies.');
        return;
    }

    const cookieOptions = {
        path: config.cookieOptions.path,
        sameSite: config.cookieOptions.sameSite,
        httpOnly: config.cookieOptions.httpOnly,
        domain: config.cookieOptions.domain,
        secure: config.cookieOptions.secure,
    };

    res.cookie(name, '', {
        ...cookieOptions,
        expires: new Date(0),
        maxAge: 0,
    });
}

module.exports = { getCookie, setCookie, cookieExists, deleteCookie };
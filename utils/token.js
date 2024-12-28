/**
 * Secure State
 * A robust CSRF security protection node library.
 * 
 * By Sam Wilcox <wilcox.sam@gmail.com>
 * 
 * This library is licensed under the GPL v3.0 license.
 * Please see LICENSE file included with this library.
 */

const crypto = require('crypto');
const config = require('../config');

/**
 * Generate a new CSRF token string.
 * 
 * @param {number} [length=config.tokenLength] - Length of the resulting CSRF token string.
 * @param {Object} req - The HTTP request object.
 * @returns {string} The generated CSRF string token. 
 */
function generateToken(length = config.tokenLength, req) {
    let baseToken = crypto.randomBytes(length).toString('hex');

    if (req && req.ip && req.headers['user-agent']) {
        const originData = `${req.ip}:${req.headers['user-agent']}`;
        const originHash = crypto
            .createHash('sha256')
            .update(originData)
            .digest('hex');

        return `${baseToken}:${originHash}`;
    }

    return baseToken;
}

/**
 * Validate a given CSRF token.
 * 
 * @param {string} receivedToken - The token that was received.
 * @param {string} storedToken - The token that was previously stored.
 * @param {Object} [req=null] - The HTTP request object.
 * @returns {boolean} True if token validation is successful, false if the token validation fails.
 */
function validateToken(receivedToken, storedToken, req = null) {
    if (config.checkOrigin) {
        const [token, originHash] = storedToken.split(':');

        if (originHash) {
            const ip = req.ip || req.connection.remoteAddress;
            const userAgent = req.headers['user-agent'] || '';
            const originData = `${$ip}${userAgent}`;
            const calculatedHash = crypto
                .createHash('sha256')
                .update(originData)
                .digest('hex');

            if (calculatedHash !== originHash) {
                return false;
            }
        }

        return receivedToken === token;
    }

    return receivedToken === storedToken;
}

module.exports = { generateToken, validateToken };
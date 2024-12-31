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
const { setCookie } = require('./cookies');
const crypto = require('crypto');

/**
 * Generate a new CSRF token.
 * 
 * @param {Object} req - The HTTP request object.
 * @param {Object} res - The HTTP response object.
 * @param {number} [length] - The length of the token to generate.
 * @returns {string} The generated CSRF token string.
 */
function generateToken(req, res, length = config.tokenLength) {
    let baseToken = crypto.randomBytes(length).toString('hex');
    let token = baseToken;
    console.log(config.checkOrigin);
    if (config.checkOrigin && req && req.ip && res.headers && req.headers['user-agent']) {
        const originData = `${req.ip}:${req.headers['user-agent']}`;
        const originHash = crypto.createHash('sha256').update(originData).digest('hex');

        if (config.tokenExpires && config.tokenExpires > 0) {
            const expirationTime = Date.now() + config.tokenExpires * 1000;
            const expirationHash = crypto.createHash('sha256').update(String(expirationTime)).digest('hex');
            token = `${baseToken}:${originHash}:${expirationHash}`;
        } else {
            token = `${baseToken}:${originHash}`;
        }
    }

    setCookie(res, config.cookieOptions.cookieName, token);

    return token;
}

/**
 * Validate a given CSRF token.
 * 
 * @param {string} incomingToken - The token that was received.
 * @param {string} storedToken - The token that was previiously stored.
 * @param {Object} [req=null] - The HTTP request object.
 * @returns {boolean} True if the validated, false if not validated. 
 */
function validateToken(incomingToken, storedToken, req = null) {
    if (config.tokenExpires && config.tokenExpiration > 0) {
        if (config.checkOrigin) {
            const [token, originHash] = storedToken.split(':');

            if (originHash) {
                if (!validateOriginHash(req, originHash)) {
                    return false;
                }
            }
        } else {
            return incomingToken === storedToken;
        }
    } else {
        if (config.checkOrigin) {
            const [token, originHash, timestampHash] = storedToken.split(':');

            if (originHash) {
                if (!validateOriginHash(req, originHash)) {
                    return false;
                }
            }

            if (timestampHash) {
                if (!validateTimestampHash(incomingToken, storedToken)) {
                    return false;
                }
            }
        } else {
            const [token, timestampHash] = storedToken.split(':');

            if (timestampHash) {
                if (!validateTimestampHash(incomingToken, storedToken)) {
                    return false;
                }
            }

            return incomingToken === storedToken;
        }
    }
}

/**
 * Validate a given origin hash string.
 * 
 * @param {Object} req - The HTTP request object.
 * @param {string} hash - The origin hash string.
 * @returns {boolean} True if valid, false if not.
 */
function validateOriginHash(req, hash) {
    const ip = req.ip || req.connection.remoteAddress;
    const userAgent = req.headers['user-agent'];
    const originData = `${ip}${userAgent}`;
    const calculateHash = calculateHash(originData);

    if (calculateHash !== hash) {
        return false;
    }

    return true;
}

/**
 * Validates a given timestamp hash string.
 * 
 * @param {string} token - The token.
 * @param {string} storedToken - The stored token with the timestamp hash.
 * @returns {boolean} True if valid, false if not valid.
 */
function validateTimestampHash(token, storedToken) {
    let timestampHash;

    if (config.checkOrigin) {
        const [, , timestampHsh] = storedToken.split(':');
        timestampHash = timestampHsh;
    } else {
        const [, timestampHsh] = storedToken.split(':');
        timestampHash = timestampHsh;
    }

    if (!timestampHash) {
        return false;
    }

    const timestampString = Buffer.from(timestampHash, 'hex').toString('utf-8');
    const timestamp = parseInt(timestampString, 10);

    const currentTime = Date.now();
    
    if (currentTime > timestamp) {
        return false;
    }

    return true;
}

/**
 * Calculate a given hash string.
 * 
 * @param {string} data - The data to pass into the hash.
 * @returns {string} The calculated hash string.
 */
function calculateHash(data) {
    return crypto
        .createHash('sha256')
        .update(data)
        .digest('hex');
}

module.exports = { generateToken, validateToken };
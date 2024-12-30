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
const config = require('../config');
const crypto = require('crypto');
const DataStore = require('./datastore');
const { setCookie } = require('./cookies');

/**
 * Generate a new CSRF token string.
 * 
 * @param {number} [length=config.tokenLength] - Length of the resulting CSRF token string.
 * @param {Object} req - The HTTP request object.
 * @returns {string} The generated CSRF string token. 
 */
function generateToken(length = parseInt(process.env.CSRF_TOKEN_LENGTH, 10), req, res) {
    length = parseInt(length, 10);
    let baseToken = crypto.randomBytes(length).toString('hex');

    let token = baseToken;

    if (process.env.CSRF_CHECK_ORIGIN === 'true' && req && req.ip && req.headers && req.headers['user-agent']) {
        const originData = `${req.ip}:${req.headers['user-agent']}`;
        const originHash = crypto.createHash('sha256').update(originData).digest('hex');
        
        if (process.env.CSRF_TOKEN_EXPIRATION === null) {
            token = `${baseToken}:${originHash}`;
        } else {
            const expirationTime = Date.now() + parseInt(process.env.CSRF_TOKEN_EXPIRATION, 10) * 1000;
            const expirationHash = crypto.createHash('sha256').update(expirationTime.toString()).digest('hex');
            token = `${baseToken}:${originHash}:${expirationHash}`;
        }
    }

    setCookie(res, process.env.CSRF_TOKEN_NAME, token, {
        httpOnly: config.cookieOptions.httpOnly,
        sameSite: config.cookieOptions.sameSite,
        secure: process.env.NODE_ENV === 'production',
        maxAge: parseInt(process.env.CSRF_COOKIE_MAXAGE, 10),
    });

    return token;
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
    if (process.env.CSRF_TOKEN_EXPIRATION === null) {
        if (process.env.CSRF_CHECK_ORIGIN === 'true') {
            const [token, originHash] = storedToken.split(':');
            
            if (originHash) {
                if (!validateOriginHash(req, originHash)) {
                    return false;
                }
            }
        } else {
            return receivedToken === storedToken;
        }
    } else {
        if (process.env.CSRF_CHECK_ORIGIN === 'true') {
            const [token, originHash, timestampHash] = storedToken.split(':');
            
            if (originHash) {
                if (!validateOriginHash(req, originHash)) {
                    return false;
                }
            }

            if (timestampHash) {
                if (!validateTimestampHash(receivedToken, storedToken)) {
                    return false;
                }
            }
        } else {
            const [token, timestampHash] = storedToken.split(':');

            if (timestampHash) {
                if (!validateTimestampHash(receivedToken, storedToken)) {
                    return false;
                }
            }

            return receivedToken === storedToken;
        }
    }
}

/**
 * Validate the origin hash string.
 * 
 * @param {Object} req - The HTTP request object.
 * @param {string} hash - The origin hash string.
 * @returns {boolean} True if valid, false if not valid.
 */
function validateOriginHash(req, hash) {
    const ip = req.ip || req.connection.remoteAddress;
    const userAgent = req.headers['user-agent'] || '';
    const originData = `${ip}${userAgent}`;
    const calculatedHash = calculateHash(originData);

    if (calculatedHash !== hash) {
        return false;
    }

    return true;
}

/**
 * Validate the timestamp hash string.
 * 
 * @param {string} token - The token.
 * @returns {boolean} True if valid, false if not valid.
 */
function validateTimestampHash(token) {
    let originalToken;

    if (process.env.CSRF_CHECK_ORIGIN === 'true') {
        const [rToken, rOrigin, rTimestamp] = token.split(':');
        originalToken = rToken;
    } else {
        const [rToken, rTimestamp] = token.split(':');
        originalToken = rToken;
    }

    const currentTime = Math.floor(Date.now() / 1000);
    const storedTimestamp = DataStore.get('timestamp');
    const { refToken, refTimestamp } = storedTimestamp;

    if (originalToken !== refToken) {
        return false;
    }

    if (currentTime - parseInt(refTimestamp, 10) > parseInt(process.env.CSRF_TOKEN_EXPIRATION, 10)) {
        return false;
    }

    return true;
}

/**
 * Helper that calculates a hash for given data.
 * 
 * @param {string} data - The data to pass into the hash.
 * @returns {string} The calculated hash. 
 */
function calculateHash(data) {
    return crypto
        .createHash('sha256')
        .update(data)
        .digest('hex');
}

module.exports = { generateToken, validateToken };
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

    if (config.checkOrigin && req && req.ip && req.headers && req.headers['user-agent']) {
        const originData = `${req.ip}:${req.headers['user-agent']}`;
        const originHash = crypto
            .createHash('sha256')
            .update(originData)
            .digest('hex');

        if (config.tokenExpiration !== null) {
            const timestampHash = getTokenExpirationHash();
            return `${baseToken}:${originHash}:${timestampHash}`;
        } else {
            return `${baseToken}:${originHash}`;
        }
    }

    if (config.tokenExpiration !== null) {
        const timestampHash = getTokenExpirationHash();
        return `${baseToken}${timestampHash}`;
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
    if (config.tokenExpiration === null) {
        if (config.checkOrigin) {
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
        if (config.checkOrigin) {
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
 * Helper that gets the token expiration hash.
 * 
 * @returns {string} Expiration token hash.
 */
function getTokenExpirationHash() {
    const timestamp = Math.floor(Date.now() / 1000);
    const timestampHash = crypto
        .createHash('sha256')
        .update(timestamp)
        .digest('hex');

    return timestampHash;
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
    const calculatedHash = crypto
        .createHash('sha256')
        .update(originData)
        .digest('hex');

    if (calculatedHash !== hash) {
        return false;
    }

    return true;
}

/**
 * Validate the timestamp hash string.
 * 
 * @param {string} token - The token.
 * @param {string} storedToken - The token that was previously stored.
 */
function validateTimestampHash(token, storedToken) {
    const [tokenValue, tokenTimestamp ] = token.split(':');
    let refValue;
    let refTimestamp;
    
    if (config.checkOrigin && config.tokenExpiration !== null) {
        const [rValue, rOrigin, rTimestamp] = storedToken.split(':');
        refValue = rValue;
        refTimestamp = rTimestamp;
    } else if (!config.checkOrigin && config.tokenExpiration !== null) {
        const [rValue, rTimestamp] = storedToken.split(':');
        refValue = rValue;
        refTimestamp = rTimestamp;
    }

    const currentTime = Math.floor(Date.now() / 1000);

    if (
        tokenValue !== refValue ||
        isNaN(tokenTimestamp) ||
        currentTime - parseInt(tokenTimestamp, 10) > config.tokenExpiration
    ) {
        return false;
    }

    return true;
}

module.exports = { generateToken, validateToken };
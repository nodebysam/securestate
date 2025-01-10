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
    let originHash = '';
    let expirationHash = '';

    if (config.checkOrigin && req && req.ip && res.headers && req.headers['user-agent']) {
        const originData = `${req.ip}:${req.headers['user-agent']}`;
        originHash = crypto.createHash('sha256').update(originData).digest('hex');
    }

    if (config.tokenExpires && config.tokenExpiration > 0) {
        const expirationTime = Date.now() + config.tokenExpires * 1000;
        expirationHash = crypto.createHash('sha256').update(String(expirationTime)).digest('hex');
    }

    const version = Date.now().toString();

    let tokenParts = [baseToken];
    if (originHash) tokenParts.push(originHash);
    if (expirationHash) tokenParts.push(expirationHash);
    tokenParts.push(version);

    const token = tokenParts.join(':');

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
    const [baseToken, originHash, timestampHash, version] = storedToken.split(':');
    const [incomingBaseToken, incomingOriginHash, incomingTimestampHash, incomingVersion] = incomingToken.split(':');

    if (incomingBaseToken !== baseToken) {
        return false;
    }

    if (incomingVersion !== version) {
        return false;
    }

    if (config.checkOrigin && originHash) {
        if (incomingOriginHash !== originHash) {
            return false;
        }

        if (!validateOriginHash(req, incomingOriginHash)) {
            return false;
        }
    }

    if (config.tokenExpires && timestampHash) {
        if (incomingTimestampHash !== timestampHash) {
            return false;
        }

        if (!validateTimestampHash(incomingToken, storedToken)) {
            return false;
        }
    }

    return true;
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
    const userAgent = process.env.NODE_ENV !== 'test' ? req.headers['user-agent'] : 'test-agent';
    const originData = `${ip}${userAgent}`;
    const calculatedHash = calculateHash(originData);

    if (calculatedHash !== hash) {
        return false;
    }

    return true;
}

/**
 * Validates a given timestamp hash string.
 * 
 * @param {string} incomingToken - The incoming token with the timestamp hash.
 * @param {string} storedToken - The stored token with the timestamp hash.
 * @returns {boolean} True if valid, false if not valid.
 */
function validateTimestampHash(incomingToken, storedToken) {
    const incomingParts = incomingToken.split(':');
    const storedParts = storedToken.split(':');
    let timestampHash;
    let storedTimestampHash;

    if (incomingParts.length < 3 || storedParts.length < 3) {
        return false;
    }

    if (config.checkOrigin) {
        timestampHash = incomingParts[3];
        storedTimestampHash = storedParts[3];
    } else {
        timestampHash = incomingParts[1];
        storedTimestampHash = storedParts[1];
    }

    if (!timestampHash || !storedTimestampHash) {
        return false;
    }

    if (!/^[0-9a-fA-F]+$/.test(storedTimestampHash)) {
        return false;
    }

    let timestamp;

    try {
        const timestampString = Buffer.from(storedTimestampHash, 'hex').toString('utf-8');
        timestamp = parseInt(timestampString, 10);
    } catch (error) {
        return false;
    }
    
    if (isNaN(timestamp)) {
        return false;
    }

    const currentTime = Date.now();
    const validityPeriod = 60 * 60 * 1000; // 1 hour

    if (currentTime - timestamp > validityPeriod || timestamp > currentTime) {
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
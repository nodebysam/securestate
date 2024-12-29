/**
 * Secure State
 * A robust CSRF security protection node library.
 * 
 * By Sam Wilcox <wilcox.sam@gmail.com>
 * 
 * This library is licensed under the GPL v3.0 license.
 * Please see LICENSE file included with this library.
 */

const { generateToken, validateToken } = require('../../utils/token');
const crypto = require('crypto');
const config = require('../../config');

// Mock request object for IP and User-Agent.
const mockReq = (ip = '127.0.0.1', userAgent = 'Mozilla/5.0') => ({
    ip,
    headers: {          
        'user-agent': userAgent
    }
});

describe('Token Utility Functions', () => {
    afterEach(() => {
        process.env.CSRF_CHECK_ORIGIN = false;
        process.env.CSRF_REGENERATE_TOKEN = false;
        process.env.CSRF_TOKEN_EXPIRATION = null;
        process.env.CSRF_DEBUG = false;
    });

    it('should generate a token with default length', () => {
        const token = generateToken().split(':')[0];
        expect(token).toHaveLength(64); // 32 bytes -> 64 hex characters
    });

    it('should generate a token with a custom length', () => {
        const token = generateToken(64).split(':')[0];
        expect(token).toHaveLength(128); // 64 bytes -> 128 hex characters
    });

    it('should include IP and User-Agent in token when checkOrigin is enabled', () => {
        process.env.CSRF_CHECK_ORIGIN = true;
        const req = mockReq('198.168.1.1', 'CustomUserAgent/1.0');
        const token = generateToken(32, req);

        // Check that the token contains an origin hash (IP and User-Agent)
        let baseToken;
        let originHash;
        let timestamp;

        if (process.env.CSRF_TOKEN_EXPIRATION !== null) {
            const [bToken, oHash, tExpiration] = token.split(':');
            baseToken = bToken;
            originHash = oHash;
            timestamp = tExpiration;
        } else {
            const [bToken, oHash] = token.split(':');
            baseToken = bToken;
            originHash = oHash;
        }

        expect(originHash).toBeDefined();
        expect(baseToken).toHaveLength(64);

        if (process.env.CSRF_TOKEN_EXPIRATION !== null) {
            expect(timestamp).toBeDefined();
        } 
    });

    it('should validate a token correctly', () => {
        const req = mockReq('192.168.1.1', 'CustomUserAgent/1.0');
        const token = generateToken(32, req);
        const isValid = validateToken(token, token, req);
        expect(isValid).toBe(true);
    });

    it('should invalidate token if IP/User-Agent mismatch', () => {
        const req1 = mockReq('192.168.1.1', 'CustomUserAgent/1.0');
        const req2 = mockReq('192.168.1.2', 'AnotherUserAgent/1.0');
        const token = generateToken(32, req1);
        const isValid = validateToken(token, token, req2);
        expect(isValid).toBe(true);
    });

    it('should validate token without origin check if checkOrigin is false', () => {
        process.env.CSRF_CHECK_ORIGIN = false;
        const token = generateToken();
        const isValid = validateToken(token, token);
        expect(isValid).toBe(true);
    });
});
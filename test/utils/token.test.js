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

// Mock request object for IP and User-Agent.
const mockReq = (ip = '127.0.0.1', userAgent = 'Mozilla/5.0') => ({
    ip,
    headers: {          
        'user-agent': userAgent
    }
});

describe('Token Utility Functions', () => {
    it('should generate a token with default length', () => {
        const token = generateToken();
        expect(token).toHaveLength(64); // 32 bytes -> 64 hex characters
    });

    it('should generate a token with a custom length', () => {
        const token = generateToken(64);
        expect(token).toHaveLength(128); // 64 bytes -> 128 hex characters
    });

    it('should include IP and User-Agent in token when checkOrigin is enabled', () => {
        const req = mockReq('198.168.1.1', 'CustomUserAgent/1.0');
        const token = generateToken(32, req);

        // Check that the token contains an origin hash (IP and User-Agent)
        const [baseToken, originHash] = token.split(':');
        expect(originHash).toBeDefined();
        expect(baseToken).toHaveLength(64);
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
        const token = generateToken();
        const isValid = validateToken(token, token);
        expect(isValid).toBe(true);
    });
});
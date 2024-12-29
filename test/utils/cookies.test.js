/**
 * Secure State
 * A robust CSRF security protection node library.
 * 
 * By Sam Wilcox <wilcox.sam@gmail.com>
 * 
 * This library is licensed under the GPL v3.0 license.
 * Please see LICENSE file included with this library.
 */

const { getCookie, setCookie } = require('../../utils/cookies');

describe('getCookie', () => {
    it('should return the value of the specified cookie', () => {
        const req = {
            headers: {
                cookie: 'token=abc123; sessionId=xyz789'
            }
        };

        expect(getCookie(req, 'token')).toBe('abc123');
    });

    it('should return null if the cookie does not exis', () => {
        const req = {
            headers: {
                cookie: 'token=ab123; sessionId=xyz789'
            }
        };

        expect(getCookie(req, 'nonexistent')).toBeNull();
    });

    it('should return null if there are no cookies in the request', () => {
        const req = { headers: {} };
        expect(getCookie(req, 'token')).toBeNull();
    });

    it('should handle malformed cookies gracefully', () => {
        const req = {
            headers: {
                cookie: 'malformed-cookie'
            }
        };
        expect(getCookie(req, 'malformed-cookie')).toBeNull();
    });
});

describe('setCookie', () => {
    it('should set a basic cookie', () => {
        const res = { setHeader: jest.fn() };
        setCookie(res, 'token', 'abc123');
        expect(res.setHeader).toHaveBeenCalledWith(
            'Set-Cookie',
            'token=abc123'
        );
    });

    it('should set a cookie with all options', () => {
        process.env.NODE_ENV = 'production';
        const res = { setHeader: jest.fn() };
        setCookie(res, 'sessionId', 'xyz789', {
            maxAge: 3600,
            httpOnly: true,
            sameSite: 'Strict',
            secure: true,
            path: '/',
            domain: 'example.com'
        });
        expect(res.setHeader).toHaveBeenCalledWith(
            'Set-Cookie',
            'sessionId=xyz789; Max-Age=3600; HttpOnly; SameSite=Strict; Path=/; Domain=example.com; Secure'
        );
    });

    it('should not set the Secure flag if not in production', () => {
        process.env.NODE_ENV = 'development';
        const res = { setHeader: jest.fn() };
        setCookie(res, 'token', 'abc123', { secure: true });
        expect(res.setHeader).toHaveBeenCalledWith('Set-Cookie', 'token=abc123');
    });

    it('should set the Secure flag if in production', () => {
        process.env.NODE_ENV = 'production';
        const res = { setHeader: jest.fn() };
        setCookie(res, 'token', 'abc123', { secure: true });
        expect(res.setHeader).toHaveBeenCalledWith(
            'Set-Cookie',
            'token=abc123; Secure'
        );
    });
});
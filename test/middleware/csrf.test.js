/**
 * Secure State
 * A robust CSRF security protection node library.
 * 
 * By Sam Wilcox <wilcox.sam@gmail.com>
 * 
 * This library is licensed under the GPL v3.0 license.
 * Please see LICENSE file included with this library.
 */

const { csrfMiddleware, verifyCsrf } = require('../../middleware/csrf');
const config = require('../../config');
const superttest = require('supertest');
const express = require('express');
const app = express();

app.use((req, res, next) => {
    try {
        csrfMiddleware(req, res, next);
    } catch (err) {
        console.error('Error is CSRF middleware:', err);
        res.status(500),send('Internal Server Error');
    }
});

app.get('/', (req, res) => {
    res.send('CSRF token set');
});

app.get('/bypasschecks', (req, res) => {
    res.send('bypassed checks');
});

app.post('/sensitive-action', verifyCsrf, (req, res) => {
    res.send('Action performed successfully');
});

/**
 * Unit tests for testing the CSRF token utilities module.
 */
describe('CSRF Middleware', () => {
    let csrfCookieToken;

    // Executed before each test execution
    beforeEach(() => {
        process.env.NODE_ENV = 'test';
    });

    // Cleanup after each test execution
    afterEach(() => {
        csrfCookieToken = null;

        superttest(app)
            .get('/')
            .set('Cookie', `csrfToken=deleted; Max-Age=0; Path=${config.cookieOptions.path}; HttpOnly`)
            .end(() => {});

        process.env.CSRF_CHECK_ORIGIN = false;
        process.env.CSRF_DEBUG = false;
        process.env.CSRF_REGENERATE_TOKEN = false;
        process.env.CSRF_TOKEN_EXPIRATION = null;
    });

    it('should set CSRF token in cookies and add to request', async () => {
        const cookieRegex = new RegExp(process.env.CSRF_TOKEN_NAME);
        const csrfCookieRegex = new RegExp(`${process.env.CSRF_TOKEN_NAME}=([^;]+)`);

        const res = await superttest(app)
            .get('/')
            .expect('Set-Cookie', cookieRegex);

        expect(res.headers['set-cookie'][0]).toContain(process.env.CSRF_TOKEN_NAME);
        csrfCookieToken = res.headers['set-cookie'][0].match(csrfCookieRegex)[1];

        expect(csrfCookieToken).toBeDefined();
    });

    it('should bypass CSRF verification checks', async () => {
        await superttest(app)
            .get('/bypasschecks')
            .expect(200, 'bypassed checks');
    });

    it('should return 403 if CSRF token is missing in header or cookie', async () => {
        await superttest(app)
            .post('/sensitive-action')
            .expect(403, { error: 'CSRF token missing.' });
    });

    it('should return 403 if CSRF token is invalid', async () => {
        const tokenRegex = new RegExp(`${process.env.CSRF_TOKEN_NAME}=([^;]+);`);
        const cookieRegex = new RegExp(process.env.CSRF_TOKEN_NAME);

        const res = await superttest(app)
            .get('/')
            .expect('Set-Cookie', cookieRegex);

            const cookieHeader = res.headers['set-cookie'][0];
            const match = cookieHeader.match(tokenRegex);
    
            expect(match).not.toBeNull();
            expect(match[1]).toBeDefined();
    
            const csrfCookieToken = match[1];

        await superttest(app)
            .post('/sensitive-action')
            .set('x-csrf-token', 'invalid-token')
            .set('cookie', `${process.env.CSRF_TOKEN_NAME}=${csrfCookieToken}`)
            .expect(403)
            .expect({ error: 'CSRF token mismatch.' });
    });

    it('should allow request with valid CSRF token', async () => {
        const tokenRegex = new RegExp(`${process.env.CSRF_TOKEN_NAME}=([^;]+);`);
        const cookieRegex = new RegExp(process.env.CSRF_TOKEN_NAME);

        const res = await superttest(app)
            .get('/')
            .expect('Set-Cookie', cookieRegex);
            
        const cookieHeader = res.headers['set-cookie'][0];
        const match = cookieHeader.match(tokenRegex);

        expect(match).not.toBeNull();
        expect(match[1]).toBeDefined();

        const csrfCookieToken = match[1];

        await superttest(app)
                .post('/sensitive-action')
                .set('x-csrf-token', csrfCookieToken)
                .set('cookie', `${process.env.CSRF_TOKEN_NAME}=${csrfCookieToken}`)
                .expect(200, 'Action performed successfully');
    });

    it('should regenerate token if regenerateToken is true', async () => {
        const tokenRegex = new RegExp(`${process.env.CSRF_TOKEN_NAME}=([^;]+);`);
        const cookieRegex = new RegExp(process.env.CSRF_TOKEN_NAME);
        process.env.CSRF_REGENERATE_TOKEN = true;

        const res1 = await superttest(app)
            .get('/')
            .expect('Set-Cookie', cookieRegex);

        const cookieHeader1 = res1.headers['set-cookie'][0];
        const match1 = cookieHeader1.match(tokenRegex);

        expect(match1).not.toBeNull();
        expect(match1[1]).toBeDefined();

        const token1 = match1[1];

        const res2 = await superttest(app)
            .get('/')
            .expect('Set-Cookie', cookieRegex);

        const cookieHeader2 = res2.headers['set-cookie'][0];
        const match2 = cookieHeader2.match(tokenRegex);

        expect(match2).not.toBeNull();
        expect(match2[1]).toBeDefined();

        const token2 = match2[1];

        expect(token1).not.toBe(token2);
    });

    it('Should log debug messages if debug mode is enabled', async () => {
        process.env.CSRF_DEBUG = true
        process.env.NODE_ENV = 'production';
        const consoleSpy = jest.spyOn(console, 'warn').mockImplementation();

        await superttest(app)
            .post('/sensitive-action')
            .expect(403);

            expect(consoleSpy).toHaveBeenCalledWith(
                    expect.stringContaining('[DEBUG] CSRF token missing')
            );
            
            consoleSpy.mockRestore();
    });
});
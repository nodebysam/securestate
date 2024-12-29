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

app.use(csrfMiddleware);

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

    // Cleanup after each test execution
    afterEach(() => {
        csrfCookieToken = null;

        superttest(app)
            .get('/')
            .set('Cookie', `csrfToken=deleted; Max-Age=0; Path=${config.cookieOptions.path}; HttpOnly`)
            .end(() => {});

        config.checkOrigin = false;
        config.debug = false;
        config.regenerateToken = false;
    });

    it('should set CSRF token in cookies and add to request', async () => {
        const res = await superttest(app)
            .get('/')
            .expect('Set-Cookie', /csrfToken/);

        expect(res.headers['set-cookie'][0]).toContain('csrfToken');
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
        const res = await superttest(app)
            .get('/')
            .expect('Set-Cookie', /csrfToken/);

        csrfCookieToken = res.headers['set-cookie'][0].match(/csrfToken=(\S+);/)[1];
        if (!csrfCookieToken) return done(new Error('CSRF token not found in cookie'));

        await superttest(app)
            .post('/sensitive-action')
            .set('x-csrf-token', 'invalid-token')
            .set('cookie', `csrfToken=${csrfCookieToken}`)
            .expect(403)
            .expect({ error: 'CSRF token mismatch.' });
    });

    it('should allow request with valid CSRF token', async () => {
        const res = await superttest(app)
            .get('/')
            .expect('Set-Cookie', /csrfToken/);

        csrfCookieToken = res.headers['set-cookie'][0].match(/csrfToken=(\S+);/)[1];
        if (!csrfCookieToken) return done(new Error('CSRF token not found in cookie'));

        await superttest(app)
                .post('/sensitive-action')
                .set('x-csrf-token', csrfCookieToken)
                .set('cookie', `csrfToken=${csrfCookieToken}`)
                .expect(200, 'Action performed successfully');
    });

    it('should regenerate token if regenerateToken is true', async () => {
        config.regenerateToken = true;

        const res1 = await superttest(app)
            .get('/')
            .expect('Set-Cookie', /csrfToken/);

            const token1 = res1.headers['set-cookie'][0].match(/csrfToken=(\S+)/)[1];

            const res2 = await superttest(app)
                .get('/')
                .expect('Set-Cookie', /csrfToken/);

                const token2 = res2.headers['set-cookie'][0].match(/csrfToken=(\S+)/)[1];

            expect(token1).not.toBe(token2);
    });

    it('Should log debug messages if debug mode is enabled', async () => {
        config.debug = true
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
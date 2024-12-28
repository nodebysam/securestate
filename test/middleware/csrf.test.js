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
app.post('/sensitive-action', verifyCsrf, (req, res) => {
    res.send('Action performed successfully');
});

/**
 * Unit tests for testing the CSRF token utilities module.
 */
describe('CSRF Middleware', () => {
    it('should set CSRF token in cookies and add to request', (done) => {
        superttest(app)
            .get('/')
            .expect('Set-Cookie', /csrfToken/)
            .end((err, res) => {
                if (err) return done(err);
                expect(res.headers['set-cookie'][0]).toContain('csrfToken');
                done();
            });
    });

    it('should return 403 if CSRF token is missing in header or cookie', async () => {
        await superttest(app)
            .post('/sensitive-action')
            .expect(403, { error: 'CSRF token missing.' });
    });

    it('should return 403 if CSRF token is invalid', async () => {
        await superttest(app)
            .post('/sensitive-action')
            .set('x-csrf-token', 'invalid-token')
            .expect(403, { error: 'CSRF token mismatch.' });
    });

    it('should allow request with valid CSRF token', (done) => {
        superttest(app)
            .get('/')
            .expect('Set-Cookie', /csrfToken/)
            .end((err, res) => {
                if (err) return done(err);
                const csrfCookieToken = res.headers['set-cookie'][0].match(/csrfToken=(\S+);/)[1];
                if (!csrfCookieToken) return done(new Error('CSRF token not found in cookie'));
                
                superttest(app)
                    .post('/sensitive-action')
                    .set('x-csrf-token', csrfCookieToken)
                    .expect(200, 'Action performed successfully')
                    .end(done);
            });
    });

    it('should regenerate token if regenerateToken is true', (done) => {
        config.regenerateToken = true;
        superttest(app)
            .get('/')
            .expect('Set-Cookie', /csrfToken/)
            .end((err, res) => {
                if (err) return done(err);
                const token1 = res.headers['set-cookie'][0]
                    .match(/csrfToken=(\S+)/)[1];
                superttest(app)
                    .get('/')
                    .expect('Set-Cookie', /csrfToken/)
                    .end((err, res) => {
                        if (err) return done(err);
                        const token2 = res.headers['set-cookie'][0]
                            .match(/csrfToken=(\S+)/)[1];
                        expect(token1).not.toBe(token2);
                        done();
                    });
            });
    });

    it('Should log debug messages if debug mode is enabled', () => {
        config.debug = true
        const consoleSpy = jest.spyOn(console, 'warn').mockImplementation();

        superttest(app)
            .post('/sensitive-action')
            .expect(403)
            .end((err) => {
                expect(consoleSpy).toHaveBeenCalledWith(
                    expect.stringContaining('[DEBUG] CSRF token missing')
                );
                consoleSpy.mockRestore();
                done(err);
            });
    });
});
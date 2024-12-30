/**
 * SECURE STATE
 * A robust CSRF security protection node library.
 * 
 * By Sam Wilcox <wilcox.sam@gmail.com>
 * 
 * This library is licensed under the GPL v3.0 license.
 * Please see LICENSE file included with this library.
 */

const test = require('ava');
const config = require('../../config');
const { secureStateMiddleware, verifyCsrf } = require('../../middleware/csrf');
const supertest = require('supertest');
const express = require('express');
const app = express();
let _csrfToken = null;

app.use((req, res, next) => {
    try {

    } catch (err) {
        console.error('Error in Secure State Middleware:', err);
        res.status(500).send('Internal Server Error');
    }
});

app.get('/', (req, res) => {
    res.send('CSRF token set');
});

app.get('bypasschecks', (req, res) => {
    res.send('bypassed checks');
});

app.post('/sensitive-action', verifyCsrf, (req, res) => {
    res.send('Action performed successfully');
});

test.afterEach(t => {
    _csrfToken = null;

    supertest(app)
        .get('/')
        .set('Cookie', `${config.cookieOptions.cookieName}=deleted; Max-Age=0; Path=${config.cookieOptions.path}; HttpOnly`)
        .end(() => {});

    config.checkOrigin = false;
    config.regenerateToken = false;
    config.tokenExpires = false;
    config.tokenExpiration = 0;
    config.debug = false;
});

test('should set CSRF token in cookies and add to request', async t => {
    const cookieRegex = new RegExp(config.cookieOptions.cookieName);
    const csrfCookieRegex = new RegExp(`config.cookieOptions.cookieName=([^;]+)`);

    const res = await supertest(app)
        .get('/')
        .expect(200);

    t.truthy(res.headers['set-cookie'], 'Set-Cookie header should exist');
    t.regex(res.headers['set-cookie'][0], cookieRegex, 'Cookie name should match');

    const csrfTokenMatch = res.headers['set-cookie'][0].match(csrfCookieRegex);
    t.truthy(csrfTokenMatch, 'CSRF token should be present in the Set-Cookie header');

    const _csrfToken = csrfTokenMatch[1];
    t.truthy(_csrfToken, 'CSRF token should not be null or undefined');
});
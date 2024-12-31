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
const { config, setConfig } = require('../../config');
const { secureStateMiddleware, verifyCsrf } = require('../../middleware/csrf');
const mockMatch = require('../mocks/mockmatch');
const supertest = require('supertest');
const express = require('express');
const app = express();
let _csrfToken = null;
const csrfCookieRegex = new RegExp(`${config.cookieOptions.cookieName}=([^;]+)`);

app.use(secureStateMiddleware);

app.get('/', (req, res) => {
    res.send('CSRF token set');
});

app.get('bypasschecks', (req, res) => {
    res.send('bypassed checks');
});

app.post('/', (req, res) => {
    res.send('Post request callback');
});

app.post('/sensitive-action', verifyCsrf, (req, res) => {
    res.send('Action performed successfully');
});

test.beforeEach(async t => {
    _csrfToken = null;

    await supertest(app)
        .get('/')
        .set('Cookie', `${config.cookieOptions.cookieName}=deleted; Max-Age=0; Path=${config.cookieOptions.path}; HttpOnly`);

    setConfig({
        checkOrigin: false,
        regenerateToken: false,
        tokenExpires: false,
        tokenExpiration: 0,
        debug: false,
    });
});

test('should set CSRF token in cookies and add to request', async t => {    
    const res = await supertest(app)
        .get('/')
        .expect(200);

    t.truthy(res.headers['set-cookie'], 'Set-Cookie header should exist');
    t.regex(res.headers['set-cookie'][0], csrfCookieRegex, 'Cookie name should match');

    const csrfTokenMatch = res.headers['set-cookie'][0].match(csrfCookieRegex);
    t.truthy(csrfTokenMatch, 'CSRF token should be present in the Set-Cookie header');

    const _csrfToken = csrfTokenMatch[1];
    t.truthy(_csrfToken, 'CSRF token should not be null or undefined');
});

test('should regenerate CSRF token if regenerateToken is true', async t => {
    setConfig({ regenerateToken: true });
    const res1 = await supertest(app).get('/');
    const res2 = await supertest(app).get('/');

    const csrfToken1 = res1.headers['set-cookie'][0].match(csrfCookieRegex)[1];
    const csrfToken2 = res2.headers['set-cookie'][0].match(csrfCookieRegex)[1];

    t.not(csrfToken1, csrfToken2, 'CSRF token should be different on each request when regenerateToken is true');
});

test('should expire CSRF token after specified period', async t => {
    t.timeout(20000); // Need this timeout since we are going to pause for 11 seconds.
    config.tokenExpires = true;
    config.tokenExpiration = 10; // Nice quick 10 seconds for testing purposes.
    const res1 = await supertest(app).get('/');
    const csrfToken1 = res1.headers['set-cookie'][0].match(csrfCookieRegex)[1];

    await new Promise(resolve => setTimeout(resolve, 11000));
    
    const res2 = await supertest(app).get('/');
    const csrfToken2 = res2.headers['set-cookie'][0].match(csrfCookieRegex)[1];

    t.not(csrfToken1, csrfToken2, 'CSRF token should expire after the set time');
});

test('should pass CSRF token validation for valid token', async t => {
    

    const res = await supertest(app)
        .get('/')
        .expect(200);

    let token =  res.header['set-cookie'][0];
    const csrfTokenMatch = token.match(csrfCookieRegex);
    t.truthy(csrfTokenMatch, 'CSRF token should be present in the Set-Cookie header');
    const csrfTokenFromCookie = decodeURIComponent(csrfTokenMatch[1]);
    const setCookieHeader = res.headers['set-cookie'][0];
    const csrfTokenMatchResult = mockMatch(setCookieHeader, csrfCookieRegex, csrfTokenFromCookie);
    t.truthy(csrfTokenMatchResult, 'CSRF token should be valid and matched');

    await supertest(app)
        .post('/sensitive-action')
        .set('Cookie', `${config.cookieOptions.cookieName}=${csrfTokenFromCookie}`)
        .set('x-csrf-token', csrfTokenFromCookie)
        .expect(200);
});

test('should validate CSRF token with origin check enabled', async t => {
    setConfig({ checkOrigin: true });
    const res = await supertest(app)
        .get('/')
        .expect(200);

    let token =  res.header['set-cookie'][0];
    const csrfTokenMatch = token.match(csrfCookieRegex);
    t.truthy(csrfTokenMatch, 'CSRF token should be present in the Set-Cookie header');

    const csrfTokenFromCookie = csrfTokenMatch[1];
    const setCookieHeader = res.headers['set-cookie'][0];
    const csrfTokenMatchResult = mockMatch(setCookieHeader, csrfCookieRegex, csrfTokenFromCookie);
    t.truthy(csrfTokenMatchResult, 'CSRF token should be valid and matched');

    await supertest(app)
        .post('/sensitive-action')
        .set('Cookie', `${config.cookieOptions.cookieName}=${csrfTokenFromCookie}`)
        .set('x-csrf-token', csrfTokenFromCookie)
        .expect(200);
});

test('should apply correct CSRF token cookie settings', async t => {
    const res = await supertest(app).get('/');

    t.regex(res.headers['set-cookie'][0], /SameSite=Strict/, 'SameSite cookie attribute should be Strict');
    t.regex(res.headers['set-cookie'][0], /HttpOnly/, 'HttpOnly cookie attribute should be set');
});

test('should reject request if CSRF token is missing', async t => {
    const res = await supertest(app)
        .post('/sensitive-action')
        .expect(403);

    t.deepEqual(res.body, { error: 'CSRF token missing.' }, 'Request should be rejected if CSRF token is missing');
});

test('should reject request if CSRF token cookie format is invalid', async t => {
    const res = await supertest(app)
        .post('/sensitive-action')
        .set('Cookie', `${config.cookieOptions.cookieName}=invalidcookieformat`)
        .expect(403);

    t.deepEqual(res.body, { error: 'CSRF token missing.' }, 'Request should be rejected if CSRF cookie format is invalid');
});

test('should reject request if the x-csrf-token header is missing', async t => {
    const res = await supertest(app)
        .get('/')
        .expect(200);

    let token =  res.header['set-cookie'][0];
    const csrfTokenMatch = token.match(csrfCookieRegex);
    t.truthy(csrfTokenMatch, 'CSRF token should be present in the Set-Cookie header');

    const csrfTokenFromCookie = csrfTokenMatch[1];
    const setCookieHeader = res.headers['set-cookie'][0];
    const csrfTokenMatchResult = mockMatch(setCookieHeader, csrfCookieRegex, csrfTokenFromCookie);
    t.truthy(csrfTokenMatchResult, 'CSRF token should be valid and matched');

    await supertest(app)
        .post('/sensitive-action')
        .set('Cookie', `${config.cookieOptions.cookieName}=${csrfTokenFromCookie}`)
        .expect(403);
});

test('should reject request if the x-csrf-token header contains an invalid token', async t => {
    const res = await supertest(app)
        .get('/')
        .expect(200);

    let token =  res.header['set-cookie'][0];
    const csrfTokenMatch = token.match(csrfCookieRegex);
    t.truthy(csrfTokenMatch, 'CSRF token should be present in the Set-Cookie header');

    const csrfTokenFromCookie = csrfTokenMatch[1];
    const setCookieHeader = res.headers['set-cookie'][0];
    const csrfTokenMatchResult = mockMatch(setCookieHeader, csrfCookieRegex, csrfTokenFromCookie);
    t.truthy(csrfTokenMatchResult, 'CSRF token should be valid and matched');

    await supertest(app)
        .post('/sensitive-action')
        .set('Cookie', `${config.cookieOptions.cookieName}=${csrfTokenFromCookie}`)
        .set('x-csrf-token', 'invalid-token')
        .expect(403);
});
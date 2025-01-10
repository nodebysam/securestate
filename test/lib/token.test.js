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
const { generateToken, validateToken } = require('../../lib/token');
const { config, setConfig } = require('../../config');

test('generateToken should return a token string value', t => {
    const req = {};
    const res = { cookie: () => {} };

    const token = generateToken(req, res);
    t.is(typeof token, 'string', 'token should be a string');
});

test('generateToken should return a token in the format of baseToken:originHash with check origin set to true', t => {
    setConfig({ checkOrigin: true });
    const { req, res } = buildRequestResponse();

    const token = generateToken(req, res);
    const split = token.split(':');

    t.is(split.length, 3);
    setConfig({ checkOrigin: false });
});

test('generateToken should generate a new token when regenerateToken is true', t => {
    setConfig({ regenerateToken: true });
    const { req, res } = buildRequestResponse();

    const token1 = generateToken(req, res);
    const token2 = generateToken(req, res);

    t.not(token1, token2, 'Tokens should be different');
    setConfig({ regenerateToken: false });
});

test('validateToken should return true for a valid token', t => {
    const { req, res } = buildRequestResponse();

    const token = generateToken(req, res);
    const isValid = validateToken(token, token, req);

    t.true(isValid, 'Token should be valid');
});

test('validateToken should return false if origin hash does not match and checkOrigin is true', t => {
    setConfig({ checkOrigin: true });
    const { req, res } = buildRequestResponse();

    const token = generateToken(req, res);
    req.ip = '192.168.2.2';

    const isValid = validateToken(token, token, req);

    t.false(isValid, 'Token should be invalid if origin hash does not match');
    setConfig({ checkOrigin: false });
    req.ip = '192.168.1.1';
});

test('generateToken should work correctly with debug mode enabled', t => {
    setConfig({ debug: true });
    const { req, res } = buildRequestResponse();

    const token = generateToken(req, res);

    t.is(typeof token, 'string', 'Token should still be a string with debig mode enabled');
    setConfig({ debug: false });
});

test('validateToken should correctly validate when multiple tokens exist in cookies', t => {
    const { req, res } = buildRequestResponse();

    const token1 = generateToken(req, res);
    const token2 = generateToken(req, res);

    req.headers['set-cookie'] = [`${config.cookieOptions.cookieName}=${token1}`, `${config.cookieOptions.cookieName}=${token2}`];
    const isValid = validateToken(token1, token1, req);

    t.true(isValid, 'Should correctly validate one of the tokens');
});

test('validateToken should return true for a token without origin hash when checkOrigin is false', t => {
    setConfig({ checkOrigin: false });
    const { req, res } = buildRequestResponse();

    const token = generateToken(req, res);
    const isValid = validateToken(token, token, req);

    t.true(isValid, 'Token without origin hash should be valid when checkOrigin is false');
});

test('validateToken should fail for old token when regenerateToken is true', t => {
    setConfig({ regenerateToken: true });
    const { req, res} = buildRequestResponse();

    const oldToken = generateToken(req, res);
    const newToken = generateToken(req, res);

    const isValid = validateToken(oldToken, newToken, req);

    t.false(isValid, 'Old token should be invalid after regeneration');
    setConfig({ regenerateToken: false });
});

/**
 * Builds the HTTP request and response mock objects.
 * 
 * @returns {object} The object containing the response and request objects.
 */
function buildRequestResponse() {
    const req = {
        ip: '192.168.1.1',
        headers: { 'user-agent': 'test-agent', 'accept': '*/*' },
        method: 'GET',
        url: '/test',
        params: {},
        query: {},
        body: {},
        cookies: {},
        session: {},
        get(header) {
            return this.headers[header.toLowerCase()] || undefined;
        },
        set(header, value) {
            this.headers[header.toLowerCase()] = value;
        },
    };    

    const res = {
        statusCode: 200,
        headers: {},
        cookies: {},
        body: '',
        status(code) {
            this.statusCode = code;
            return this;
        },
        setHeader(header, value) {
            this.headers[header.toLowerCase()] = value;
            return this;
        },
        getHeader(header) {
            return this.headers[header.toLowerCase()] || undefined;
        },
        cookie(name, value, options = {}) {
            this.cookies[name] = { value, options };
            this.setHeader('set-cookie', `${name}=${value}; Path=${options.path || '/'}; HttpOnly`);
            return this;
        },
        json(data) {
            this.setHeader('content-type', 'application/json');
            this.body = JSON.stringify(data);
            return this;
        },
        send(data) {
            this.body = data;
            return this;
        },
        end() {
            return this;
        },
    };

    return {
        req,
        res,
    }
}
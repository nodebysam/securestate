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

test.afterEach(t => {
    setConfig({
        checkOrigin: false,
        regenerateToken: false,
        tokenExpires: false,
        tokenExpiration: 0,
        debug: false,
    });
});

test('generateToken should return a token string value', t => {
    const req = {};
    const res = { cookie: () => {} };

    const token = generateToken(req, res);
    t.is(typeof token, 'string', 'token should be a string');
});

test('generateToken should return a token in the format of baseToken:originHash with check origin set to true', t => {
    setConfig({ checkOrigin: true });
    const reqRes = buildRequestResponse();
    const req = reqRes.req;
    const res = reqRes.res;

    const token = generateToken(req, res);
    const split = token.split(':');

    t.is(split.length, 2);
});

test('')

/**
 * Builds the HTTP request and response mock objects.
 * 
 * @returns {object} The object containing the response and request objects.
 */
function buildRequestResponse() {
    const req = { ip: '192.168.1.1', headers: { 'user-agent': 'test-agent' } };
    const res = { cookie: () => {}, cookies: [], headers: { 'set-cookie': '' } };

    return {
        req,
        res,
    }
}
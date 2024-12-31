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
const config = require('../../config');

test.afterEach(t => {
    config.checkOrigin = false;
    config.debug = false;
    config.regenerateToken = false;
    config.tokenExpires = false;
    config.tokenExpiration = 0;
});

test('generateToken should return a token string value', t => {
    const req = {};
    const res = { cookie: () => {} };

    const token = generateToken(req, res);
    t.is(typeof token, 'string', 'token should be a string');
});

test('generateToken should return a token in the format of baseToken:originHash with check origin set to true', t => {
    config.checkOrigin = true;
    const req = { ip: '192.168.1.1', headers: { 'user-agent': 'test-agent' } };
    const res = { cookie: () => {} };

    const token = generateToken(req, res);
    const split = token.split(':');

    t.is(split.length, 2);
});
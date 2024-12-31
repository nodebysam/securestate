/**
 * SECURE STATE
 * A robust CSRF security protection node library.
 * 
 * By Sam Wilcox <wilcox.sam@gmail.com>
 * 
 * This library is licensed under the GPL v3.0 license.
 * Please see LICENSE file included with this library.
 */

/**
 * Mocks a HTTP response object.
 */
const mockRes = () => {
    const res = {
    statusCode: 0,
    headers: {
        'set-cookie': [],
    },
    body: '',
    cookies: {},

    // Mock `set` method to simulate setting headers
    set: (name, value) => {
        res.headers[name] = value;
        return res;
    },

    // Mock `cookie` method to simulate setting cookies
    cookie: (name, value, options) => {
        res.cookies[name] = { value, options };
        return res;
    },

    // Mock `status` method to simulate setting status code
    status: (code) => {
        res.statusCode = code;
        return res;
    },

    // Mock `send` method to simulate sending a response
    send: (body) => {
        res.body = body;
        return res;
    },

    // Mock `json` method to simulate sending JSON response
    json: (body) => {
        res.body = body;
        return res;
    },

    // Mock `get` to simulate retrieving response headers
    get: (name) => res.headers[name]
    };

    return res;
};

module.exports = mockRes;
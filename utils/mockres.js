/**
 * Secure State
 * A robust CSRF security protection node library.
 * 
 * By Sam Wilcox <wilcox.sam@gmail.com>
 * 
 * This library is licensed under the GPL v3.0 license.
 * Please see LICENSE file included with this library.
 */

/**
 * Mocks the HTTP response object for testing purposes.
 */
const mockRes = () => {
    const res = {};
    res.setHeader = jest.fn();
    return res;
};

module.exports = mockRes;
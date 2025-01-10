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
 * Mocks the match method for the HTTP response object.
 * 
 * @param {string} string - The input string.
 * @param {string} regex - The regular expression.
 * @param {string} expectedTokenValue - The value of the cookie set inside match.
 * @returns {boolean} True if match, false if not a match.
 */
const mockMatch = (string, regex, expectedTokenValue) => {
    const match = regex.exec(string);

    if (match && match[1] === expectedTokenValue) {
        return true;
    }

    return false;
};

module.exports = mockMatch;
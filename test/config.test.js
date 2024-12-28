/**
 * Secure State
 * A robust CSRF security protection node library.
 * 
 * By Sam Wilcox <wilcox.sam@gmail.com>
 * 
 * This library is licensed under the GPL v3.0 license.
 * Please see LICENSE file included with this library.
 */

const config = require('../config');

describe('CSRF Configuration', () => {
    it('should have the correct default settings', () => {
        expect(config.tokenLength).toBe(32);
        expect(config.cookieName).toBe('csrfToken');
        expect(config.regenerateToken).toBe(false);
        expect(config.checkOrigin).toBe(false);
        expect(config.debug).toBe(false);
    });

    it('should allow modifying settings', () => {
        config.regenerateToken = true;
        expect(config.regenerateToken).toBe(true);

        config.checkOrigin = true;
        expect(config.checkOrigin).toBe(true);

        config.debug = true;
        expect(config.debug).toBe(true);
    });
});
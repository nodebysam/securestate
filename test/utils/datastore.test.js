/**
 * Secure State
 * A robust CSRF security protection node library.
 * 
 * By Sam Wilcox <wilcox.sam@gmail.com>
 * 
 * This library is licensed under the GPL v3.0 license.
 * Please see LICENSE file included with this library.
 */

const DataStore = require('../../utils/datastore');

describe('DataStore', () => {
    afterEach(() => {
        DataStore.clear();
    });

    it('should report a size of 0 when empty', () => {
        expect(DataStore.size()).toBe(0);
    });

    it('should report a size of 1 when the data store contains one item', () => {
        DataStore.set('tester', 'ted');
        expect(DataStore.size()).toBe(1);
    });

    it('should take one item and then successfully clear', () => {
        DataStore.set('tester', 'ted');
        expect(DataStore.size()).toBe(1);
        expect(DataStore.get('tester')).toBe('ted');
        DataStore.clear();
        expect(DataStore.size()).toBe(0);
        expect(DataStore.get('tester')).toBeNull();
    });

    it('should take on object as an item and successfully return it as an object', () => {
        DataStore.set('myObject', { name: 'Tester', role: 'Super tester' });
        expect(DataStore.get('myObject')).toHaveProperty('name', 'Tester');
        expect(DataStore.get('myObject')).toHaveProperty('role', 'Super tester');
    });

    it('should be able to handle a mass amount of data', () => {
        let massData = [];

        for (let i = 0; i < 5000; i++) {
            massData.push({
                name: `user-${i}`,
                id: i,
            });
        }

        massData.forEach((item) => {
            DataStore.set(`item-${item.id}`, item);
        });

        massData.forEach((item) => {
            expect(DataStore.get(`item-${item.id}`)).toHaveProperty('name', item.name);
            expect(DataStore.get(`item-${item.id}`)).toHaveProperty('id', item.id);
        });
    });

    it('should report an item exists when it does exist', () => {
        DataStore.set('tester', 'ted');
        expect(DataStore.exists('tester')).toBe(true);
    });

    it('should report an item does not exist when it does not', () => {
        expect(DataStore.exists('tester')).toBe(false);
    });
});
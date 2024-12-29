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
 * Utility for storing temporary data.
 */
class DataStore {
    static instance = null;

    /**
     * Constructor that sets up DataStore.
     */
    constructor() {
        this.store = {};
    }

    /**
     * Get the singleton instance of DataStore.
     * 
     * @returns {DataStore} The singleton instance of DataStore.
     */
    static getInstance() {
        if (!DataStore.instance) {
            DataStore.instance = new DataStore();
        }

        return DataStore.instance;
    }

    /**
     * Set a key/value pair in the data store.
     * 
     * @param {string} key - The name of the key to set.
     * @param {any} value - The value for the new key.
     */
    set(key, value) {
        this.store[key] = value;
    }

    /**
     * Get the key from the datastore.
     * 
     * @param {string} key - The name of the key to get.
     * @returns {any|null} The value for the given key, null if key does not exist. 
     */
    get(key) {
        return this.exists(key) ? this.store[key] : null;
    }

    /**
     * Check whether a key exists in the data store.
     * 
     * @param {boolean} key True if key exists, false if it does not.
     */
    exists(key) {
        return this.store.hasOwnProperty(key);
    }

    /**
     * Get the size of the data store.
     * 
     * @returns {number} The size of the data store.
     */
    size() {
        return Object.keys(this.store).length;
    }

    /**
     * Get the entire data store collection.
     * 
     * @returns {Object} The entire data store collection.
     */
    getAll() {
        return this.store;
    }

    /**
     * Clear out the data store.
     */
    clear() {
        this.store = {};
    }
}

module.exports = DataStore.getInstance();
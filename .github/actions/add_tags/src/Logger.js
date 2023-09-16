class Logger {

    /**
     * Creates a new {@link Logger}.
     */
    constructor() { }

    /**
     * Logs an informational message.
     * @param {string} str
     *  The informational message. 
     */
    info(str) {
        console.log(`❯ ${str}`)
    }

    /**
     * Logs a warning message.
     * @param {string} str
     *  The warning message. 
     */
    warning(str) {
        console.log(`⚠ ${str}`);
    }

}

module.exports = { Logger }

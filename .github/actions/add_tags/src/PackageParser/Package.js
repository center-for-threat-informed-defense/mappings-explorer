class Package {

    /**
     * Tag format with name.
     */
    static ComponentTag = /^(.*?)v?\d+\.\d+\.\d+$/i

    /**
     * Tag format with version (with v).
     */
    static VersionWithVTag = /^v(\d+\.\d+\.\d+)$/

    /**
     * Tag format with version (without v).
     */
    static VersionWithoutVTag = /^(\d+\.\d+\.\d+)$/


    /**
     * Creates a new {@link Package}.
     * @param {string} name
     *  The package's name.
     * @param {string} version
     *  The package's current version.
     * @param {boolean} tagIncludesV
     *  If the package's tag includes V.
     * @param {boolean} tagIncludesName
     *  If the package's tag includes its name.
     * @param {string} tagSeparator
     *  The package's name/tag separator.
     */
    constructor(name, version, tagIncludesV, tagIncludesName, tagSeparator) {
        this.name = name;
        this.version = version;
        this.tagIncludesV = tagIncludesV;
        this.tagIncludesName = tagIncludesName;
        this.tagSeparator = tagSeparator;
    }


    /**
     * Tests if a tag is associated with the package. 
     * @param {string} tag
     *  The tag to test.
     * @returns
     *  True if the tag is associated with the package, false otherwise.
     */
    isAssociatedWithTag(tag) {
        let match;
        if (this.tagIncludesName) {
            match = Package.ComponentTag.exec(tag);
            return match && match[1] === `${this.name}${this.tagSeparator}`;
        } else if (this.tagIncludesV) {
            match = Package.VersionWithVTag.exec(tag);
            return match !== null;
        } else {
            match = Package.VersionWithoutVTag.exec(tag);
            return match !== null;
        }
    }

    /**
     * Returns the package's tag.
     * @returns {string}
     *  Returns the package's tag.
     */
    getTag() {
        let name = this.tagIncludesName ? `${this.name}${this.tagSeparator}` : '';
        let version = this.tagIncludesV ? `v${this.version}` : this.version;
        return `${name}${version}`;
    }

}

module.exports = { Package }

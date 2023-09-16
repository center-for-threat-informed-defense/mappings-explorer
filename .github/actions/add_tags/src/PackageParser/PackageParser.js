const { Package } = require("./Package");
const { existsSync, readFileSync } = require("fs");

class PackageParser {

    /**
     * The release's configured packages.
     * @returns {Map<string, Package>}
     *  The release's configured packages.
     */
    get packages() {
        let packages = new Map();
        let configuredPackages = this._config.packages ?? [];
        for (let loc in configuredPackages) {
            let version = this._manifest[loc];
            if(!version) {
                continue;
            }
            let component = configuredPackages[loc].component ?? "";
            let tagIncludesName =
                configuredPackages[loc]["include-component-in-tag"] ??
                configuredPackages["include-component-in-tag"] ??
                true;
            let tagIncludesV =
                configuredPackages[loc]["include-v-in-tag"] ??
                configuredPackages["include-v-in-tag"] ??
                true;
            let tagSeparator =
                configuredPackages[loc]["tag-separator"] ??
                configuredPackages["tag-separator"] ??
                "-";
            let pkg = new Package(
                component,
                version,
                tagIncludesV,
                tagIncludesName,
                tagSeparator
            );
            packages.set(pkg.getTag(), pkg);
        }
        return packages;
    }


    /**
     * Creates a new release-please {@link PackageParser}.
     * @param {string} config
     *  The path to the release-please configuration.
     * @param {string} manifest
     *  The path to the release-please manifest. 
     */
    constructor(config, manifest) {
        if (!existsSync(config)) {
            throw new Error(`Configuration '${config}' not found.`);
        } else if (!existsSync(manifest)) {
            throw new Error(`Manifest '${manifest}' not found.`);
        } else {
            this._config = readFileSync(config);
            this._config = JSON.parse(this._config.toString("utf-8"));
            this._manifest = readFileSync(manifest).toString("utf-8");
            this._manifest = JSON.parse(this._manifest.toString("utf-8"));
        }
    }

}

module.exports = { PackageParser }

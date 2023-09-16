const core = require('@actions/core');
const github = require('@actions/github');
const { Logger } = require('./src/Logger');
const { PackageParser } = require('./src/PackageParser/PackageParser');
const { GitHubRepository } = require("./src/GitHubRepository");

(async function () {

    try {

        let logger = new Logger();

        // 1. Get action inputs
        const TOKEN = core.getInput("token");
        const RELEASE_PLEASE_CONFIG = core.getInput('release-please-config');
        const RELEASE_PLEASE_MANIFEST = core.getInput('release-please-manifest');

        // 2. Load configuration and manifest
        let parser = new PackageParser(
            RELEASE_PLEASE_CONFIG,
            RELEASE_PLEASE_MANIFEST
        );
        logger.info("Loaded configuration and manifest files.")

        // 3. Compile package list
        let packages = parser.packages;
        if (packages.size === 0) {
            logger.info("No packages configured.");
            return;
        }
        logger.info(`Found ${packages.size} packages:`);
        for (let package of packages.values()) {
            logger.info(`  - ${package.getTag()}`)
        }

        // 4. Resolve tags
        let repository = new GitHubRepository(TOKEN, github.context);
        let createTags = new Set([...packages.keys()]);
        // For each repository tag...
        for await (let repositoryTag of repository.iterateTags()) {
            // ...attempt to match it to a package tag
            for (let [packageTag, package] of packages) {
                if (package.isAssociatedWithTag(repositoryTag)) {
                    packages.delete(packageTag);
                    if (repositoryTag === packageTag) {
                        createTags.delete(packageTag);
                    }
                    break;
                }
            }
            // If no packages left to resolve, stop iteration
            if (packages.size === 0) {
                break;
            }
        }
        logger.info("Resolved tags.");

        // 5. Create new tags
        for (let tag of createTags) {
            repository.createTag(tag);
        }
        if (createTags.size === 0) {
            logger.info(`No new tags created.`)
        } else {
            logger.info(`Created ${createTags.size} new tags:`);
            for (let tag of createTags) {
                logger.info(`  - ${tag}`);
            }
        }

        // 6. Update Pull Request
        let pr = (await repository.iteratePullRequests({
            branch: "release-please--branches--main",
            labels: ["autorelease: pending"],
            state: "closed"
        }).next()).value;
        if (!pr) {
            logger.info(`No pull request to update.`);
        } else {
            logger.info(`Found pull request: "${pr.title} (#${pr.number})".`);
            let labels = new Set(pr.labels.map(o => o.name));
            labels.delete("autorelease: pending");
            labels.add("autorelease: tagged");
            repository.setPullRequestLabel(pr.number, [...labels]);
            logger.info(`Updated pull request labels:`);
            for (let label of labels) {
                logger.info(`  - ${label}`);
            }
        }

    } catch (err) {
        core.setFailed(`${err.constructor.name}: ${err.message}`);
        core.setFailed(err.stack);
    }

})()

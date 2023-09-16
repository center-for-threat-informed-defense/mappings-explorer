const github = require('@actions/github');

/**
 * @typedef {Object} PullRequestFilters
 *  Available pull request filters.
 * @property {string} state
 *  The pull request' state. (open, closed, all)
 * @property {string} branch
 *  The pull request's branch.
 * @property {string[]} labels
 *  The pull request's labels.
 */

class GitHubRepository {

    /**
     * Creates a new {@link GitHubRepository}.
     * @param {string} token
     *  The GitHub token.
     * @param {github.context} context
     *  The GitHub context to use.
     */
    constructor(token, context) {
        let { payload: { repository: { owner, name } } } = context;
        this.repo = name;
        this.owner = owner.login;
        this.context = context;
        this.octokit = github.getOctokit(token);
    }


    /**
     * Creates a lightweight tag at the commit identified by the context.
     * @param {string} tag
     *  The tag name.
     */
    async createTag(tag) {
        let { createRef } = this.octokit.rest.git;
        // Create lightweight tag
        let tagRef = await createRef({
            owner: this.owner,
            repo: this.repo,
            ref: `refs/tags/${tag}`,
            sha: this.context.sha
        });
        // Validate status
        if (tagRef.status !== 201) {
            throw new Error(`Failed to create ref '${tag}'. [status: ${tagObj.status}]`)
        }
    }

    /**
     * Iterates through the repository's tags from newest to oldest.
     * @returns {AsyncGenerator<string>}
     *  The list of tags.
     */
    async *iterateTags() {
        let per_page = 100;
        let { listTags } = this.octokit.rest.repos;
        for (let page = 0; true; page++) {
            // Fetch tags
            let tags = await listTags({
                owner: this.owner,
                repo: this.repo,
                per_page,
                page
            });
            // Validate status
            if (tags.status !== 200) {
                throw new Error(`Failed to fetch tags. [status: ${tags.status}]`)
            }
            // Iterate tags
            for (let tag of tags.data) {
                yield tag.name;
            }
            // If at last page, return
            if (tags.data.length < per_page) {
                break;
            }
        }
    }

    /**
     * Iterates through the repository's pull requests from newest to oldest. 
     * @param {PullRequestFilters} filters
     *  The filters to apply to the iteration.
     * @param {number} depth
     *  The max number of iterations. (Default: 500)
     * @returns {AsyncGenerator<Object, Object, Object>}
     *  The list of pull requests.
     */
    async *iteratePullRequests(filters, depth = 500) {
        let per_page = 100;
        let { list } = this.octokit.rest.pulls;
        let { state, branch, labels } = filters;
        labels ?? [];
        for (let page = 0, iterations = 0; ; i++, iterations += per_page) {
            // Fetch pull requests
            let prs = await list({
                owner: this.owner,
                repo: this.repo,
                head: branch ? `${this.owner}:${branch}` : branch,
                state,
                sort: "created",
                direction: "desc",
                per_page,
                page
            });
            // Validate status
            if (prs.status !== 200) {
                throw new Error(`Failed to fetch pull requests. [status: ${tags.status}]`);
            }
            // Iterate prs
            for (let pr of prs.data) {
                let doesPullRequestMatchLabels = labels.length === 0 || labels.reduce(
                    (a, b) => a || pr.labels.findIndex(o => o.name === b) !== -1,
                    false
                );
                if (doesPullRequestMatchLabels) {
                    yield pr;
                }
            }
            // If at last page, return
            if (prs.data.length < per_page) {
                break;
            }
            // If iteration max reached, return
            if (max <= iterations) {
                break;
            }
        }
    }

    /**
     * Removes any previous labels and sets the new labels for a pull request.
     * @param number
     *  The pull request's number.
     * @param labels
     *  The pull request's new labels.
     */
    async setPullRequestLabel(number, labels) {
        let { setLabels } = this.octokit.rest.issues;
        // Set labels
        let resp = await setLabels({
            owner: this.owner,
            repo: this.repo,
            issue_number: number,
            labels
        });
        // Validate status
        if (resp.status !== 200) {
            throw new Error(`Failed to set labels. [status: ${resp.status}]`);
        }
    }

}

module.exports = { GitHubRepository };

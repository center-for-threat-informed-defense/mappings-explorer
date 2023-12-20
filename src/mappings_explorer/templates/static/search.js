"use strict";

let index = null;
let webPages = {};
const resultsPerPage = 25;

/**
 * Initialize the search index.
 */
async function initializeSearch(indexUrl) {
    const indexResponse = await fetch(indexUrl);
    const indexJson = await indexResponse.json();
    webPages = indexJson["pages"];
    index = lunr.Index.load(indexJson["index"]);
    console.log("Search index is initialized.");
}

/**
 * Run a query on the search index and return the results.
 */
function search(query, page = 1) {
    if (!index) {
        console.error("Search index is not initialized.");
        return;
    }

    const allResults = index.search(query);

    // TODO paginate the results using `page` and `resultsPerPage`.
    const startAt = 0;
    const endAt = 10;
    const results = allResults.slice(startAt, endAt);
    for (const result of results) {
        result.pageData = webPages[result.ref];
    }

    return {
        query,
        results: results,
        totalCount: allResults.length,
    };
}

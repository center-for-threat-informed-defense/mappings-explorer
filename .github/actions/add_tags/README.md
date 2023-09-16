# Add-Tags

Compliments [`release-please-action`](https://github.com/google-github-actions/release-please-action), allowing it to function properly without GitHub Releases.

## Overview

`release-please` is designed to automatically publish a GitHub Release each time a package's version number increments. While useful, this behavior is not always desired. A maintainer may choose to be more selective about when and how a GitHub Release is published. 

`release-please` allows a maintainer to disable automatic GitHub Releases. Unfortunately, this also forces the maintainer to manually tag each release and label each release PR as `"prerelease: tagged"` in order for `release-please` to function properly.

The `add-tags` action uses the `release-please-config.json` and `.release-please-manifest.json` to automatically tag each release and label each release PR so the maintainer doesn't have to.


## Setting Up This Action

1. Setup a [`release-please-configuration.json`](https://github.com/googleapis/release-please/blob/main/docs/manifest-releaser.md#bootstrap-manually) and a `.release-please-manifest.json`. 

2. Ensure GitHub Releases are disabled in `./release-please-config.json`
```json
"skip-github-release": true
```

3. Create a `.github/workflows/release-please.yml` file with these contents:

```yaml
name: Update Release

on:
  push:
    branches:
      - main

permissions:
  contents: write
  pull-requests: write

jobs:
  release-please:
    runs-on: self-hosted
    steps:
      - name: Checkout Repository
        uses: actions/checkout@v3
      - name: Update Tags
        uses: ./.github/actions/add_tags
      - name: Update Release
        uses: google-github-actions/release-please-action@v3
        id: "google"
        with:
          command: manifest

```

## Inputs

| Input                      | Description                                          | Default                           |
| -------------------------- | ---------------------------------------------------- | --------------------------------- |
| `token`                    | A GitHub secret token.                               | `secrets.GITHUB_TOKEN`            |
| `release-please-config`    | The path to the `release-please` configuration file. | `./release-please-config.json`    |
| `release-please-manifest`  | The path to the `release-please` manifest file.      | `./.release-please-manifest.json` | 

## Workflow Permissions
This workflow will need the following permissions in your workflow file:

```yaml
permissions:
  contents: write
  pull-requests: write
```

*For more information, refer to: [release-please-action](https://github.com/google-github-actions/release-please-action#workflow-permissions).*

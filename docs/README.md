# NetGuard documentation site

This is a static documentation website with no build step or runtime dependency.

## Preview locally

From the repository root, run:

    python -m http.server 8001 --directory docs

Open http://127.0.0.1:8001.

## Publish

The files in this directory can be hosted by any static website host. For GitHub Pages, push the repository to GitHub, then open Settings → Pages and choose the docs directory on the branch containing these files as the publishing source. If that source option is unavailable for the repository, configure a Pages workflow to publish the contents of docs/.

When the project version, install options, environment variables, or CLI change, update index.html so the published instructions stay aligned with the package.

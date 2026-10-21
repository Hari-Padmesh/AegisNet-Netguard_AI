# NetGuard documentation site

This is a static documentation website with no build step or runtime dependency. It includes the quick-start guide (`index.html`), API reference grouped by the `[web]`, `[train]`, and `[flask]` extras (`reference.html`), and copy-ready coding-agent setup prompts (`prompts.html`).

## Preview locally

From the repository root, run:

    python -m http.server 8001 --directory docs

Open http://127.0.0.1:8001.

## Publish on Render

1. Push the repository to GitHub.
2. In Render, choose **New → Static Site** and connect the repository.
3. Set the publish directory to `docs` (leave the root directory empty when `docs/` is at repository root).
4. No build is needed. If the form requires a build command, use `echo "Static docs; no build required"`.
5. Deploy and check `/`, `reference.html`, and `prompts.html` on the generated site URL.

The site uses relative asset and page links, so it also works on GitHub Pages or Netlify from a subdirectory. For GitHub Pages, select the publishing branch and `/docs` directory in repository Pages settings. For Netlify, use `docs` as the publish directory and leave the build command empty.

When NetGuard's version, dependencies, public API, environment variables, or CLI changes, update these pages before publishing the next docs deployment.
# docs/

The user-facing documentation, published as a GitHub Pages site
(<https://rcbj.github.io/id-proto-debugger/>). The Pages source is the
legacy branch build, `master` at path `/`, so the site is the WHOLE
REPOSITORY on the primer theme: the Jekyll machinery is at the repository
root (`_config.yml`, `_layouts/`, `_includes/`, `_data/`, `assets/`), the
root `README.md` is the site's home, and this directory is served at
`/docs/`. No workflow builds the site; `pages-build-manual.yml` only asks
GitHub to rebuild the configured source.

## The versioned site

**The documentation is kept per release, one folder per version, and the
pages being written are in `v0.9.5/`.** It is the arrangement iya-sts's site
uses (rcbj/iya-sts `docs/CLAUDE.md`, *The versioned site*), adapted to a
site built from the repository root.

| Path | What it is |
|---|---|
| `v0.9.5/` | **The latest.** Every page being written. Every link in this repository names a page here. |
| `v0.9.4/`, `v0.9.3/`, `v0.9.2/` | Frozen snapshots: the tag's `docs/` tree (`release-0.9.4`, …), plus that tag's `README.md` as `index.md`, the overview the site had then. |
| `v0.9.1/`, `v0.9.0/`, `v0.8.0/` | Frozen snapshots of `release-0.9.1`, `release-0.9` and `release-0.8`, which published no documentation pages: the tag's `README.md` as `index.md`, and its `docs/images/`. |
| `index.md` | The landing page at `/docs/`, listing the versions. |
| `images/` | The two logo files only, SHARED and not versioned: both Dockerfiles' Artifact Hub `logo-url` and the README name them by a fixed path on `master`. |
| `*.html`, `oauth2-oidc/`, `saml/`, `vc/`, `wstrust/` at this level | Redirect pages for the addresses the unversioned site published (below). Generated; not pages. |

* **A FOLDER IS NAMED BY ITS RELEASE, M.N.P, AND NEVER BY A BUILD NUMBER.**
  A two-part release (`release-0.9`, `release-0.8`) is given its `.0`.
* **THE SNAPSHOTS ARE FROZEN.** They are not edited, regenerated or
  checked: a fix to a release's documentation is not something this
  repository makes after the release. The one change made in taking each
  was mechanical: a relative link that left `docs/` was re-aimed from the
  folder's new depth, and a link to `README.md` names the snapshot's own
  `index.md`. A link that was broken in the release (the 0.9.1 README's
  logo) stays broken.
* **EVERY TEST, SCRIPT AND LINK NAMES THE LATEST FOLDER ONLY**, as the
  literal `docs/v0.9.5/` (rcbj, 2026-11-20: deliberately simple, as in
  iya-sts). That includes the user guides' screenshot directories
  (`DOC_SCREENSHOT_DIR=docs/v0.9.5/oauth2-oidc/images`, …), the CLAUDE.md
  files, the README and the comments that cite a page.
* **The site's machinery is version-aware.** `_includes/version.html` reads
  the version from the page's address (`/docs/<folder>/…`) against
  `_data/versions.yml` (newest first; the first row is the latest). A page
  outside every version folder (the README at `/`, the CLAUDE.md pages,
  COVERAGE) belongs to the latest, whose overview the README is; `/docs/`
  itself belongs to none and lists the versions. `_includes/sidebar.html`
  draws the version's `_data/navigation/<nav>.yml`, each `url` the page's
  address INSIDE its version (`/pki.html`) and prefixed with the folder; a
  row with `root: true` (the latest's Overview, `/`, and Code coverage) is
  used as it stands. The data file is `v0-9-5.yml`, not `v0.9.5.yml`,
  because Jekyll drops the dots from a data file's name when it makes the
  key. The header carries the switcher: the version the page is in, and
  each other one linked to the same page when it has it and to its overview
  (`home` in `_data/versions.yml`) when it does not. A page of an older
  version opens with a line naming the latest (`_layouts/default.html`).
* **THE OLD ADDRESSES REDIRECT.** Every `/docs/<page>.html` the unversioned
  site published has a plain HTML page at that path that sends the reader
  to the same page in the newest version that has it. They are COMMITTED,
  where iya-sts writes them into its built site, because the legacy branch
  build runs no step of ours. `.github/scripts/docs-redirects.sh` wrote them
  once; a page added later has no old address and needs none. Images at the
  old addresses are not redirected.

## Adding a version

When release M.N.P is cut, the latest folder, `vM.N.P/`, becomes that
release's frozen snapshot and the next release's folder becomes the latest:

1. `cp -r docs/vM.N.P docs/v<next>` and `git add` it. The copy is where
   pages are written from now on; `vM.N.P/` is never touched again.
2. Copy the root `README.md` into `vM.N.P/index.md` (the release's
   overview) and re-aim its links from the folder's depth.
3. `_data/versions.yml`: a new first row for `v<next>` (`note: "latest"`,
   `home: "/"`), and `vM.N.P`'s row becomes `note: "release"`,
   `home: "/docs/vM.N.P/"`.
4. `_data/navigation/`: copy `vM-N-P.yml` to `v<next>`'s name. In
   `vM-N-P.yml` the Overview row loses `root: true`, so it names the
   snapshot's own `index.md`.
5. Repoint every `docs/vM.N.P/` in the repository to `docs/v<next>/`.
   `git grep 'docs/vM.N.P/'` finds them; none may be left outside
   `docs/vM.N.P/` itself.
6. Add the version to the table in `index.md`.

Write documentation pages in the latest folder, and add a row to its
navigation file for a new page; a page without one is built and reachable by
a link, and has no place in the sidebar.

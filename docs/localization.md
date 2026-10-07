# Website localization

The English landing page is `docs/index.html`. Ten localized pages are generated
from the corresponding `README.<locale>.md` files. These editions cover
installation, interface languages, capabilities, workflows, platform packages,
safety, and verification; the English README retains the detailed support matrix.

Supported locales: `en`, `zh-CN`, `ja`, `ko`, `de`, `fr`, `es`, `it`, `pt-BR`, `ru`, `vi`.
Each README links to all eleven editions. Each website page has an accessible
language menu, a locale-specific canonical URL, and eleven `hreflang` alternatives.
URLs work directly and language switching does not depend on JavaScript.

To update localized content, edit the corresponding README. Navigation and footer
translations live in `docs/locales/content.json`. Screenshot titles reuse the
existing desktop translation catalogs. Keep commands, product names, file formats,
and versioned schema identifiers unchanged.

Rebuild the static pages:

```sh
cd docs
npm ci
npm run build:locales
```

Commit both the source README edits and generated HTML. GitHub Pages publishes
the `docs` directory from `main`, so a documentation change does not require a new
macOS binary or release tag. Check language links, downloads, screenshots, keyboard
navigation, and narrow layouts before pushing. The Markdown renderer is pinned in
`package-lock.json`; generated pages have no runtime rendering dependency.

# Static assets

This directory contains versioned assets served by the Flask admin UI:

- `style.css`: shared layout, navigation, form, and table styling.
- `spa.js`: progressive enhancement for shell navigation and UI behavior.

Keep assets dependency-free and cache-safe through the `asset_version` query parameter emitted by `layout.html`.

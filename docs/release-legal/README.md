# Release Legal Pack

This folder contains the legal material that must accompany Disturb release artifacts.

## Included files

- `THIRD_PARTY_NOTICES.md`: inventory of bundled third-party components and licensing notes.
- `licenses/libregexp-LICENSE.txt`: upstream license text for `libs/libregexp`.
- `licenses/tinycc-COPYING.LGPL-2.1.txt`: upstream LGPL-2.1 text bundled with vendored TinyCC (`libs/tinycc`).

## Release packaging

The GitHub release workflow packages this legal material in two ways:

- inside `docs/release-legal` (because `docs/` is shipped), and
- duplicated at top-level as `release-legal/` in each release archive for visibility.

## Notes

- Disturb project policy may treat its own code as unlicensed/public-domain style, but third-party licenses still apply to bundled components.
- If TinyCC code or binaries are distributed as part of a release, LGPL obligations remain applicable to that component.

# Package entry in Markdown

Package fallback test: import("tests/modules/pkg_md") should resolve to this file
when `pkg_md.urb` does not exist.

```papagaio
counter = 0,
counter++,
return {
  tag = "pkg_md",
  count = counter
},
```

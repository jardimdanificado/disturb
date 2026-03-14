# Disturb WASM Browser Demo

This example shows how to embed the Disturb WASM runtime in a plain browser page.

## Run this demo

1. Build the WASM runtime in the repository root:

```bash
make wasm
```

2. Start a local HTTP server in this folder (the browser must load `disturb.wasm` over HTTP):

```bash
cd examples/web
python3 -m http.server 8000
```

3. Open in your browser:

```
http://localhost:8000/
```

4. Edit the Disturb source/Markdown and click **Run**.

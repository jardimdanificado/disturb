# papagaio Obsidian Plugin Example

This folder contains a minimal example of an **Obsidian plugin** that runs papagaio scripts via a WebAssembly build.

## How to use

1. Build the WASM runtime and package the plugin:

```bash
cd /path/to/disturb
make obsidian
```

This produces `papagaio-obsidian/` with `papagaio.js` + `papagaio.wasm` included.

3. Install the plugin in Obsidian:

- Copy the entire folder `examples/papagaio-obsidian` to your Obsidian vault’s `plugins/` directory (e.g. `~/.obsidian/plugins/papagaio-obsidian`).
- Enable the plugin in Obsidian settings.

4. Use the command **"Run papagaio (active note)"** to execute the current note as papagaio source.

## Notes

- The plugin uses a `DisturbHost` hook object for file I/O. The example implementation uses `fs` (Electron) to read/write vault files.
- This example is minimal and intended as a starting point. For production use, add error handling, security considerations, and UI feedback.

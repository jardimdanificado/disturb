# Disturb Obsidian Plugin Example

This folder contains a minimal example of an **Obsidian plugin** that runs Disturb scripts via a WebAssembly build of Disturb.

## How to use

1. Build the WASM runtime and package the plugin:

```bash
cd /path/to/disturb
make obsidian
```

This produces `disturb-obsidian/` with `disturb.js` + `disturb.wasm` included.

3. Install the plugin in Obsidian:

- Copy the entire folder `examples/obsidian-plugin` to your Obsidian vault’s `plugins/` directory (e.g. `~/.obsidian/plugins/disturb-obsidian`).
- Enable the plugin in Obsidian settings.

4. Use the command **"Run Disturb (active note)"** to execute the current note as Disturb source.

## Notes

- The plugin uses a `DisturbHost` hook object for file I/O. The example implementation uses `fs` (Electron) to read/write vault files.
- This example is minimal and intended as a starting point. For production use, add error handling, security considerations, and UI feedback.

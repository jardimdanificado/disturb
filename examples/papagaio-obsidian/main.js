const { Plugin, MarkdownView, Notice, Modal } = require('obsidian');

class PapagaioOutputModal extends Modal {
  constructor(app, title, content) {
    super(app);
    this.title = title;
    this.content = content;
  }

  onOpen() {
    const { contentEl } = this;
    contentEl.empty();
    contentEl.createEl('h2', { text: this.title });
    const pre = contentEl.createEl('pre');
    pre.setText(this.content || '');
  }

  onClose() {
    const { contentEl } = this;
    contentEl.empty();
  }
}

module.exports = class PapagaioPlugin extends Plugin {
  async onload() {
    console.log('papagaio plugin onload');

    // Determine the vault root path (desktop + mobile).
    const vaultRoot = ((this.app.vault && this.app.vault.adapter) ? (this.app.vault.adapter.basePath || (typeof this.app.vault.adapter.getBasePath === 'function' ? this.app.vault.adapter.getBasePath() : '')) : '') || '';

    // Determine plugin directory for loading runtime assets.
    // On mobile there is no Node `path`/`fs`, so we use the vault path directly.
    const pluginDir = vaultRoot ? `${vaultRoot}/.obsidian/plugins/${this.manifest.id}` : '';

    // Setup host I/O hooks for papagaio.
    // In desktop (Electron) this can use Node FS.
    if (typeof require === 'function') {
      const fs = require('fs');
      const path = require('path');
      const resolvePath = (p) => {
        if (path.isAbsolute(p)) return p;
        return path.join(vaultRoot || process.cwd(), p);
      };

      window.PapagaioHost = {
        readFile: (p) => {
          try {
            return fs.readFileSync(resolvePath(p), 'utf8');
          } catch (e) {
            return null;
          }
        },
        writeFile: (p, content) => {
          try {
            fs.writeFileSync(resolvePath(p), content, 'utf8');
            return true;
          } catch (e) {
            return false;
          }
        },
      };
    } else {
      // No synchronous file I/O available (e.g., mobile). Provide no-op hooks.
      window.PapagaioHost = {
        readFile: () => null,
        writeFile: () => false,
      };
    }

    // Load the WASM runtime.
    try {
      // Use the plugin folder path (computed above). Other fallbacks will try to locate the file.
      let createPapagaioModule = null;
      console.log('papagaio-obsidian: pluginDir', pluginDir);

      if (typeof require === 'function' && pluginDir) {
        try {
          const path = require('path');
          const papagaioPath = path.join(pluginDir, 'papagaio.js');
          console.log('papagaio-obsidian: require path', papagaioPath);
          createPapagaioModule = require(papagaioPath);
        } catch (e) {
          console.warn('papagaio-obsidian: require(papagaio.js) failed, will try dynamic import', e);
        }
      }

      if (!createPapagaioModule) {
        // Dynamic import fallback (works in ESM-like environments).
        // On mobile, try to load the runtime from the plugin folder.
        if (pluginDir) {
          try {
            const runtimeJs = await this.app.vault.adapter.read(`${pluginDir}/papagaio.js`);
            const blob = new Blob([runtimeJs], { type: 'application/javascript' });
            const blobUrl = URL.createObjectURL(blob);
            const mod = await import(blobUrl);
            URL.revokeObjectURL(blobUrl);
            createPapagaioModule = mod.default || mod;
          } catch (e) {
            console.warn('papagaio-obsidian: failed to import runtime via vault adapter', e);
          }
        }

        if (!createPapagaioModule) {
          // Attempt a relative import as a last resort.
          try {
            const mod = await import('./papagaio.js');
            createPapagaioModule = mod.default || mod;
          } catch (e) {
            console.warn('papagaio-obsidian: failed to import runtime via relative path', e);
          }
        }

        if (!createPapagaioModule) {
          throw new Error('Cannot load papagaio runtime (papagaio.js)');
        }
      }

      // Load the WASM binary directly (avoid fetch/file:// issues).
      let moduleArg = {};
      this._papagaioOutput = '';
      const appendOutput = (text) => {
        if (typeof text !== 'string') text = String(text);
        this._papagaioOutput += text + '\n';
      };

      if (typeof require === 'function' && pluginDir) {
        try {
          const fs = require('fs');
          const path = require('path');
          const wasmPath = path.join(pluginDir, 'papagaio.wasm');
          moduleArg.wasmBinary = fs.readFileSync(wasmPath);
          moduleArg.locateFile = (file) => path.join(pluginDir, file);
        } catch (e) {
          console.warn('papagaio-obsidian: failed to pre-load WASM binary', e);
        }
      } else if (pluginDir) {
        try {
          const wasmBinary = await this.app.vault.adapter.readBinary(`${pluginDir}/papagaio.wasm`);
          moduleArg.wasmBinary = wasmBinary;
          const wasmUrl = URL.createObjectURL(new Blob([wasmBinary]));
          this._papagaioWasmUrl = wasmUrl;
          moduleArg.locateFile = (file) => {
            if (file.endsWith('.wasm')) return wasmUrl;
            return file;
          };
        } catch (e) {
          console.warn('papagaio-obsidian: failed to load WASM binary via vault adapter', e);
        }
      }

      // Last-resort fallback: relative fetch from the plugin directory (works in some environments).
      if (!moduleArg.wasmBinary && typeof fetch === 'function') {
        try {
          const resp = await fetch('./papagaio.wasm');
          if (resp.ok) {
            const wasmBinary = await resp.arrayBuffer();
            moduleArg.wasmBinary = wasmBinary;
            const wasmUrl = URL.createObjectURL(new Blob([wasmBinary]));
            this._papagaioWasmUrl = wasmUrl;
            moduleArg.locateFile = (file) => {
              if (file.endsWith('.wasm')) return wasmUrl;
              return file;
            };
          }
        } catch (e) {
          console.warn('papagaio-obsidian: failed to load WASM via fetch', e);
        }
      }

      // Capture stdout/stderr from the WASM runtime to show in the UI.
      moduleArg.print = (text) => appendOutput(text);
      moduleArg.printErr = (text) => appendOutput(text);

      this._module = await createPapagaioModule(moduleArg);
      this._papagaioEval = this._module.cwrap('papagaio_wasm_eval', 'number', ['string']);
      this._papagaioInit = this._module.cwrap('papagaio_wasm_init', null, []);
      this._papagaioFree = this._module.cwrap('papagaio_wasm_free', null, []);

      // Expose markdown extractor from the native runtime
      this._papagaioMdExtract = this._module.cwrap('papagaio_md_extract', 'number', ['string']);
      this._papagaioFreePtr = this._module.cwrap('free', null, ['number']);

      if (this._papagaioInit) this._papagaioInit();
    } catch (err) {
      console.error('Failed to initialize papagaio WASM runtime:', err);
      new Notice('papagaio: failed to initialize WASM runtime (see console)');
    }

    this.addCommand({
      id: 'papagaio-run-active-note',
      name: 'Run papagaio (active note)',
      callback: async () => {
        const view = this.app.workspace.getActiveViewOfType(MarkdownView);
        if (!view || !view.file) {
          new Notice('No active Markdown note');
          return;
        }

        const content = await this.app.vault.read(view.file);
        if (!this._papagaioEval) {
          new Notice('papagaio runtime not initialized');
          return;
        }

        // Use the native markdown extractor to handle all supported MD syntax.
        if (!this._papagaioMdExtract) {
          new Notice('papagaio runtime missing markdown parser');
          return;
        }

        const ptr = this._papagaioMdExtract(content);
        if (!ptr) {
          new Notice('Failed to parse markdown');
          return;
        }

        const code = this._module.UTF8ToString(ptr);
        this._papagaioFreePtr(ptr);

        if (!code.trim()) {
          new Notice('No papagaio code found in markdown');
          return;
        }

        this._papagaioOutput = '';
        this._papagaioEval(code);

        new PapagaioOutputModal(this.app, 'papagaio Output', this._papagaioOutput).open();
      },
    });
  }

  onunload() {
    if (this._papagaioFree) this._papagaioFree();
    if (this._papagaioWasmUrl) URL.revokeObjectURL(this._papagaioWasmUrl);
  }
}

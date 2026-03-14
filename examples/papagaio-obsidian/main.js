const { Plugin, MarkdownView, Notice, Modal, ItemView, WorkspaceLeaf } = require('obsidian');

const PAPAGAIO_OUTPUT_VIEW = 'papagaio-output-view';

class PapagaioOutputView extends ItemView {
  constructor(leaf) {
    super(leaf);
    this._output = '';
    this._sourceFile = '';
  }

  getViewType() {
    return PAPAGAIO_OUTPUT_VIEW;
  }

  getDisplayText() {
    return this._sourceFile ? `papagaio: ${this._sourceFile}` : 'papagaio output';
  }

  getIcon() {
    return 'code';
  }

  setContent(output, sourceFile) {
    this._output = output;
    this._sourceFile = sourceFile || '';
    this._render();
    // Update the tab title
    this.titleEl && (this.titleEl.textContent = this.getDisplayText());
  }

  _render() {
    const { contentEl } = this;
    contentEl.empty();

    const header = contentEl.createEl('div', { cls: 'papagaio-output-header' });
    header.createEl('span', { text: this.getDisplayText(), cls: 'papagaio-output-title' });

    const pre = contentEl.createEl('pre', { cls: 'papagaio-output-pre' });
    const code = pre.createEl('code', { cls: 'papagaio-output-code' });
    code.setText(this._output || '(no output)');
  }

  async onOpen() {
    this._render();
  }

  async onClose() {
    this.contentEl.empty();
  }
}


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

    this.registerView(PAPAGAIO_OUTPUT_VIEW, (leaf) => new PapagaioOutputView(leaf));

    // Determine the vault root path (desktop only; undefined/empty on mobile).
    const vaultRoot = ((this.app.vault && this.app.vault.adapter) ? (this.app.vault.adapter.basePath || (typeof this.app.vault.adapter.getBasePath === 'function' ? this.app.vault.adapter.getBasePath() : '')) : '') || '';

    // Vault-relative path for the plugin dir — works on both desktop and mobile
    // because adapter.read / adapter.readBinary expect vault-relative paths.
    const pluginRelDir = `.obsidian/plugins/${this.manifest.id}`;

    // Absolute path — only valid on desktop (Electron/Node).
    const pluginDir = vaultRoot ? `${vaultRoot}/${pluginRelDir}` : '';

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
        // Use vault-relative path — adapter.read expects relative paths on mobile.
        try {
          const runtimeJs = await this.app.vault.adapter.read(`${pluginRelDir}/papagaio.js`);
          // Blob URL dynamic import is blocked by CSP on Android WebView.
          // Use indirect eval via Function constructor instead.
          const mod = {};
          const fn = new Function('module', 'exports', 'require', runtimeJs);
          fn(mod, mod.exports = {}, typeof require === 'function' ? require : () => { throw new Error('require not available'); });
          createPapagaioModule = mod.exports.default || mod.exports;
        } catch (e) {
          console.warn('papagaio-obsidian: failed to load runtime via vault adapter', e);
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
      let wasmUrl = null;
      this._papagaioOutput = '';
      const appendOutput = (text) => {
        if (typeof text !== 'string') text = String(text);
        this._papagaioOutput += text + '\n';
      };

      // Detect a real Node.js environment: on Android, require() exists but returns
      // undefined for Node built-ins like 'path' and 'fs'. Guard explicitly.
      const _nodePath = (() => { try { const p = (typeof require === 'function') && require('path'); return (p && typeof p.join === 'function') ? p : null; } catch(e) { return null; } })();
      const _nodeFs   = (() => { try { const f = (typeof require === 'function') && require('fs');   return (f && typeof f.readFileSync === 'function') ? f : null; } catch(e) { return null; } })();
      const isNodeEnv = Boolean(_nodePath && _nodeFs && pluginDir);

      const makeLocateFile = (url) => (file) => {
        if (file.endsWith('.wasm') && url) return url;
        if (isNodeEnv) return _nodePath.join(pluginDir, file);
        return file;
      };

      if (isNodeEnv) {
        try {
          const wasmPath = _nodePath.join(pluginDir, 'papagaio.wasm');
          moduleArg.wasmBinary = _nodeFs.readFileSync(wasmPath);
        } catch (e) {
          console.warn('papagaio-obsidian: failed to pre-load WASM binary', e);
        }
      } else if (this.app.vault.adapter && typeof this.app.vault.adapter.readBinary === 'function') {
        try {
          // Use vault-relative path — adapter.readBinary does NOT accept absolute paths on mobile.
          const wasmBinary = await this.app.vault.adapter.readBinary(`${pluginRelDir}/papagaio.wasm`);
          moduleArg.wasmBinary = wasmBinary;
          wasmUrl = URL.createObjectURL(new Blob([wasmBinary]));
          this._papagaioWasmUrl = wasmUrl;
        } catch (e) {
          console.warn('papagaio-obsidian: failed to load WASM binary via vault adapter', e);
        }
      }

      // Last-resort fallback: relative fetch — unreliable on Android WebView (no base URL for plugin dir).
      // Only reached if both Node fs and vault adapter failed.
      if (!moduleArg.wasmBinary && typeof fetch === 'function') {
        try {
          const resp = await fetch('./papagaio.wasm');
          if (resp.ok) {
            const wasmBinary = await resp.arrayBuffer();
            moduleArg.wasmBinary = wasmBinary;
            wasmUrl = URL.createObjectURL(new Blob([wasmBinary]));
            this._papagaioWasmUrl = wasmUrl;
          }
        } catch (e) {
          console.warn('papagaio-obsidian: failed to load WASM via fetch', e);
        }
      }

      moduleArg.locateFile = makeLocateFile(wasmUrl);

      if (!moduleArg.wasmBinary) {
        console.warn('papagaio-obsidian: no WASM binary available; runtime will likely fail to initialize');
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
      const msg = err && err.message ? err.message : String(err);
      new Notice(`papagaio: failed to initialize WASM runtime: ${msg}`);
    }

    this.addCommand({
      id: 'papagaio-run-active-note',
      name: 'run active note',
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

        await this._showOutputView(this._papagaioOutput, view.file.basename);
      },
    });
  }

  async _showOutputView(output, sourceFile) {
    const { workspace } = this.app;

    // Reuse an existing output leaf if one is already open.
    let leaf = workspace.getLeavesOfType(PAPAGAIO_OUTPUT_VIEW)[0];

    if (!leaf) {
      // Open a new leaf to the right of the current editor.
      leaf = workspace.getLeaf('split', 'vertical');
      await leaf.setViewState({ type: PAPAGAIO_OUTPUT_VIEW, active: true });
    }

    const outputView = leaf.view;
    if (outputView instanceof PapagaioOutputView) {
      outputView.setContent(output, sourceFile);
    }

    workspace.revealLeaf(leaf);
  }

  onunload() {
    if (this._papagaioFree) this._papagaioFree();
    if (this._papagaioWasmUrl) URL.revokeObjectURL(this._papagaioWasmUrl);
  }
}
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
    // Setup host I/O hooks for papagaio.
    // In desktop (Electron) this can use Node FS.
    let resolvePath = null;
    const vaultRoot = this.app.vault.adapter.basePath || process.cwd();

    // Determine plugin directory for loading runtime assets.
    // Use the known plugin folder under the vault.
    let pluginDir = null;
    if (typeof require === 'function') {
      const path = require('path');
      pluginDir = path.join(vaultRoot, '.obsidian', 'plugins', this.manifest.id);
    }

    if (typeof require === 'function') {
      const fs = require('fs');
      const path = require('path');
      resolvePath = (p) => {
        if (path.isAbsolute(p)) return p;
        return path.join(vaultRoot, p);
      };

      window.PapagaioHost = window.DisturbHost = {
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
      window.PapagaioHost = window.DisturbHost = {
        readFile: () => null,
        writeFile: () => false,
      };
    }

    // Load the WASM runtime.
    try {
      // Use the plugin folder path (computed above). Other fallbacks will try to locate the file.
      let createPapagaioModule = null;
      console.log('papagaio-obsidian: pluginDir', pluginDir);

      if (typeof require === 'function') {
        try {
          const path = require('path');
          const papagaioPath = path.join(pluginDir || '', 'papagaio.js');
          console.log('papagaio-obsidian: require path', papagaioPath);
          createPapagaioModule = require(papagaioPath);
        } catch (e) {
          console.warn('papagaio-obsidian: require(papagaio.js) failed, will try dynamic import', e);
        }
      }

      if (!createPapagaioModule) {
        // Dynamic import fallback (works in ESM-like environments).
        // Use file:// URL to ensure correct path resolution from plugin folder.
        const papagaioUrl = `file://${pluginDir || ''}/papagaio.js`;
        console.log('papagaio-obsidian: dynamic import url', papagaioUrl);
        const mod = await import(papagaioUrl);
        createPapagaioModule = mod.default || mod;
      }

      // Load the WASM binary directly (avoid fetch/file:// issues).
      let moduleArg = {};
      this._disturbOutput = '';
      const appendOutput = (text) => {
        if (typeof text !== 'string') text = String(text);
        this._disturbOutput += text + '\n';
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
      }

      // Capture stdout/stderr from the WASM runtime to show in the UI.
      moduleArg.print = (text) => appendOutput(text);
      moduleArg.printErr = (text) => appendOutput(text);

      this._module = await createPapagaioModule(moduleArg);
      this._disturbEval = this._module.cwrap('disturb_wasm_eval', 'number', ['string']);
      this._disturbInit = this._module.cwrap('disturb_wasm_init', null, []);
      this._disturbFree = this._module.cwrap('disturb_wasm_free', null, []);

      // Expose markdown-to-urb extractor from the native runtime
      this._disturbMdExtractUrb = this._module.cwrap('disturb_md_extract_urb', 'number', ['string']);
      this._disturbFreePtr = this._module.cwrap('free', null, ['number']);

      if (this._disturbInit) this._disturbInit();
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
        if (!this._disturbEval) {
          new Notice('papagaio runtime not initialized');
          return;
        }

        // Use the native markdown extractor to handle all supported MD syntax.
        if (!this._disturbMdExtractUrb) {
          new Notice('papagaio runtime missing markdown parser');
          return;
        }

        const ptr = this._disturbMdExtractUrb(content);
        if (!ptr) {
          new Notice('Failed to parse markdown');
          return;
        }

        const code = this._module.UTF8ToString(ptr);
        this._disturbFreePtr(ptr);

        if (!code.trim()) {
          new Notice('No Disturb code found in markdown');
          return;
        }

        this._disturbOutput = '';
        this._disturbEval(code);

        new PapagaioOutputModal(this.app, 'papagaio Output', this._disturbOutput).open();
      },
    });
  }

  onunload() {
    if (this._disturbFree) this._disturbFree();
  }
}

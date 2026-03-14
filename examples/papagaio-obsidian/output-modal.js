const { Modal } = require('obsidian');

module.exports = class DisturbOutputModal extends Modal {
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
};

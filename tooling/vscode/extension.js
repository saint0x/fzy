const path = require('path');
const { workspace } = require('vscode');
const { LanguageClient, TransportKind } = require('vscode-languageclient/node');

let client;

function resolveFzCommand() {
  const configured = workspace.getConfiguration('fozzy').get('fzPath');
  if (configured && configured.trim().length > 0) {
    return configured;
  }
  return 'fz';
}

function activate(context) {
  const command = resolveFzCommand();
  const serverOptions = {
    command,
    args: ['lsp', 'serve'],
    transport: TransportKind.stdio
  };

  const clientOptions = {
    documentSelector: [{ scheme: 'file', language: 'fzy' }],
    synchronize: {
      fileEvents: workspace.createFileSystemWatcher('**/*.fzy')
    }
  };

  client = new LanguageClient(
    'fozzy-lsp',
    'Fozzy Language Server',
    serverOptions,
    clientOptions
  );

  context.subscriptions.push(client.start());
}

function deactivate() {
  if (!client) {
    return undefined;
  }
  return client.stop();
}

module.exports = {
  activate,
  deactivate,
};

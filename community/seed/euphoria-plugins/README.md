# Euphoria plugins

The plugin list behind the Marketplace section in [Euphoria](https://github.com/JoeyKoch1/euphoria-re). This is a pre-alpha.

## Publishing

1. Put your plugin in `plugins/` with a lowercase file name made of letters, digits, `_` and `-`. Start it with the header described in the [plugin docs](https://github.com/JoeyKoch1/euphoria-re/blob/main/plugins/README.md).
2. Run `eu plugin index .` in this folder to refresh `index.json`.
3. Open a pull request.

Euphoria installs a plugin only if its contents match the hash in `index.json`, and it stays switched off until the user turns it on. Plugins run in a sandbox, but read what you install, because nobody here audits them for you.

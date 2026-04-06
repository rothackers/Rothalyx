# Zara Plugin Marketplace

This directory is the local marketplace root used by Zara's plugin manager.

Expected layout:

- `index.json`
- one directory per published plugin package

The `index.json` file contains entries like:

```json
{
  "plugins": [
    {
      "name": "Example Plugin",
      "version": "1.0.0",
      "api_version": "1",
      "description": "Example marketplace package",
      "path": "example_plugin",
      "entry": "plugin.py",
      "sandboxed": true,
      "hooks": ["on_startup", "on_binary_analyzed"]
    }
  ]
}
```

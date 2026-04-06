# Architecture

Zara is organized as a layered native reverse engineering system. The intent is simple: the same core should power the desktop app, the CLI, the SDK, and automation surfaces.

## Analysis Pipeline

The main pipeline is:

1. loader
2. memory model
3. disassembly
4. function discovery and CFG recovery
5. IR and SSA
6. analysis and type recovery
7. decompiler
8. debugger integration
9. persistence, SDK, plugins, and optional AI workflows

Each stage produces data that later stages consume. The desktop UI is a client of that pipeline, not a separate implementation.

## Repository Layout

### Core

- `core/loader`  
  Parses supported binary formats and produces a normalized `BinaryImage`.
- `core/memory`  
  Owns mapped regions, permissions, rebasing support, and symbol lookup.
- `core/disasm`  
  Handles instruction decoding and architecture metadata.
- `core/cfg`  
  Recovers functions, basic blocks, successors, loops, switch edges, and call relationships.
- `core/ir`, `core/ssa`, `core/analysis`, `core/type`  
  Lift instructions into analysis-friendly form and run recovery and simplification passes.
- `core/decompiler`  
  Generates structured C-like output from recovered program state.
- `core/debugger`  
  Exposes runtime execution control and static/runtime integration.
- `core/database`  
  Persists projects, annotations, AI output, and analysis artifacts.
- `core/sdk`  
  Publishes the stable C ABI.

### Applications

- `apps/desktop_qt`  
  Native Qt Widgets application.
- `apps/cli`  
  Command-line tooling for analysis and scripting.

### Extension Surfaces

- `plugins`  
  Python plugin packaging and runtime integration.
- `scripting`  
  Embedded Python bindings and SDK support.

## Desktop Shape

The desktop product follows this split:

- Qt Widgets GUI
- C++ application layer
- C++ reverse engineering core
- embedded Python for plugins and automation

That separation keeps heavy UI and state management in the native application while leaving Python as an extension surface rather than part of the main execution path.

## Design Rule

If a capability must exist in more than one interface, it belongs in the core first. The desktop app, CLI, and SDK should consume the same implementation.

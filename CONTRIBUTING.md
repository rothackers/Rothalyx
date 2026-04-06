# Contributing

Thanks for contributing to Zara.

This is a systems-heavy codebase. The best changes are focused, tested, and easy to review.

## Before You Start

- Read [README.md](README.md) for the current build, run, and packaging flow.
- Check [docs](docs) if you are changing the architecture-facing behavior, AI integration, fuzzing, or the SDK.
- Open an issue first if the change is large, architectural, or likely to alter public behavior.

## Development Setup

Build:

```bash
cmake --preset dev
cmake --build --preset dev
```

Run tests:

```bash
ctest --test-dir build/dev --output-on-failure
```

If you are touching parser or hostile-input code, also run the sanitizer path described in [docs/fuzzing.md](docs/fuzzing.md).

## What Good Contributions Look Like

- one clear change per pull request
- tests added or updated when behavior changes
- docs updated when the user-facing workflow changes
- no unrelated cleanup mixed into the same PR
- no generated artifacts committed

## Code Style

- prefer simple, explicit code over clever shortcuts
- match the existing style in the area you are editing
- keep interfaces stable unless the change really justifies a break
- explain new dependencies instead of assuming they are acceptable

## Pull Request Checklist

Before opening a PR:

- build the project
- run the relevant tests
- explain the change clearly
- call out platform-specific risk when it exists
- keep follow-up work out of the same PR unless it is required for correctness

## Licensing

By contributing to this repository, you agree that your contributions will be licensed under the GNU Affero General Public License v3.0 or later.

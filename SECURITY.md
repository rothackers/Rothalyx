# Security Policy

If you believe you have found a security issue in Zara, do not open a public issue with exploit details.

## Reporting

Use GitHub's private vulnerability reporting for the repository if it is enabled. If it is not enabled, contact the maintainers directly and keep the report private until a fix is ready.

Please include:

- affected version or commit
- platform and package type
- clear reproduction steps
- impact
- proof-of-concept input, trace, or binary when it is safe to share
- suggested remediation if you already have one

## What to Expect

- reports are acknowledged as quickly as practical
- maintainers may ask for a reduced test case or environment details
- impact is confirmed before timelines are discussed
- once fixed, disclosure is coordinated through a normal release

## Scope

Security reports are especially useful for:

- parser bugs triggered by hostile binaries
- sandbox escapes
- debugger privilege or attachment issues
- distributed worker authentication or transport flaws
- credential leakage or unsafe model-backend behavior

## Out of Scope

These do not usually qualify on their own:

- hardening requests without a concrete weakness
- problems that depend on running the tool with local debug-only settings
- issues in unsupported third-party environments that cannot be reproduced

## Supported Versions

The current supported line is `1.x`, plus the current default branch while development continues.

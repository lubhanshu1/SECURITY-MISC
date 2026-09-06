# SECURITY-MISC Utility Scripts

This directory contains small, safe, read-only utilities written in
different scripting languages.

The scripts are intended for security research, file analysis,
project inspection, and learning purposes.

## Available Utilities

### Bash

Path:

`shell/hash_file.sh`

Purpose:

- Calculate SHA-256 for a specified file.
- Does not modify the input file.
- Does not execute the input file.
- Does not transmit data.

Example:

```bash
bash scripts/shell/hash_file.sh README.md
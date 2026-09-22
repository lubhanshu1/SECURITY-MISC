# SECURITY-MISC

**SECURITY-MISC** is a Python security research toolkit covering:

- forensic file analysis and IOC extraction
- Windows PE static analysis and reverse-engineering helpers
- string intelligence and suspicious API classification
- local TCP port assessment and service detection
- structured JSON reporting and self-tests

## Security Research Console

The repository now includes a static futuristic web console at `web/index.html`. It is a presentation and workflow layer for the toolkit's existing capabilities. It does not execute uploaded binaries, perform destructive actions, or provide a remote attack surface.

## Core CLI

```bash
python -m core.cli info
python -m core.cli doctor
python -m core.cli network scan 127.0.0.1
```

## Web

Open `web/index.html` directly or deploy the `web` directory as a static Vercel project.

The console is intentionally local-first and read-only. Verify and test the Python modules separately in a controlled lab environment.

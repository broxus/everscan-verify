# everscan-verify

A tool for verifying and uploading Everscale smart contracts.

## Commands

### verify

Verify a contract by compiling it on the server:

```
everscan-verify verify -i <SOURCE_DIR> -l <LICENSE> --compiler-version <COMPILER_VERSION> --linker-version <LINKER_VERSION>
```

### upload

Upload pre-built contract artifacts with source code:

```
everscan-verify upload --artifacts-dir <ARTIFACTS_DIR> --source-dir <SOURCE_DIR> -l <LICENSE> --compiler-version <COMPILER_VERSION> --linker-version <LINKER_VERSION>
```

### info

Get information about supported compiler and linker versions:

```
everscan-verify info
```

## Authentication

Set the following environment variables:
- `EVERSCAN_API_KEY` - Your API key
- `EVERSCAN_SECRET` - Your API secret

Or provide them as command-line arguments:
```
--api-key <API_KEY> --secret <SECRET>
```

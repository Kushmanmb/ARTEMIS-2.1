# Security policy

ARTEMIS-2.1 is the source-code audit and blockchain-monitoring component of the [0XCON](https://0xcon.org) platform. This repository is public. Deployment credentials and RPC endpoints live only in GitHub Actions secrets and are never committed.

## Supported versions

Only the `main` branch is supported. Fixes are not backported.

## Reporting a vulnerability

Report vulnerabilities privately through **[GitHub private vulnerability reporting](https://github.com/Kushmanmb/ARTEMIS-2.1/security/advisories/new)** on this repository's Security tab. Do not open a public issue or pull request for a security problem.

Please include:
- the affected file, contract function, or workflow
- steps to reproduce, or a proof of concept against a local Hardhat network or a public testnet
- the impact you expect

Never include private keys, seed phrases, API keys, or live wallet details in a report. Do not test against mainnet contracts or other users' assets.

We aim to acknowledge reports within 3 business days and to give a remediation plan within 14 days.

## Scope

In scope:
- `contracts/ARTEMIS.sol` (owner authorization, `reportFinding`, `pause`/`unpause`)
- the Python bot in `bot/`, including the read-only snapshot API used by 0XCON
- GitHub Actions workflows in `.github/workflows/`, especially anything that could expose `DEPLOYER_PRIVATE_KEY`, `WEB3_RPC_URL`, or `ETHERSCAN_API_KEY`, or push unreviewed code

Out of scope:
- findings that the ARTEMIS auditor reports in third-party contracts (report those to the contract's owner)
- dependency advisories that Dependabot already tracks, unless you have a working exploit path

## Safeguards in this repository

- Secret scanning and push protection are enabled.
- Dependabot security updates run weekly for npm, pip, and GitHub Actions.
- Contracts are compiled and tested in CI on every push and pull request (`contracts.yml`).
- Auto-fix commits are opt-in through manual workflow dispatch only. Scheduled and pull-request audit runs are read-only.
- Contract deployment (`deploy.yml`) runs only on manual workflow dispatch, which requires write access to this repository.

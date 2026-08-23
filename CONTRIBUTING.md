# Contributing to Bughunter

Thanks for your interest in contributing! This project follows an open contribution model. Please read this guide before opening an issue or pull request.

## Getting started

1. Fork the repo and clone your fork.
2. Install dependencies:

```bash
python -m pip install -e ".[dev]"
```

3. Run a scan to verify:

```bash
python -m bughunter.cli init test-project
python -m bughunter.cli scan scanme.nmap.org --passive-only
```

## Before you start

- Open an [issue](https://github.com/ceptor29/bughunter/issues) describing the bug or feature so we know what you are working on.
- Keep changes focused: one logical change per PR.

## Development workflow

- Write code in `src/bughunter/` following the conventions in neighboring files.
- Run checks before pushing:

```bash
python -m bughunter.cli doctor
python -m bughunter.cli modules --list
python -m bughunter.cli scan scanme.nmap.org --passive-only
```

## Commit messages

Use conventional, imperative-style commits:

- `feat(detectors): add CORS misconfiguration detection`
- `fix(auth): handle expired JWT tokens gracefully`
- `docs: add auth token configuration guide`

## Pull requests

- Fill out the PR template.
- Link any related issues with `Closes #123`.
- Ensure CI passes.
- Reviewers may ask for changes; keep the conversation on the PR.

## Reporting bugs

Use the bug report template and include:
- OS and Python version
- Steps to reproduce
- Full error output
- Whether it happens with `--passive-only`

## Code of conduct

All participants must follow the [Code of Conduct](CODE_OF_CONDUCT.md). Please report unacceptable behavior to the project maintainers.

# Contributing to Codios

Thank you for your interest in contributing!

## Ways to contribute

- **Bug reports** — open a GitHub issue with steps to reproduce
- **Features** — open an issue first to discuss before submitting a PR
- **Documentation** — improvements to README, inline docs, or examples
- **SDK ports** — new language SDKs are very welcome (Go, Rust, Java)

## Development setup

### Backend
```bash
cd backend
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.vpc.example .env   # fill in values
uvicorn main:app --reload
```

### TypeScript SDK
```bash
cd sdk-js
npm install
npm run build
npm test
```

### CLI
```bash
cd cli
npm install
npm run build
node dist/index.js --help
```

## Pull request guidelines

- Keep PRs focused — one feature or fix per PR
- Add or update tests for changed behaviour
- Run `python3 -m pytest` (backend) and `npm test` (SDK/CLI) before submitting
- Describe *why* the change is needed, not just *what* it does

## Security issues

Please **do not** open public issues for security vulnerabilities.
Email security@midlantics.com instead.

## License

By contributing you agree that your contributions will be licensed under the Apache 2.0 License.

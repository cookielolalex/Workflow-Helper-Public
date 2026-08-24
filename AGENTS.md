# Repository instructions

- Optimize for traceable workflow knowledge, not volume of recording.
- Preserve the privacy boundary in `docs/PRIVACY_BOUNDARY.md`.
- Keep recording disabled by default and fail closed on uncertain context.
- Never add credentials, signed URLs, client drawings, or employee data.
- Version exchanged schemas under `contracts/`.
- Distinguish observed behavior from human-approved rules in code and UI.
- Prefer the smallest end-to-end vertical slice over speculative orchestration.
- Run `python scripts/validate.py` after changes.

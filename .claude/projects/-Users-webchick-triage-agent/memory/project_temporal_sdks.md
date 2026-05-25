---
name: project-temporal-sdk-ecosystems
description: All Temporal SDK languages are represented as package ecosystems in this project, including Rust
metadata:
  type: project
---

All 8 official Temporal SDK languages have a corresponding ecosystem provider in `activities/ecosystems/`:

- Python → pip.py
- TypeScript/JS → npm.py
- Java → maven.py
- Go → gomod.py
- .NET → nuget.py
- PHP → composer.py
- Ruby → rubygems.py
- Rust → cargo.py (SDK shipped ~May 2026)

**Why:** The project is maintained by Temporal staff (angela.byron@temporal.io). Covering all SDK languages is intentional — not just general Dependabot coverage.
**How to apply:** When considering which ecosystems to prioritize for new features or signal improvements, all 8 are first-class. Cargo is not a "bonus" ecosystem.

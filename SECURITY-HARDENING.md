# Brandlogic security fork

Based on upstream commit `6b316b85793ed0157d5987a53f0aaecfb46eac1b`.
The version adds build metadata (`9.0.3+brandlogic.1`) to preserve compatibility
with existing 9.0.3 project configurations. The original MIT license is retained.

## Changes

- Update `sfmc-sdk` to 3.2.2, using `fast-xml-parser` 5.7.2; retain upstream's
  `simple-git` 3.36.0 fix and refresh vulnerable transitive dependencies.
- Update Mocha to 12.0.0 and prettier-eslint to 17.1.2 so the development
  dependency tree also resolves patched packages, including shell-quote.
- Remove `json-to-table` and its outdated Lodash dependency. An internal helper
  covers report conversion, including nested own properties, without path lookups
  through object prototypes. No root-only npm overrides are required by consumers.
- Execute commands with separate arguments through `cross-spawn`, with shell
  interpretation disabled. Update quoting and clone-option call sites accordingly.
- Accept HTTPS and SSH remotes in init/join, including SCP-style SSH URLs. Reject
  executable Git transports, local paths, cleartext HTTP and embedded passwords.
- Create/update `.mcdev-auth.json` with owner-only file permissions and reject
  symlinks. Tighten existing auth/session file permissions when used; create
  session files and new log files with mode 0600.
- Redact known authentication keys in API request/response diagnostics, including
  lowercase headers, JSON, form/query parameters and multiline SOAP tokens.
- Clear in-memory SDKs when clearing sessions; use consistent disk cache keys
  and do not reuse cached sessions after client-secret/auth-endpoint changes
  detected when initializing an SDK.
- Mark this fork private for npm publishing and disable upstream update prompts
  and automatic npm replacement. This does not change GitHub repository visibility.
- Direct Dependabot to `main` and add a weekly/PR production dependency audit.
- Align the inherited CI Node matrix with the existing package engine range;
  Node 21 and 23 are outside that range.

## Install from a reviewed revision

Use Node.js 24 and a normal user account. Clone this fork, then check out the
exact reviewed commit from the security pull request (or its merged commit).

```sh
git clone https://github.com/brandlogic/sfmc-devtools.git
cd sfmc-devtools
git checkout <reviewed-commit-sha>
npm ci --omit=dev --ignore-scripts
node lib/cli.js --version
```

To run in an SFMC project directory, use the absolute path to this checkout:

```sh
node /absolute/path/to/sfmc-devtools/lib/cli.js retrieve
```

Alternatively, create a tarball with `npm pack --ignore-scripts` and install that
tarball into a dedicated tool directory. Keep the resulting consumer lockfile;
the package tarball does not enforce this repository's dependency lockfile.
Audit the resolved installation before attaching credentials.

Avoid `npm audit fix --force`: npm may suggest downgrading mcdev to 1.0.0 rather
than repairing the intended version. Update this fork through reviewed commits.

## Validation

Run `npm ci --ignore-scripts`, `npm test`, `npm run lint`, `npm run lint-ts`, and
`npm audit`. The test suite uses mocked SFMC HTTP responses, not a live tenant.
Security regressions test literal shell arguments, Git names/messages, remote
URL validation, report conversion, log redaction, file permissions and symlinks.

On 10 September 2026, Node.js 24.19.0 on Linux: 324 tests passed, 16 existing
tests remained pending; lint passed with warnings and TypeScript checks passed.
The complete repository lockfile audit reported zero known vulnerabilities.
A fresh production installation from `npm pack --ignore-scripts` also reported
zero known vulnerabilities; its CLI version and help commands were smoke-tested.
GitHub CI also passed lint/tests on Node 20.19, 22, 24 and 25, plus the production
audit and coverage report. Node 24 remains the recommended installation target.

## Remaining boundaries

- This fixes identified issues, not every possible vulnerability. A clean audit
  only covers advisories known to the registry at the time of the check.
- Credentials and cached tokens remain plaintext, protected by OS permissions,
  not encrypted or stored in macOS Keychain. On Windows, configure suitable ACLs;
  Unix mode bits do not provide equivalent protection there.
- Logs and retrieved metadata can still contain sensitive business data and
  secrets under arbitrary field names. API diagnostics are not anonymized.
  Existing logs/backups are not rewritten or deleted by these changes.
- Commands and project configuration must still be trusted. Project dependency
  installation can execute that project's npm scripts. Local installation does
  not sandbox the CLI or isolate credentials from other software running as you.
- Test live retrieval/deployment in a non-production Business Unit with a
  dedicated least-privilege installed package before production use. Automated
  tests do not validate your tenant, network or Windows/macOS integration.

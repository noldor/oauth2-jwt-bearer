# Publishing releases

Source: [GitHub](https://github.com/noldor/oauth2-jwt-bearer). Package: [Packagist](https://packagist.org/packages/noldors/oauth2-jwt-bearer). Stable versions follow `MAJOR.MINOR.PATCH` and Git tags use the `v` prefix.

Run the **Release** workflow from `master`, supplying a version such as `0.1.0`. Do not push a version tag first. The workflow calls the same reusable Quality workflow used for pushes and pull requests. Its publish job depends on successful Quality completion; failure, cancellation or an unexpected skip prevents publication. The publisher checks out the exact tested commit and accepts only `master` and a stable version.

Quality runs in the pinned PHP 8.5 Docker runtime with an isolated PostgreSQL service:

- Composer strict manifest/lock validation and installation of the committed graph.
- Runtime and development dependency advisory checks.
- Shared formatting, PHPStan max, phanalist and the complete unit/League/Passport/PostgreSQL integration tests.
- Pinned Betterleaks controls, current/index and complete candidate-history scanning.
- Exact Composer/Git distribution allowlist checks.

Only the subsequent publish job has `contents: write`. It creates an annotated tag for the tested SHA and a GitHub Release. An existing tag for the same SHA is reusable; an existing tag pointing elsewhere fails without moving it. An interrupted release can be rerun for the same version and commit. An existing draft/prerelease is reported as a failure instead of being mistaken for a completed stable release. Packagist imports the version from that tag through the configured repository integration. Check the Actions result, release/tag commit and Packagist version before declaring publication complete.

The package registry derives versions from Git tags; do not add a `version` field to `composer.json`. Consumers can install the first stable release with `composer require noldors/oauth2-jwt-bearer:^0.1`. Development path repositories are described separately in [local installation](local-installation.md).

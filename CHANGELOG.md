# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.0.1] - 2020-12-10
First Open Source release to the public domain.

### Changed
- Installation no longer requires a deploy secret.
- Installation now references Docker images stored in public Docker-Hub repositories.
- Secret files no longer are encrypted under a PGP key, but are instead changed to a default value of `CHANGEME` that **must** be changed when install.

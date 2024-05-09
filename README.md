# AppCheck Backend for Rust

## What

An opinionated implementation of a Firebase AppCheck backend for performing
token validation by Rust backend services. Assumes the implementing service utilizes
the Tokio runtime for long-running Rust server apps, the Triggered crate to monitor for
shutdown signals from the parent application, the Tracing crate for logging events from
the caching task and Axum for the backend API.

## How

The AppCheck backend Rust crate has three primary components:
* A `TokenVerifier` which contains the cached collection of `RS256PublicKey`s indexed by
  `kid` within a hash map that performs individual request token validation by verifying
  the supplied key against the configured app ID allow list, the project number and standard
  JWT claims and of course, the token signature.

* A `JwkCache` which runs as a persistent background task, spawned on the Tokio runtime and
  listening for shutdown signals from the parent application, meanwhile refreshing the cache
  of public keys used to perform token validation every X hours.

* A `AppCheckLayer` Axum middleware layer for injecting the check into the application router.

The `settings.rs` module provides the configuration knobs for customizing the behavior of the crate.
The only required configuration value is the Firebase Project Number for configuring the `iss` and `aud`
values of the auth token. Other config values of note are the allowlist of Firebase App IDs to allow
as a possible `sub` token value, the duration the cache task should wait before refreshing the public
keys and timing fields for validating the token is unexpired within tolerances and boundaries.

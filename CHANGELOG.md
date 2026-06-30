# Changelog

## [0.4.0](https://github.com/Gitlawb/node/compare/v0.3.9...v0.4.0) (2026-06-30)


### Features

* agent profiles (display name, bio, avatar, social links) ([#23](https://github.com/Gitlawb/node/issues/23)) ([09a3397](https://github.com/Gitlawb/node/commit/09a339745eca40a2567d911e947e3fc7426fc621))
* **db:** versioned schema migrations with idempotent backfill ([#21](https://github.com/Gitlawb/node/issues/21)) ([927e4d0](https://github.com/Gitlawb/node/commit/927e4d0cfb4ea11dca6930780939afaa067797ba))
* encrypted replication for private subtrees (B1/B2/B3) for [#18](https://github.com/Gitlawb/node/issues/18) ([#36](https://github.com/Gitlawb/node/issues/36)) ([5ff7af8](https://github.com/Gitlawb/node/commit/5ff7af84fa21fab53a12dfa04a0e7fb7e7d672e6))
* **git-remote-gitlawb:** add --version and --help flags ([#30](https://github.com/Gitlawb/node/issues/30)) ([3a401eb](https://github.com/Gitlawb/node/commit/3a401eb0792f9c5f5a10de6c16861655ab3836e0))
* **gitlawb-attest:** External Attestation v1 for ref-update certs ([#20](https://github.com/Gitlawb/node/issues/20)) ([924bccd](https://github.com/Gitlawb/node/commit/924bccd8e53e9be2dc9d6d4e4f1376952d6462bb))
* **node:** blind recipient identities at rest and gate B1 by repo readability ([#40](https://github.com/Gitlawb/node/issues/40)) ([abdc775](https://github.com/Gitlawb/node/commit/abdc7757708d2bbb2bfda99bb65d50756142a42e))
* **node:** enforce per-route authorization across the REST and GraphQL surface ([#87](https://github.com/Gitlawb/node/issues/87)) ([2202b00](https://github.com/Gitlawb/node/commit/2202b0097fab6976ab366a2cdc385f1146a72f86))
* **node:** graceful shutdown + Prometheus metrics endpoint ([#22](https://github.com/Gitlawb/node/issues/22)) ([2ce4da9](https://github.com/Gitlawb/node/commit/2ce4da9cc5a4791e8ae5a1cd90270b67f60d9ec3))
* **node:** iCaptcha proof-of-intelligence gate on create_repo + register ([#108](https://github.com/Gitlawb/node/issues/108)) ([adc20f9](https://github.com/Gitlawb/node/commit/adc20f9effad7b42fab55002875d209c4ed79518))
* **node:** iCaptcha-aware repo propagation gate with quarantine ([#125](https://github.com/Gitlawb/node/issues/125)) ([8b9ceec](https://github.com/Gitlawb/node/commit/8b9ceec25ef338965d1db72d39a7f2adb5300cc9))
* **node:** owner-only push enforcement behind GITLAWB_ENFORCE_OWNER_PUSH ([#31](https://github.com/Gitlawb/node/issues/31)) ([#68](https://github.com/Gitlawb/node/issues/68)) ([0a15e76](https://github.com/Gitlawb/node/commit/0a15e763d2ab46737a3831715facbe51045b33ba))
* **node:** peer partial-mirrors for repos with private subtrees ([#35](https://github.com/Gitlawb/node/issues/35)) ([e365a57](https://github.com/Gitlawb/node/commit/e365a57b51c167abf06e87bfeb0565c80ed1b849))
* **node:** pin the per-push object delta instead of re-enumerating the whole repo ([#90](https://github.com/Gitlawb/node/issues/90)) ([1af4fdf](https://github.com/Gitlawb/node/commit/1af4fdf485c7084cd160551b757b1ad1eed65cc6))
* **node:** replication enforcement (Phase 2) for [#18](https://github.com/Gitlawb/node/issues/18) ([#34](https://github.com/Gitlawb/node/issues/34)) ([8680d0f](https://github.com/Gitlawb/node/commit/8680d0f9d6600bba1a52d15624f8a2802a169511))
* **node:** signature-gated agent self-deregister ([#29](https://github.com/Gitlawb/node/issues/29)) ([#63](https://github.com/Gitlawb/node/issues/63)) ([ff492b4](https://github.com/Gitlawb/node/commit/ff492b452126f5568dac4286a7249f0cadb8b380))
* **node:** subtree content withholding (Phase 3) for [#18](https://github.com/Gitlawb/node/issues/18) ([#28](https://github.com/Gitlawb/node/issues/28)) ([61b3830](https://github.com/Gitlawb/node/commit/61b383019fd895a1a6adfad934ad6c626e0f095e))
* path-scoped repository visibility (Phase 1) for [#18](https://github.com/Gitlawb/node/issues/18) ([#25](https://github.com/Gitlawb/node/issues/25)) ([6abaf1d](https://github.com/Gitlawb/node/commit/6abaf1d7ed8fc55c6547568ae7247131311bde98))
* per-DID rate limiting on creation endpoints (10/hour) ([#13](https://github.com/Gitlawb/node/issues/13)) ([b12c6bc](https://github.com/Gitlawb/node/commit/b12c6bc3283c2647224a62fb520a3cb7acf4a747))
* **sync:** auto-register as replica with origin after successful mirror ([#56](https://github.com/Gitlawb/node/issues/56)) ([c03c9af](https://github.com/Gitlawb/node/commit/c03c9af8fadafe262a2bf3cf25e19edf7160d376))


### Bug Fixes

* **api:** blob endpoint returns 400/404 instead of 500 on bad paths ([#37](https://github.com/Gitlawb/node/issues/37)) ([b61a1bd](https://github.com/Gitlawb/node/commit/b61a1bd46ffe78b39c0967e97b0ad349eba0b046))
* **core:** route seed access through the zeroizing wrapper ([#41](https://github.com/Gitlawb/node/issues/41)) ([#64](https://github.com/Gitlawb/node/issues/64)) ([c9f43b0](https://github.com/Gitlawb/node/commit/c9f43b010576edb3c92a3be3d935cad232250344))
* **core:** zeroize the derived X25519 secret ([#65](https://github.com/Gitlawb/node/issues/65)) ([#91](https://github.com/Gitlawb/node/issues/91)) ([2f6611a](https://github.com/Gitlawb/node/commit/2f6611a30fbb66cef9991cf4c6e507548acc5038))
* **gl:** paginate gl-clone Arweave recovery and make /encrypted-blobs parsing schema-strict ([#49](https://github.com/Gitlawb/node/issues/49)) ([#70](https://github.com/Gitlawb/node/issues/70)) ([2153b0b](https://github.com/Gitlawb/node/commit/2153b0b7a67a48c29a33cd70b80cfbb69760805d))
* **infra:** drop fly idle_timeout 600 -&gt; 120 ([#38](https://github.com/Gitlawb/node/issues/38)) ([a2217bf](https://github.com/Gitlawb/node/commit/a2217bff27ff3d6cae02bd8a12f8a0af7ce2b0a1))
* **node:** anchor the real old_sha and issue a per-ref certificate ([#72](https://github.com/Gitlawb/node/issues/72)) ([6809201](https://github.com/Gitlawb/node/commit/6809201daa223d6f833be6e95876a7b4e1f2b0b5))
* **node:** close under-withholding via full ref scope and full-history classification ([#42](https://github.com/Gitlawb/node/issues/42)) ([#84](https://github.com/Gitlawb/node/issues/84)) ([3e1e904](https://github.com/Gitlawb/node/commit/3e1e9045e4e3aa5ea0aee69767ceb01637920d2a))
* **node:** dedupe mirror and canonical repo rows on list surfaces ([#6](https://github.com/Gitlawb/node/issues/6)) ([#73](https://github.com/Gitlawb/node/issues/73)) ([3e8e333](https://github.com/Gitlawb/node/commit/3e8e333aa03d7a2fe455d5d83f23089d58feb8c9))
* **node:** enforce path-scoped visibility on the REST read API ([#52](https://github.com/Gitlawb/node/issues/52)) ([e37ea7f](https://github.com/Gitlawb/node/commit/e37ea7fec6d5a3171b526c84f884670bbbd258fb))
* **node:** fail closed when a recipient DID can't be resolved ([#47](https://github.com/Gitlawb/node/issues/47)) ([#67](https://github.com/Gitlawb/node/issues/67)) ([abc9ad0](https://github.com/Gitlawb/node/commit/abc9ad03acb48e608234650a25049622673fa53a))
* **node:** gate fork_repo on per-caller path-scoped visibility ([#98](https://github.com/Gitlawb/node/issues/98)) ([#109](https://github.com/Gitlawb/node/issues/109)) ([6ae316c](https://github.com/Gitlawb/node/commit/6ae316cc88521747cbacb2a612b9433897d2e490))
* **node:** gate GET /ipfs/{cid} on per-caller path-scoped visibility ([#110](https://github.com/Gitlawb/node/issues/110)) ([#128](https://github.com/Gitlawb/node/issues/128)) ([174f25a](https://github.com/Gitlawb/node/commit/174f25a206380b26796b8782e1bd860b0a409fc9))
* **node:** gate repo-listing and stats surfaces on visibility ([#97](https://github.com/Gitlawb/node/issues/97), [#99](https://github.com/Gitlawb/node/issues/99), [#101](https://github.com/Gitlawb/node/issues/101), [#104](https://github.com/Gitlawb/node/issues/104)) ([#111](https://github.com/Gitlawb/node/issues/111)) ([828dd27](https://github.com/Gitlawb/node/commit/828dd279a286f58bbb3c73627b2a1e23778b25cf))
* **node:** make Tigris repo hydration resilient to corrupt archives & failed writes ([#54](https://github.com/Gitlawb/node/issues/54)) ([7a99d0f](https://github.com/Gitlawb/node/commit/7a99d0f27cfa869e9f8a803f16cff30191745a51))
* **node:** preserve promisor mirror mode on unknown withheld-paths lookup ([#48](https://github.com/Gitlawb/node/issues/48)) ([#69](https://github.com/Gitlawb/node/issues/69)) ([96fcfdb](https://github.com/Gitlawb/node/commit/96fcfdb1ca6d4cd27226670068702c9f177e283a))
* **node:** reap leaked git child processes ([#53](https://github.com/Gitlawb/node/issues/53)) ([#61](https://github.com/Gitlawb/node/issues/61)) ([803d83e](https://github.com/Gitlawb/node/commit/803d83efdbcfa9d98affac1c5aaf8aacc511ae64))
* **node:** reject malformed path globs with non-trailing or empty-segment wildcards ([#74](https://github.com/Gitlawb/node/issues/74)) ([#75](https://github.com/Gitlawb/node/issues/75)) ([3d880cd](https://github.com/Gitlawb/node/commit/3d880cd56fed10e4c5ae787b52ce411384950f5e))
* **node:** skip withheld-walk when no path-scoped rule can withhold ([#60](https://github.com/Gitlawb/node/issues/60)) ([338ff83](https://github.com/Gitlawb/node/commit/338ff83584f2ab960be7e42ecec64191f5aaeb95))
* **release:** give crates explicit versions for release-please ([#129](https://github.com/Gitlawb/node/issues/129)) ([788a868](https://github.com/Gitlawb/node/commit/788a8686c1deafe03573703d72eb927cde81f54d))
* **release:** use simple release-type + generic Cargo.toml updaters ([#130](https://github.com/Gitlawb/node/issues/130)) ([12bfb1b](https://github.com/Gitlawb/node/commit/12bfb1b3c86b38f0b22d488cd6e85dfd96e0c37f))
* **security:** gate webhook creation through the public-host validator ([#81](https://github.com/Gitlawb/node/issues/81)) ([#92](https://github.com/Gitlawb/node/issues/92)) ([f28fa02](https://github.com/Gitlawb/node/commit/f28fa02236bd65c6a4fb690131ab14640cc53a12))
* **security:** reject non-public peer URLs + prune poisoned peers ([#78](https://github.com/Gitlawb/node/issues/78)) ([a8cc33a](https://github.com/Gitlawb/node/commit/a8cc33a185f2649d3fe100ec271ee5739a55eba7))

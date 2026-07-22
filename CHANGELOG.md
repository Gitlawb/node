# Changelog

## [0.6.0](https://github.com/Gitlawb/node/compare/v0.5.1...v0.6.0) (2026-07-22)


### Features

* **icaptcha-client:** solve the iCaptcha proof-of-work on answer ([#181](https://github.com/Gitlawb/node/issues/181)) ([c98b503](https://github.com/Gitlawb/node/commit/c98b503f90cade54ce9c588bd2373a4e3486f2fc))


### Bug Fixes

* **core:** honor wildcard capabilities in Ucan::can, matching is_attenuated_by ([#200](https://github.com/Gitlawb/node/issues/200)) ([b6877a6](https://github.com/Gitlawb/node/commit/b6877a65981dbf41c4a7838971eb5c826c7fcaf2))
* **gl:** point doctor's version check at Gitlawb/node, not the frozen Gitlawb/releases repo ([#198](https://github.com/Gitlawb/node/issues/198)) ([98d728c](https://github.com/Gitlawb/node/commit/98d728c325f68f0ee4a62e473dc484b7dd627504))
* **node:** carry full owner DID on ref-update wire event ([#144](https://github.com/Gitlawb/node/issues/144)) ([#145](https://github.com/Gitlawb/node/issues/145)) ([69a62e5](https://github.com/Gitlawb/node/commit/69a62e51c2d2f090f9cae88f4d8ce3b9017b7149))
* **node:** gate /hooks and sibling read surfaces leaking private repo metadata ([#94](https://github.com/Gitlawb/node/issues/94)) ([#113](https://github.com/Gitlawb/node/issues/113)) ([ee8d7c0](https://github.com/Gitlawb/node/commit/ee8d7c03b26a0b678cc90b8801aa340fe81da700))
* strip Cf bidi/format controls in terminal-bound error sanitizers ([#183](https://github.com/Gitlawb/node/issues/183)) ([#188](https://github.com/Gitlawb/node/issues/188)) ([b07d41e](https://github.com/Gitlawb/node/commit/b07d41ea97569d79d3f545ae5d43c373cd6f0f33))

## [0.5.1](https://github.com/Gitlawb/node/compare/v0.5.0...v0.5.1) (2026-07-10)


### Bug Fixes

* **bounties:** add tests for claim_bounty repo-read gate ([#160](https://github.com/Gitlawb/node/issues/160)) ([#169](https://github.com/Gitlawb/node/issues/169)) ([6bafaa6](https://github.com/Gitlawb/node/commit/6bafaa6dc5f05c0dcd61c708397afddbcf8c2e3f))
* **deps:** bump crossbeam-epoch to 0.9.20 for RUSTSEC-2026-0204 ([#162](https://github.com/Gitlawb/node/issues/162)) ([#163](https://github.com/Gitlawb/node/issues/163)) ([67ad2b8](https://github.com/Gitlawb/node/commit/67ad2b876c8d9a336219d1016968de7a88fc4e75))
* **node,git:** bound a hung served git with a total-duration timeout ([#62](https://github.com/Gitlawb/node/issues/62)) ([#165](https://github.com/Gitlawb/node/issues/165)) ([cd67718](https://github.com/Gitlawb/node/commit/cd67718f49ec38726a40f6bcf36f539ccdb42969))
* **node:** bound list_ref_certificates with LIMIT and add upsert to prevent unbounded growth ([#147](https://github.com/Gitlawb/node/issues/147)) ([#149](https://github.com/Gitlawb/node/issues/149)) ([6b5e5bc](https://github.com/Gitlawb/node/commit/6b5e5bc7aee00a2d03295d3620df1ee4d8c024a2))
* **node:** gate POST /api/v1/sync/trigger and rate-limit the peer-sync routes ([#82](https://github.com/Gitlawb/node/issues/82)) ([#161](https://github.com/Gitlawb/node/issues/161)) ([d00d89a](https://github.com/Gitlawb/node/commit/d00d89ae5be992d1f63e95b714ae1bd3735e8457))
* **node:** rate-limit repo/agent creation per client IP to stop DID-farm spam floods ([#180](https://github.com/Gitlawb/node/issues/180)) ([dfcaa22](https://github.com/Gitlawb/node/commit/dfcaa22b23ec91be4c75926956aa994ca89de8d5))
* **release:** build aarch64-musl natively on arm64 runners, replace retired macos-13 ([#155](https://github.com/Gitlawb/node/issues/155)) ([6cff528](https://github.com/Gitlawb/node/commit/6cff5286b436fdee44ad881999e2a5f4bdba18f9))
* **visibility:** gate repo-scoped read surfaces on visibility ([#120](https://github.com/Gitlawb/node/issues/120)) ([#157](https://github.com/Gitlawb/node/issues/157)) ([26bc3f6](https://github.com/Gitlawb/node/commit/26bc3f69870aa77e43c0d92115a5aa59555b7d88))

## [0.5.0](https://github.com/Gitlawb/node/compare/v0.4.0...v0.5.0) (2026-07-05)


### Features

* **gl:** sanctioned iCaptcha client flow + secure git lifecycle ([#138](https://github.com/Gitlawb/node/issues/138)) ([06388ec](https://github.com/Gitlawb/node/commit/06388ec26aa29d356ae311276fdb91be054e9ecc))


### Bug Fixes

* **gl:** sign the CLI's /ipfs/pins reads under the [#134](https://github.com/Gitlawb/node/issues/134) auth gate ([#146](https://github.com/Gitlawb/node/issues/146)) ([20d6848](https://github.com/Gitlawb/node/commit/20d6848846b3a988d604208833167a528b7d8820))
* **node,git-remote:** gate receive-pack advertisement, sign client fetch/push ([#119](https://github.com/Gitlawb/node/issues/119)) ([6f36fc0](https://github.com/Gitlawb/node/commit/6f36fc07b8e10a650c5948b269feac1cb25cae2a))
* **node,gossip:** route gossip HTTP through the no-redirect client ([#93](https://github.com/Gitlawb/node/issues/93)) ([#140](https://github.com/Gitlawb/node/issues/140)) ([563c456](https://github.com/Gitlawb/node/commit/563c456803bf3e958d63869db424b3940472bc3d))
* **node:** close two spam-vector root causes (trust upsert + ungated push) ([#152](https://github.com/Gitlawb/node/issues/152)) ([2df6ff9](https://github.com/Gitlawb/node/commit/2df6ff9d30de62f754fa41473e85db316021718e))
* **node:** gate GET /ipfs/{cid} on reachable allowed-set, not deny-set ([#126](https://github.com/Gitlawb/node/issues/126)) ([#133](https://github.com/Gitlawb/node/issues/133)) ([466a550](https://github.com/Gitlawb/node/commit/466a550915edd711856ef32035f9f474e2577c4f))
* **node:** gate the ref-updates feeds on read visibility ([#112](https://github.com/Gitlawb/node/issues/112), [#114](https://github.com/Gitlawb/node/issues/114)) ([#143](https://github.com/Gitlawb/node/issues/143)) ([4891db3](https://github.com/Gitlawb/node/commit/4891db38892663326ee0c1417a2db931988be4b5))
* **node:** prefer canonical repo row over mirror row in get_repo ([#124](https://github.com/Gitlawb/node/issues/124)) ([#141](https://github.com/Gitlawb/node/issues/141)) ([6c95592](https://github.com/Gitlawb/node/commit/6c95592d188222ac3446dc23ef8d9befbf82ad6f))
* **remote:** include HTTP error response body ([#137](https://github.com/Gitlawb/node/issues/137)) ([09a0cb2](https://github.com/Gitlawb/node/commit/09a0cb23b9f284ccbd69aca6958b70671f3bfb46))
* **repos:** log the cause when repo create fails ([#103](https://github.com/Gitlawb/node/issues/103)) ([2620e97](https://github.com/Gitlawb/node/commit/2620e973e3cd4835ed42ddd4adcd8183b5b3080e))

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

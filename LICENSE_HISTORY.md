# License history

This file identifies the license boundary of published `vericto-proxy` source.
It is part of the release record. A Git author or committer date alone is not
proof of when source was first made available.

## Current and planned license

| Source | License |
|---|---|
| Tag `v5.0.0` and later releases, beginning with the transition represented by this working tree | GNU Affero General Public License, version 3 only (`AGPL-3.0-only`), or a separate commercial license from Vericto S.A.S. |
| Tags `v4.14.0` through `v4.23.0` | Functional Source License, Version 1.1, ALv2 Future License (`FSL-1.1-ALv2`) |
| Tag `v4.13.0` and earlier releases | Elastic License 2.0 (`Elastic-2.0`) |

The last FSL release is:

- tag: `v4.23.0`;
- commit: `68f72720ab1ed7abcada0a824c8e9bd9c922a3cb`;
- first documented public availability: 2026-10-31 (UTC), through pull request 99.

The first AGPL release will be identified by tag `v5.0.0`. The tag itself is
the immutable mapping to its commit SHA. Create and publish that tag at the
same time as the release. Do not publish an artifact called `4.23.0` from the
AGPL working tree.

## FSL future-license schedule

FSL 1.1 grants Apache License 2.0 for each version on the second anniversary of
the date Vericto first made that version available. The dates below use the
creation date of the public pull request as the earliest retained evidence for
each tagged release line. If Vericto finds earlier public evidence for a
specific commit or artifact, that earlier date controls for that version.

| Release | Commit | Documented public date (UTC) | Apache 2.0 no later than |
|---|---|---:|---:|
| `v4.14.0` | `b69ce7dcc965e46cafa700711a8ed0853238e01c` | 2026-10-19 | 2028-10-19 |
| `v4.14.1` | `b46844f6248892a17e308ab61e04dede8b2e2ff3` | 2026-10-19 | 2028-10-19 |
| `v4.14.2` | `ec634ca68366176b99dd9eddecfcec022c760b5f` | 2026-10-19 | 2028-10-19 |
| `v4.14.3` | `a821ca61a6673d92dfe5f0fa05b4d51758ccb1d5` | 2026-10-19 | 2028-10-19 |
| `v4.15.0` | `282f5b143a07b38e402e94fd19448cfd6a6d3256` | 2026-10-22 | 2028-10-22 |
| `v4.15.1` | `370d0659f7f48088209a1d6238660adfc20df61e` | 2026-10-23 | 2028-10-23 |
| `v4.15.2` | `ea43d23df315219e0a3752e60b0be2b735bf6be5` | 2026-10-23 | 2028-10-23 |
| `v4.15.3` | `8e1528867b8482a20e29182c9647db8892f7dc15` | 2026-10-23 | 2028-10-23 |
| `v4.16.0` | `86f52119c958d7850d71ce4a4ad347a48e9e589d` | 2026-10-23 | 2028-10-23 |
| `v4.16.1` | `b125978ee28d175e3ba788808fad0b4f79e6e580` | 2026-10-24 | 2028-10-24 |
| `v4.16.2` | `35ae1aec482f7db436f08e500e63c2ed32a4bf9f` | 2026-10-24 | 2028-10-24 |
| `v4.17.0` | `bb1fdbaf9cabe9ef6eda6d95c4fd92ed7816cb44` | 2026-10-24 | 2028-10-24 |
| `v4.17.3` | `ee97330197520c8b812c017cc94e4240574c5481` | 2026-10-25 | 2028-10-25 |
| `v4.18.0` | `57e8ddec9f0273848de00a4e7fa10be7f7078be1` | 2026-10-25 | 2028-10-25 |
| `v4.20.0` | `132a60be291df4956960f3f2e53629fa482d063b` | 2026-10-28 | 2028-10-28 |
| `v4.21.0` | `e2d56e64a781dcf2e23ba2bb4338e61b24adc558` | 2026-10-31 | 2028-10-31 |
| `v4.22.0` | `c96d9e14dbcf2cd10ce48d91a953689aa337f98b` | 2026-10-31 | 2028-10-31 |
| `v4.23.0` | `68f72720ab1ed7abcada0a824c8e9bd9c922a3cb` | 2026-10-31 | 2028-10-31 |

Public FSL versions without a release tag are recorded separately:

| Version | Commit | Documented public date (UTC) | Apache 2.0 no later than |
|---|---|---:|---:|
| `4.17.1` | `52abdc7dd8a175c827c7b88ac7baa81a11a14a80` | 2026-10-24 | 2028-10-24 |
| `4.19.0` | `40e6f991eae8d0107ad2b943ab6bdcc9c58901b5` | 2026-10-28 | 2028-10-28 |

The tables list tagged releases and retained untagged release commits. Another
intermediate FSL commit or package may have its own date because FSL defines
the Software as each version made available with its terms. Preserve pull-request, package and release records.
Do not infer the effective date only with `git rev-list --before`.

The controlling text remains the `LICENSE` file distributed with each version:

```sh
git show v4.23.0:LICENSE
git show v4.13.0:LICENSE
```

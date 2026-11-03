# Licensing

`vericto-proxy` version 5.0.0 and later is available under either:

1. the [GNU Affero General Public License, version 3 only](LICENSE)
   (`AGPL-3.0-only`); or
2. a separate commercial license from Vericto S.A.S.

You may choose the AGPL without asking Vericto. A commercial license applies
only after Vericto and the customer sign an agreement covering the relevant
software and use.

| Source release | License |
|---|---|
| 5.0.0 and later | AGPL-3.0-only, or a separate commercial license from Vericto S.A.S. |
| 4.14.0 through 4.23.0 | FSL-1.1-ALv2, including its future Apache-2.0 grant |
| 4.13.0 and earlier | Elastic-2.0 |

The exact tags, commits and documented publication dates are in
[LICENSE_HISTORY.md](LICENSE_HISTORY.md). The license text distributed with a
specific version controls that version.

This page is a practical summary, not legal advice and not an additional
license. If it conflicts with [LICENSE](LICENSE), LICENSE controls the public
AGPL option.

## AGPL option

The AGPL is an OSI-approved open-source license. It permits use, modification,
distribution and commercial activity, subject to its conditions.

Important cases include:

- **Running an unmodified copy.** The AGPL gives unlimited permission to run an
  unmodified copy. Merely operating it through a network does not by itself
  trigger section 13.
- **Distributing source or binaries.** Sections 4 through 6 require the license
  notices and, for covered object code, the complete corresponding source by
  one of the permitted methods. A covered combined work must be licensed as a
  whole under the AGPL, as section 5(c) requires. Separate components may keep
  compatible licenses where the AGPL permits that combination.
- **Modified network use.** If you modify the Program and users interact with
  that modified version remotely through a computer network, section 13
  requires you to offer those users the corresponding source of that version
  at no charge through a standard or customary means.
- **Internal use.** Making or modifying a private copy without conveying it is
  generally permitted by section 2. Section 13 can still matter if users
  interact remotely with a modified version. A parent, subsidiary or other
  affiliate is a separate legal person unless applicable law provides
  otherwise.

Whether the proxy and another component form one covered work is a
fact-specific copyright question. Packaging, linking, process boundaries and
the substance of communication can be relevant, but none decides every case
by itself. Vericto does not grant an exception through this FAQ. Obtain your
own legal advice or a commercial license when a closed-source integration
depends on that conclusion.

The AGPL does not prohibit a competitor from using, modifying, selling or
providing the software as a service when the competitor complies with the
license. Its network-source rule applies to modified versions; it is not a
non-compete restriction.

## Embedded engine

Version 5.0.0 pins `vericto-engine` version 5.0.0. Both public components use
`AGPL-3.0-only`, so the public binary and its Vericto source components have a
single compatible public-license path. Third-party components keep their own
licenses.

A separate commercial agreement for the proxy may include rights for the
engine it embeds when the agreement says so. This FAQ does not itself grant a
commercial license.

The container includes the project license, project notice, compiled dependency
notices and runtime-base license texts at `/usr/share/doc/vericto-proxy/`. It
also retains the base packages' SPDX documents under `/var/lib/db/sbom`.
Image labels identify the source repository and exact proxy revision; the
release `Cargo.lock` identifies the exact engine tag and commit. Together they
provide the directions needed to locate the corresponding Vericto source for
the image.

## Commercial option

A commercial license is available for organizations that want rights beyond
the AGPL option, such as:

- embedding the proxy in a closed-source distributed product;
- distributing a modified version without applying the AGPL to the covered
  combined work;
- operating a modified version without the section 13 source offer; or
- satisfying an organizational policy that does not permit AGPL software.

Scope, price, included components, support, warranties and other conditions
are set only by the signed commercial agreement. Vericto may decline a
request. Until an agreement is signed, only the AGPL option applies to version
5.0.0 and later.

Contact [legal@vericto.com](mailto:legal@vericto.com) with the company name,
product, version and intended deployment or distribution model.

## Older versions

A license change does not revoke permissions already granted for an older
version.

- Versions 4.14.0 through 4.23.0 remain under the Functional Source License,
  Version 1.1, ALv2 Future License. Each version receives Apache License 2.0 on
  the second anniversary of the date Vericto first made that version
  available. See [LICENSE_HISTORY.md](LICENSE_HISTORY.md); the FSL text in each
  tag controls that version.
- Versions 4.13.0 and earlier remain under Elastic License 2.0. The license
  text in each tag controls those versions.

Security fixes are made for supported releases under [SECURITY.md](SECURITY.md).

## Other Vericto projects

This repository licenses only `vericto-proxy`. Other projects, SDKs and hosted
services are governed by their own license or terms for the version received.
Nothing here changes another project's terms.

## Contributions

Contributions are governed by the Vericto Individual Contributor License
Agreement ([CLA.md](CLA.md)). It gives Vericto the rights needed to distribute
accepted contributions under the public project license and separate
commercial licenses while the contributor keeps copyright. The permanent text
of the current agreement is
[legal/cla/1.1.md](legal/cla/1.1.md).

See [CONTRIBUTING.md](CONTRIBUTING.md) and [AI_POLICY.md](AI_POLICY.md).

## Trademarks and third-party software

No software license grants a general right to use the Vericto marks. See
[TRADEMARKS.md](TRADEMARKS.md).

Third-party components remain under their own licenses. The container's
`THIRD_PARTY_LICENSES` file is generated by
[third-party/build-notices.sh](third-party/build-notices.sh).

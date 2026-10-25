# Licensing

vericto-proxy is **source-available** under the
[Functional Source License, Version 1.1, ALv2 Future License](LICENSE)
(SPDX `FSL-1.1-ALv2`), from version 4.14.0 on. Each version becomes
**open source under the [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0)**
two years after Vericto makes it available.

| Versions | License |
|---|---|
| 4.14.0 and later | [FSL-1.1-ALv2](LICENSE); each version also under Apache-2.0 from the second anniversary of its publication |
| 4.13.0 and earlier | [Elastic License 2.0](https://www.elastic.co/licensing/elastic-license) (SPDX `Elastic-2.0`), unchanged |

The licensor is Vericto S.A.S. (see [NOTICE](NOTICE)). This page is a summary
written to help you; it is not legal advice and does not change the license.
If this page and [LICENSE](LICENSE) disagree, LICENSE applies.

## The engine inside the binary

vericto-proxy compiles in [vericto-engine](https://github.com/vericto/vericto-engine),
Vericto's own SQL engine. vericto-proxy 4.14.0 pins vericto-engine v4.3.0,
which is licensed under FSL-1.1-ALv2 like the proxy, so the whole binary,
engine included, is under one license; the engine's crate metadata and its
entry in the image's `THIRD_PARTY_LICENSES` say `FSL-1.1-ALv2`. Earlier
vericto-engine releases, 4.2.0 and before, stay under the Elastic License 2.0.

The third-party crates and C libraries in the binary keep their own licenses;
the Docker image lists them with their license texts in
`/usr/share/doc/vericto-proxy/THIRD_PARTY_LICENSES`.

## FAQ

### Is vericto-proxy open source?

Not yet. The FSL is not an [OSI-approved](https://opensource.org/licenses)
license, so we call vericto-proxy "source-available". Every version becomes open
source on a fixed date: two years after we make it available, it is also
licensed under the Apache License 2.0, irrevocably.

### What can I do with it?

Anything that is not a Competing Use (next question). In particular, you can:

- read, build, run, copy and modify the code;
- use it in production for your own organization, including inside a
  for-profit company ("internal use and access");
- build it into your own product or service, as long as that product or
  service is not a Competing Use;
- use it for non-commercial education and non-commercial research;
- provide professional services, such as consulting or integration, to a
  customer who uses it under the license;
- redistribute copies, modified or not, with a copy of (or a link to) the
  license, keeping the copyright notices.

### What is not allowed?

A **Competing Use**: making the software available to others in a commercial
product or service that

1. substitutes for the software;
2. substitutes for any other product or service Vericto offers using the
   software that exists when that version is made available; or
3. offers the same or substantially similar functionality as the software.

For example, selling a SQL firewall or SQL-guardrail product or service, hosted
or self-managed, that is built on vericto-proxy is a Competing Use. Running
vericto-proxy to protect your own databases is not.

How Vericto reads these terms, for example:

- Selling others a hosted or managed service that checks, blocks or rewrites
  their SQL with vericto-proxy is a Competing Use, including when it runs
  inside each customer's own account. Operating vericto-proxy for one customer
  as part of consulting or integration work, where that customer holds the
  license and the work is not sold as a product, is a permitted professional
  service.
- A product that costs nothing but is offered as part of a commercial business
  (to win customers for a paid product, bundled with one, or as the free tier
  of one) is still a commercial product.
- Building vericto-proxy into a larger product that blocks, flags or rewrites
  SQL for others offers substantially similar functionality, even when
  guardrails are not that product's main purpose.

Not sure whether your case is a Competing Use? Write to
[legal@vericto.com](mailto:legal@vericto.com) before you rely on it.

### When does a version become Apache-2.0?

On the second anniversary of the date Vericto made that version available:
a published release, a pushed commit or a published package each count. A
version released on 2026-11-01 is available under the Apache License 2.0 from
2028-11-01, while newer versions are still under the FSL until their own date.
To find the newest commit that is already two years old:

```sh
git rev-list -n 1 --before="2 years ago" main
```

### What about versions released before 4.14.0?

vericto-proxy 4.13.0 and earlier, and every commit before the one that introduced
the FSL, were released under the Elastic License 2.0 and stay under it. Nothing
you received under it is taken away. The FSL applies only to 4.14.0 and later.
If you move to a newer version, the FSL applies to that version.

Those versions are no longer maintained and receive no security fixes (see
[SECURITY.md](SECURITY.md)). The Elastic License 2.0 does not allow providing
them to others as a hosted or managed service, or removing their license
notices, and it grants no right to the Vericto marks: a modified build must not
carry a Vericto name (see [TRADEMARKS.md](TRADEMARKS.md)).

### Can I get a commercial license?

Yes. You probably don't need one: the FSL already lets you run vericto-proxy to
protect your own databases, and build it into a product that is not a Competing
Use. Integrating with Vericto through its API or MCP server needs no commercial
license either; that use is governed by the [Terms of
Service](https://vericto.com/terms).

A commercial license is for cases the FSL does not cover:

- **OEM / embedding.** You want SQL guardrails inside your own product or
  hosted service (for example a database gateway, a connection pooler or a
  managed database platform) in a way that would be a Competing Use. An OEM
  license lets you embed and distribute vericto-proxy, modified or not, in the
  product named in the agreement. OEM agreements normally include attribution,
  such as "powered by Vericto"; the agreement grants the trademark permission
  that [TRADEMARKS.md](TRADEMARKS.md) otherwise requires in writing, and sets
  how modified builds may be described.
- **Other terms.** Your organization cannot accept the FSL and needs
  vericto-proxy under different terms.

Scope, price, support and update commitments are agreed in each contract. OEM
and Enterprise agreements can include a continuity clause: if Vericto stops
offering and maintaining the licensed component and no successor takes it over,
the licensee receives the version covered by its agreement under the Apache
License 2.0. Vericto reviews every request and may decline it. Until an
agreement is signed, the FSL applies. A commercial license does not change the
FSL for anyone else, and every FSL version still becomes Apache-2.0 on its
second anniversary.

To ask, write to [enterprise@vericto.com](mailto:enterprise@vericto.com) with
your company, the product vericto-proxy would go into, how it is distributed
(hosted, self-managed or both), the SQL dialects you need and the expected
scale. Not sure whether you need a license? Write to
[legal@vericto.com](mailto:legal@vericto.com) first.

### How are contributions licensed?

Contributors sign the Vericto Contributor License Agreement ([CLA.md](CLA.md)),
which lets Vericto distribute contributions under this license, under the
Apache License 2.0 when a version converts, and under its commercial licenses.
See [CONTRIBUTING.md](CONTRIBUTING.md).

### Can I use the Vericto name and logo?

The license does not grant trademark rights. See [TRADEMARKS.md](TRADEMARKS.md).

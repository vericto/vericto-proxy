# Privacy notice for CLA signatures

**Effective 2026-11-02**

Vericto S.A.S., NIT 902.100.599-0, Bogotá D.C., Colombia, is responsible for
the personal data used to administer its Contributor License Agreement (CLA).

## Data and source

When a contributor signs CLA 1.1 by posting the required GitHub pull-request
comment, the repository workflow records:

- GitHub username and numeric account ID;
- GitHub repository ID;
- pull-request number;
- signature-comment ID; and
- comment timestamp;
- CLA version; and
- SHA-256 hash of the permanent CLA document.

The workflow obtains those fields from GitHub. It does not use a separate form
to collect a legal name or email address.

## Purpose and authorization

Vericto uses the record to verify who accepted the CLA, administer
contributions, prove the copyright and patent licenses granted to Vericto, and
protect or defend rights in Vericto projects.

By posting the signature comment after reading CLA 1.1 and this notice, the
contributor authorizes that processing for those purposes. A contributor who
does not authorize it should not post the comment or submit copyrightable
material for inclusion. Questions may be sent to privacy@vericto.com before
signing.

## Storage, visibility and international processing

The data is stored in `signatures/v1.1/cla.json` on the `cla-signatures` branch
of GitHub repository `vericto/vericto-proxy`. Because the repository is
public, the signature record may be publicly visible. GitHub also stores the
pull request and signature comment under its own terms and privacy statement.

The workflow runs in GitHub Actions using a pinned version of
`actions/github-script` and base-branch JavaScript. Vericto does not send this
signature record to the hosted CLA Assistant service, SAP or Microsoft Azure.
GitHub may process data outside Colombia, including in the United States.

## Retention and rights

Vericto retains the signature record while it distributes a Contribution
covered by it and for any additional period reasonably necessary to establish,
exercise or defend legal claims. Deleting the public comment or a GitHub
account does not revoke an irrevocable license already granted.

Subject to applicable law, a contributor may request access, correction,
information about processing, proof of authorization, or deletion when no
legal or contractual reason requires retention. Contact privacy@vericto.com.
A contributor may complain to Colombia's Superintendencia de Industria y
Comercio.

This specific notice supplements the general privacy policy at
https://vericto.com/privacy. For CLA 1.1 signature records, this notice controls
if the general policy still describes the former hosted CLA Assistant process.

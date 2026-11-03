# Policy for AI-assisted contributions

Artificial-intelligence and code-generation tools may assist a contribution,
but a human contributor remains responsible for everything submitted.

## Required disclosure

For an AI-assisted pull request, add this line to the pull-request description:

```text
Created with: <tool name>; assistance: <brief description of what it produced>
```

Also identify any model output copied substantially without human rewriting,
and third-party code or documentation that You intentionally supplied to the
tool as prompt or context.

## Contributor responsibilities

Before submitting, the contributor must:

1. read, understand and test every AI-assisted change;
2. make the design, selection and editorial decisions reflected in the final
   contribution;
3. check that generated material does not reproduce third-party code, license
   notices, personal data, confidential information or trade secrets without
   authorization;
4. comply with the terms and data-handling rules of the tool used;
5. identify third-party material and its license in the pull request; and
6. be legally entitled to grant the rights in the Vericto CLA.

Do not list an AI system as an author or use a `Co-authored-by` trailer for it.
That trailer is reserved for human contributors.

Maintainers may reject a contribution when its provenance cannot be reasonably
established, when the contributor cannot explain it, or when the amount of
generated material makes review impractical. Disclosure does not cure a license
or ownership problem.

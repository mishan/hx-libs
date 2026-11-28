# Delegation

Status: draft. Sections are added as they are built; §3 is the first.

hl-delegation lets a person give an agent narrow, short-lived, revocable
authority over hl-identity: grants signed by the person, requests signed by
the agent, and a verifier that checks both before acting. This document
specifies its objects; hl-identity's specifications (in hxd-ng's `docs/`)
cover the identities, devices and certificates it builds on.

## 3. Scopes

A scope says what a grant allows: `service:action:resource`. A request
names one concrete action in the same form, with no wildcards.

### 3.1 Grammar

The first two `:` split the three parts; the resource may contain `:`.

- `service`: 1 to 32 of `a-z`, `0-9`, `-`. In a grant, also `*`.
- `action`: dot-separated parts, each one or more of `a-z`, `0-9`, `-`,
  at most 64 characters in all. In a grant, also `*`. A part is never a
  pattern: `pr.*` is not an action.
- `resource`: 1 to 256 bytes of printable ASCII (`0x21` to `0x7e`) other
  than `*`. In a grant, also `*`, or a prefix pattern: a resource ending
  in `/`, followed by `*` (`acme/*`), at most 256 bytes with the `*`.

A service publishes its actions and the canonical form of its resources.
Its adapter refuses a request whose resource is not canonical before any
scope is matched against it.

### 3.2 Covering

A grant scope **covers** an action when:

- its service is `*` or equal to the action's;
- its action is `*` or equal to the action's;
- its resource is `*`, or equal to the action's, or a prefix pattern
  `p/*` where the action's resource starts with `p/` and is longer than
  it.

So `acme/*` covers `acme/repo` and `acme/a/b`, but not `acme/`, `acme` or
`acme-evil/repo`. Comparison is exact bytes: no case folding, no
normalization.

### 3.3 Containment

A grant scope **contains** another when every action the other covers, it
covers too. It is decided segment by segment:

- a service or action segment: the outer one is `*`, or both are equal;
- a resource: the outer one is `*`; or both are equal literals; or the
  outer one is `p/*` and the inner one is a literal that starts with `p/`
  and is longer than it, or a pattern `q/*` where `q/` starts with `p/`.

Anything else is not contained. Containment is decided by these rules
alone, so it is sound by construction. A narrower grant must show, for
each of its scopes, a scope of its parent that contains it.

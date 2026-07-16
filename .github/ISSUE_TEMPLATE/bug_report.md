---
name: Bug report
about: Report a parsing bug, a missed rule, or a false positive
title: "[BUG] "
labels: bug
---

**Describe the bug**
A clear and concise description of what is wrong.

**SQL input**
```sql
-- The exact query that reproduces the issue
```

**Dialect**
- [ ] PostgreSQL
- [ ] MySQL
- [ ] Oracle
- [ ] SQL Server

**Expected decision**
- [ ] ALLOWED
- [ ] BLOCKED (which rule? e.g. VERICTO-001)
- [ ] PARSE_ERROR

**Actual decision**
What the engine returned.

**Environment**
- Engine version / commit:
- Rust version:

**Logs / output**
```
paste relevant output here
```

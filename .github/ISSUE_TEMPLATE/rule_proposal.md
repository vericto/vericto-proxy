---
name: Rule proposal
about: Propose a new detection rule for a destructive or risky SQL pattern
title: "[RULE] "
labels: rule-proposal
---

**Pattern to detect**
Describe the SQL pattern that should be flagged and why it is dangerous.

**Example queries that SHOULD be blocked**
```sql
-- one or more examples
```

**Example queries that should still be ALLOWED (false-positive guards)**
```sql
-- safe variants that must not be caught by the rule
```

**Suggested severity**
- [ ] critical
- [ ] high
- [ ] medium

**Dialects affected**
- [ ] PostgreSQL
- [ ] MySQL
- [ ] Oracle
- [ ] SQL Server
- [ ] all

**AST condition (if known)**
How would this be expressed over the AST? (node type, WHERE state, etc.)

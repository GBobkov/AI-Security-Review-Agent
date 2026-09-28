---
title: OWASP prevention guidance for B608 SQL findings
cwe: CWE-89
source_url: https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html
---
OWASP recommends prepared statements with parameterized queries as the primary defense against SQL injection. With this design, the database parses the statement structure separately from supplied values. A B608 result should be repaired at the point where the query is created so callers cannot accidentally bypass the separation. Stored procedures are useful only when they avoid unsafe dynamic SQL internally.

Some query parts cannot be bound as values. Table names, column names, and keywords such as ascending or descending order should come from a strict mapping between an accepted application choice and a constant fragment. Input validation supports that mapping but should not be used to make concatenated data values safe. Broad escaping routines are fragile because correct behavior depends on the database, connection settings, and context.

The database account should have only the permissions required by the feature. Avoid administrative accounts for application traffic, and consider separate accounts or views for distinct workloads. This limits the result of a mistake without curing it. During review, inspect logging too: parameter values may contain secrets and should not be copied into logs merely to demonstrate the fixed query. A useful regression test sends a familiar injection-shaped string and verifies it is stored or compared literally while the query still returns only authorized rows.

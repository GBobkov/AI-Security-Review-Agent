---
title: OWASP deserialization guidance for B506 YAML findings
cwe: CWE-502
source_url: https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html
---
OWASP's deserialization guidance treats complex object reconstruction as a dangerous boundary because data can select types and trigger behavior the application did not intend. For a B506 YAML finding, first ask whether the format needs object construction at all. Most configuration and API inputs need only primitive collections, making `yaml.safe_load` plus schema validation the appropriate design.

Do not rely on secrecy, filename extensions, or a trusted network location to make serialized content safe. Artifacts can be replaced, caches can be poisoned, and internal services can be compromised. If serialized data crosses a trust boundary, authenticate its origin and integrity, but remember that signatures do not protect against vulnerable data produced by an authorized source. Keep the parser and its dependencies updated and restrict the types it may create.

Run unavoidable high-risk parsing with minimal privileges and away from sensitive services, then copy only validated primitive results across the boundary. Log rejection reasons without echoing confidential document contents. Regression tests should include explicit Python-object YAML tags and assert that loading rejects them without side effects. Tests should also cover oversized or deeply nested inputs according to the application's limits. These controls address both code execution and denial-of-service paths commonly associated with unsafe deserialization.

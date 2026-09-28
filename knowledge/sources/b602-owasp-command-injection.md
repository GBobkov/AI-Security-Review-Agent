---
title: OWASP guidance for command injection in B602 findings
cwe: CWE-78
source_url: https://owasp.org/www-community/attacks/Command_Injection
---
OWASP describes command injection as unintended operating-system commands executed through a vulnerable application. A B602 warning is therefore a prompt to inspect the complete data flow, not only the line containing `shell=True`. Values can arrive indirectly through environment variables, uploaded filenames, job definitions, database records, or helper functions. Shell metacharacters are one route; attacker control over the executable name or option values can also change behavior.

Prefer a library API for the underlying operation. For example, use filesystem functions for copying and archive libraries for extraction instead of launching shell utilities. When a child process is necessary, use an argument array, choose the program in code, validate each argument according to its purpose, and separate user-controlled operands from options. Some programs support a `--` delimiter, but reviewers should confirm the selected program actually honors it.

Avoid denylist filters for characters such as semicolons because shells have many equivalent constructions and platform rules differ. Escaping should be a last resort for a narrowly defined legacy interface. Also remove sensitive environment variables, run with minimal permissions, and capture only the output the application needs. These measures limit consequences while the argument boundary prevents the injection itself.

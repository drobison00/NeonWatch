# Security

NeonWatch runs an agent as root, so a security problem in it matters. Please report one through
a [GitHub security advisory](https://github.com/drobison00/NeonWatch/security/advisories/new)
on this repository, not a public issue. Say what you found, how to reproduce it, and what it
lets someone do.

What NeonWatch claims, and what it does not, is set out in the README's *Before you run it as
root* section and in `docs/design.md`. The known limitations there, such as the agent running
code your account can modify and running unconfined in manual mode, are documented rather than
secret. A report that shows one of them is worse than documented is welcome.

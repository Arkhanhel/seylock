# Security

Please report vulnerabilities privately through GitHub's private
vulnerability reporting on the repository ("Security" tab, "Report a
vulnerability"). Do not open a public issue for a vulnerability. We
acknowledge reports within 3 working days, give an initial assessment within
10 working days, and disclose in coordination with the reporter.

What is in scope: list signature checks and freshness rules, the local
proxy's access control (loopback only, token), certificate validation on
every path, and memory safety of the C ABI.

The protocol is described in PROTOCOL.md; the adversaries, what the library
does and does not protect against, and the audit scope are in
THREAT_MODEL.md.

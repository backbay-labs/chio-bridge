# Signed owner recovery qualification

Source 52f8051 adds an operator-only importer. It does not dispatch or acknowledge
resource actions. The complete bridge suite passes 131 tests with zero skips.
The archive SHA256 is 02a0e4ad4e61ffb989302cae8774a9ae9ab8f647473f1926d1e671673169a37b.
It installed with an empty npm cache and offline mode. Four independently run
native hosts recovered exact retained signed owner results, explicitly
acknowledged them and performed one read with no repeated write. Each refused a
forged signed record and a missing retained result. Native records identify the
owning host evidence commits. This does not establish all integration gates.

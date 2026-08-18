# Temporary release-gate fixture. The test script loads and unloads this
# profile; it is not installed as a production policy.
#include <tunables/global>

profile ferrocrate-security-test flags=(attach_disconnected) {
  #include <abstractions/base>

  /bin/sh rix,
  /usr/bin/cat rix,
  /usr/bin/true rix,
  deny /etc/shadow r,
}

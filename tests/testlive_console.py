#!/usr/bin/env python3
"""Live coverage for the console shells.

app/Console/Command is 12,572 statements at 1.22% - MISP's single largest
dark block. Shells cannot be reached over HTTP, so they are exercised here by
invoking the cake console directly. Under the coverage instrumentation
(build/coverage/covcollect.php is an auto_prepend_file for the CLI SAPI too)
these runs are attributed like any other.

Only read-only invocations are used, and each shell is probed with an INVALID
subcommand rather than bare. That distinction matters: a bare invocation can
trigger a shell's default action, and `cake Live` with no argument takes the
instance offline.

Usage:
    MISP_ROOT=/var/www/MISP python3 testlive_console.py -v
"""
import os
import subprocess
import sys
import unittest

MISP_ROOT = os.environ.get("MISP_ROOT", "/var/www/MISP")
CAKE = os.path.join(MISP_ROOT, "app", "Console", "cake")

# Shells probed for their usage output.
#
# DELIBERATELY EXCLUDED, because invoking them bare MUTATES the instance:
#   Live      - `cake Live` with no argument takes MISP OFFLINE. Running it
#               here once set MISP.live=false and every PyMISP-based suite
#               that followed failed to connect, with an error that pointed
#               at PyMISP rather than at the cause.
#   Password  - resets credentials.
#   Admin     - has subcommands that write settings; probed only with an
#               invalid subcommand below, never bare.
SHELLS = [
    "Admin", "Event", "Server", "User", "Training",
    "EventGraph", "Log", "Sighting", "Statistics",
]

# Probing with an invalid subcommand forces the option parser to print usage
# and exit. A bare invocation can run a shell's DEFAULT action, which is how
# `cake Live` silently disabled the instance.
USAGE_PROBE = "__usage_probe_not_a_subcommand__"


def run_cake(*args: str, timeout: int = 120) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["sudo", "-u", "www-data", CAKE, *args],
        capture_output=True, text=True, timeout=timeout, cwd=MISP_ROOT,
    )


class TestConsoleShells(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        if not os.path.exists(CAKE):
            raise unittest.SkipTest(f"cake console not found at {CAKE}")

    def test_console_lists_available_commands(self) -> None:
        """A bare `cake` lists the available shells and runs none of them.

        This one IS safe without the probe: with no shell name the dispatcher
        prints its command list. The hazard is `cake <Shell>` with no
        subcommand, which can run that shell's default action.
        """
        result = run_cake()
        output = (result.stdout or "") + (result.stderr or "")
        self.assertTrue(output.strip(), "the console must print its command list")
        self.assertNotIn("Fatal error", output, "listing commands must not fatal")

    def test_each_shell_reports_its_usage(self) -> None:
        """Every shell must respond to an unknown/absent subcommand with usage.

        This exercises each shell's option parser and help output - the part
        that is pure argument handling and needs no database state.
        """
        failures = []
        for shell in SHELLS:
            try:
                result = run_cake(shell, USAGE_PROBE)
            except subprocess.TimeoutExpired:
                failures.append((shell, "timeout"))
                continue
            output = (result.stdout or "") + (result.stderr or "")
            if not output.strip():
                failures.append((shell, "no output"))
            elif "Fatal error" in output or "PHP Fatal" in output:
                failures.append((shell, output.strip().splitlines()[0][:120]))

        self.assertEqual([], failures, f"shells failed to report usage: {failures}")

    def test_admin_shell_exposes_its_subcommands(self) -> None:
        result = run_cake("Admin", USAGE_PROBE)
        output = (result.stdout or "") + (result.stderr or "")
        self.assertNotIn("Fatal error", output)
        self.assertTrue(output.strip(), "Admin shell must print its subcommands")

    def test_unknown_shell_is_reported_cleanly(self) -> None:
        result = run_cake("ThisShellDoesNotExist")
        output = (result.stdout or "") + (result.stderr or "")
        self.assertNotIn("Fatal error", output, "an unknown shell must not fatal")


if __name__ == "__main__":
    unittest.main(verbosity=2)

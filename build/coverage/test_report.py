"""Unit tests for the coverage reporter.

The property that matters: union counts each covered line once, however
many suites covered it. Getting that wrong would silently inflate the
headline number.
"""
import json
import subprocess
import sys
import textwrap
from pathlib import Path

CLOVER = textwrap.dedent("""\
    <?xml version="1.0" encoding="UTF-8"?>
    <coverage><project>
      <file name="/app/Lib/Tools/A.php">
        <line num="1" type="stmt" count="1"/>
        <line num="2" type="stmt" count="0"/>
        <line num="3" type="stmt" count="0"/>
        <line num="4" type="stmt" count="0"/>
      </file>
    </project></coverage>
""")

REPORT = str(Path(__file__).with_name("report.py"))


def _run(tmp_path: Path, live_lines: list[int]) -> dict:
    clover = tmp_path / "clover.xml"
    clover.write_text(CLOVER)
    merged = tmp_path / "merged.json"
    merged.write_text(json.dumps({"Lib/Tools/A.php": live_lines}))
    summary = tmp_path / "summary.json"
    subprocess.run(
        [sys.executable, REPORT, str(clover), str(merged), "--json", str(summary)],
        capture_output=True, text=True, check=True,
    )
    return json.loads(summary.read_text())


def test_disjoint_suites_sum_in_union(tmp_path: Path) -> None:
    # unit covers line 1; live covers 2 and 3; union = 3/4.
    s = _run(tmp_path, [2, 3])
    assert s["statements"] == 4
    assert s["unit_pct"] == 25.0
    assert s["live_pct"] == 50.0
    assert s["union_pct"] == 75.0
    assert s["both_lines"] == 0


def test_overlapping_line_counted_once(tmp_path: Path) -> None:
    # live also covers line 1, which unit already covered.
    s = _run(tmp_path, [1, 2])
    assert s["unit_pct"] == 25.0
    assert s["live_pct"] == 50.0
    assert s["union_pct"] == 50.0, "an overlapping line must not be double-counted"
    assert s["both_lines"] == 1


def test_live_lines_outside_the_statement_map_are_ignored(tmp_path: Path) -> None:
    # pcov reports lines clover does not consider executable statements.
    s = _run(tmp_path, [2, 99])
    assert s["live_pct"] == 25.0


def test_min_union_gate_fails_below_threshold(tmp_path: Path) -> None:
    clover = tmp_path / "clover.xml"; clover.write_text(CLOVER)
    merged = tmp_path / "merged.json"; merged.write_text(json.dumps({"Lib/Tools/A.php": [2]}))
    r = subprocess.run(
        [sys.executable, REPORT, str(clover), str(merged), "--min-union", "99"],
        capture_output=True, text=True,
    )
    assert r.returncode == 1
    assert "FAIL: union" in r.stdout


def test_min_union_lines_gate_fails_below_threshold(tmp_path: Path) -> None:
    clover = tmp_path / "clover.xml"; clover.write_text(CLOVER)
    merged = tmp_path / "merged.json"; merged.write_text(json.dumps({"Lib/Tools/A.php": [2]}))
    r = subprocess.run(
        [sys.executable, REPORT, str(clover), str(merged), "--min-union-lines", "3"],
        capture_output=True, text=True,
    )
    assert r.returncode == 1
    assert "FAIL: union 2 lines" in r.stdout


def test_min_union_lines_gate_ignores_a_growing_denominator(tmp_path: Path) -> None:
    """The property the percentage gate lacks.

    Same tests, same covered lines, twice as much code in the tree: the
    percentage halves, the lines gate does not move.
    """
    grown = CLOVER.replace(
        "</file>",
        "</file>\n  <file name=\"/app/Lib/Tools/B.php\">\n"
        + "\n".join(f'    <line num="{n}" type="stmt" count="0"/>' for n in range(1, 5))
        + "\n  </file>",
    )
    clover = tmp_path / "clover.xml"; clover.write_text(grown)
    merged = tmp_path / "merged.json"; merged.write_text(json.dumps({"Lib/Tools/A.php": [2, 3]}))
    args = [sys.executable, REPORT, str(clover), str(merged)]
    percent = subprocess.run(args + ["--min-union", "75"], capture_output=True, text=True)
    lines = subprocess.run(args + ["--min-union-lines", "3"], capture_output=True, text=True)
    assert percent.returncode == 1, "the percentage gate trips on code growth alone"
    assert lines.returncode == 0, "the lines gate must not trip on code growth alone"

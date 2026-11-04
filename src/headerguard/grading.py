"""Turn findings into a score out of 100 and an A-F grade.

Every check has a weight that reflects how much it matters. A failed check
loses its full weight, a warning loses half, and a pass loses nothing.
"""

from __future__ import annotations

from dataclasses import dataclass

from headerguard.headers import FAIL, WARN, Finding

# How many points each check is worth. Unknown checks default to 3.
WEIGHTS: dict[str, int] = {
    "Content-Security-Policy": 25,
    "Strict-Transport-Security": 20,
    "X-Frame-Options": 15,
    "X-Content-Type-Options": 10,
    "Referrer-Policy": 5,
    "Permissions-Policy": 5,
}
DEFAULT_WEIGHT = 3

# Lowest score needed for each grade, checked from the top down.
GRADE_BANDS: list[tuple[int, str]] = [
    (90, "A"),
    (75, "B"),
    (60, "C"),
    (45, "D"),
    (30, "E"),
    (0, "F"),
]


@dataclass
class Grade:
    score: int
    letter: str
    passed: int
    warnings: int
    failed: int


def penalty(finding: Finding) -> float:
    weight = WEIGHTS.get(finding.header, DEFAULT_WEIGHT)
    if finding.status == FAIL:
        return weight
    if finding.status == WARN:
        return weight / 2
    return 0


def letter_for(score: int) -> str:
    for minimum, letter in GRADE_BANDS:
        if score >= minimum:
            return letter
    return "F"


def grade(findings: list[Finding]) -> Grade:
    score = round(max(0.0, 100 - sum(penalty(f) for f in findings)))
    failed = sum(f.status == FAIL for f in findings)
    warnings = sum(f.status == WARN for f in findings)
    return Grade(
        score=score,
        letter=letter_for(score),
        passed=len(findings) - failed - warnings,
        warnings=warnings,
        failed=failed,
    )

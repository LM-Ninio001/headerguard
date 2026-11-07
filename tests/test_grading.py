import pytest

from headerguard.grading import DEFAULT_WEIGHT, grade, letter_for, penalty
from headerguard.headers import FAIL, PASS, WARN, Finding


def finding(header, status):
    return Finding(header, status, "msg", "risk", "fix")


def test_penalty_full_half_none():
    assert penalty(finding("Content-Security-Policy", FAIL)) == 25
    assert penalty(finding("Content-Security-Policy", WARN)) == 12.5
    assert penalty(finding("Content-Security-Policy", PASS)) == 0


def test_unknown_check_uses_default_weight():
    assert penalty(finding("Something-New", FAIL)) == DEFAULT_WEIGHT


@pytest.mark.parametrize(
    ("score", "letter"),
    [(100, "A"), (90, "A"), (89, "B"), (75, "B"), (60, "C"), (45, "D"), (30, "E"), (29, "F"), (0, "F")],
)
def test_letter_bands(score, letter):
    assert letter_for(score) == letter


def test_perfect_site():
    result = grade([finding("Content-Security-Policy", PASS), finding("HTTPS", PASS)])
    assert (result.score, result.letter, result.passed) == (100, "A", 2)


def test_score_never_negative():
    checks = ["HTTPS", "TLS Certificate", "Content-Security-Policy", "Strict-Transport-Security"]
    result = grade([finding(name, FAIL) for name in checks])  # 115 points of penalties
    assert result.score == 0
    assert result.letter == "F"
    assert result.failed == 4


def test_counts():
    result = grade([finding("A", PASS), finding("B", WARN), finding("C", WARN), finding("D", FAIL)])
    assert (result.passed, result.warnings, result.failed) == (1, 2, 1)

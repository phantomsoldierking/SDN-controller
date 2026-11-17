"""PASS / FAIL / SKIP bookkeeping for the testbed scenarios."""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field


@dataclass
class Check:
    name: str
    ok: bool | None  # None = skipped
    detail: str = ""

    @property
    def tag(self) -> str:
        return "SKIP" if self.ok is None else ("PASS" if self.ok else "FAIL")


@dataclass
class Report:
    checks: list[Check] = field(default_factory=list)
    data: dict = field(default_factory=dict)  # measurements behind the checks

    def add(self, name: str, ok: bool | None, detail: str = "") -> None:
        check = Check(name, ok, detail)
        self.checks.append(check)
        print(f"[{check.tag}] {name}" + (f" - {detail}" if detail else ""))

    def skip(self, name: str, reason: str) -> None:
        self.add(name, None, reason)

    @property
    def passed(self) -> bool:
        return all(c.ok is not False for c in self.checks)

    def save(self, path: str, label: str) -> None:
        with open(path, "w") as f:
            json.dump({"mode": label, "passed": self.passed,
                       "checks": [{**asdict(c), "result": c.tag} for c in self.checks],
                       "data": self.data}, f, indent=2)

    def print_summary(self) -> None:
        print("\n" + "=" * 72)
        for c in self.checks:
            print(f"  {c.tag:<5} {c.name:<44} {c.detail}")
        print("=" * 72)

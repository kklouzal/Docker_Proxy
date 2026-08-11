from __future__ import annotations

from pathlib import Path

from lxml import html

TEMPLATES = Path(__file__).resolve().parents[1] / "templates"


def test_every_admin_form_control_has_an_accessible_name() -> None:
    """Keep first-party template controls named without a browser dependency."""
    failures: list[str] = []

    for template in sorted(TEMPLATES.glob("*.html")):
        document = html.fromstring(template.read_text(encoding="utf-8"))
        label_targets = {label.get("for") for label in document.xpath("//label[@for]")}

        for control in document.xpath("//input | //select | //textarea | //button"):
            if (
                control.tag == "input"
                and control.get("type", "text").lower() == "hidden"
            ):
                continue

            visible_text = " ".join(control.text_content().split())
            has_name = bool(
                control.get("aria-label", "").strip()
                or control.get("aria-labelledby", "").strip()
                or (control.get("id") and control.get("id") in label_targets)
                or control.xpath("ancestor::label")
                or (control.tag == "button" and visible_text)
            )
            if not has_name:
                failures.append(f"{template.name}:{control.sourceline} <{control.tag}>")

            if (
                control.tag == "textarea"
                and not control.get("name")
                and control.get("readonly") is None
            ):
                failures.append(
                    f"{template.name}:{control.sourceline} output textarea is not readonly"
                )

    assert not failures, "Unnamed or mutable output controls:\n" + "\n".join(failures)

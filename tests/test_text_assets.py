from pathlib import Path


ROOT = Path(__file__).parents[1]
TEXT_SUFFIXES = {".md", ".py", ".yaml", ".yml", ".html", ".js", ".css", ".service", ".timer"}
MOJIBAKE_MARKERS = ("\u9286\u3006", "\u951b\uff0c", "\u7eef\u8373\u7cba\u7cba",
                    "\u7039\u590a\u53cf", "\u93ac\u4f7a\u5a0d", "\u9225")


def test_user_facing_text_assets_are_valid_utf8_without_mojibake():
    failures = []
    for path in ROOT.rglob("*"):
        if (not path.is_file() or path.suffix.lower() not in TEXT_SUFFIXES
                or any(part in {".venv", "build", "dist", ".git", ".pytest_cache"}
                       for part in path.relative_to(ROOT).parts)):
            continue
        text = path.read_text(encoding="utf-8")
        if "\ufffd" in text or any(0xE000 <= ord(char) <= 0xF8FF for char in text):
            failures.append(f"{path}: replacement/private-use character")
        for marker in MOJIBAKE_MARKERS:
            if marker in text:
                failures.append(f"{path}: mojibake marker {marker}")
    assert not failures, "\n".join(failures)

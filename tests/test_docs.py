# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Marek Cingel

import json
from pathlib import Path
import re
import shlex
import unittest

from scripts import run_differential as differential

ROOT = Path(__file__).resolve().parents[1]
README = ROOT / "README.md"
GUIDES = sorted((ROOT / "docs").glob("*.md"))
PAGES = [README, *GUIDES]
FENCE = re.compile(r"^ *```.*?^ *```", re.M | re.S)
LINK = re.compile(r"\]\(([^)\s]+)\)|^\[[\w-]+\]:\s*(\S+)", re.M)


def prose(path):
    return FENCE.sub("", path.read_text(encoding="utf-8"))


def anchors(path):
    headings = re.findall(r"^#+\s+(.*)$", prose(path), re.M)
    return {re.sub(r"[^\w\- ]", "", heading.replace("`", "").lower()).replace(" ", "-") for heading in headings}


def documented_commands(path):
    """Each `python3 scripts/...` line of a shell block, split into arguments."""
    for block in re.findall(r"^ *```sh\n(.*?)^ *```", path.read_text(encoding="utf-8"), re.M | re.S):
        for line in block.splitlines():
            arguments = shlex.split(line)
            if arguments[1:2] and arguments[0] == "python3" and arguments[1].startswith("scripts/"):
                yield arguments[1:]


class DocumentationTests(unittest.TestCase):
    def test_every_local_link_and_anchor_resolves(self):
        for page in PAGES:
            for match in LINK.finditer(prose(page)):
                link = match.group(1) or match.group(2)
                if link.startswith("http"):
                    continue
                with self.subTest(page=page.name, link=link):
                    target, _, anchor = link.partition("#")
                    resolved = (page.parent / target).resolve() if target else page
                    self.assertTrue(resolved.exists())
                    if anchor:
                        self.assertIn(anchor, anchors(resolved))

    def test_readme_links_every_guide(self):
        links = {match.group(1) for match in LINK.finditer(prose(README))}
        for guide in GUIDES:
            self.assertIn(guide.relative_to(ROOT).as_posix(), links)

    def test_documented_commands_use_real_scripts_options_and_fixtures(self):
        seen = set()
        for page in PAGES:
            for script, *arguments in documented_commands(page):
                with self.subTest(page=page.name, script=script, arguments=arguments):
                    source = (ROOT / script).read_text(encoding="utf-8")
                    seen.add(script)
                    for argument in arguments:
                        if argument.startswith("--"):
                            self.assertIn(f'"{argument}"', source)
                    if "--fixtures" in arguments:
                        corpus = ROOT / arguments[arguments.index("--fixtures") + 1]
                        identifiers = {fixture["id"] for fixture in differential.load_corpus(corpus)["fixtures"]}
                        # The guide's "Add a fixture" command names an entry a contributor has yet to add.
                        if page == README and "--fixture" in arguments:
                            self.assertIn(arguments[arguments.index("--fixture") + 1], identifiers)
        self.assertEqual(seen, {path.relative_to(ROOT).as_posix() for path in (ROOT / "scripts").glob("*.py")})

    def test_fixture_example_is_valid(self):
        text = (ROOT / "docs/differential-runner.md").read_text(encoding="utf-8")
        section = text.split("## Add a fixture", 1)[1].split("\n## ", 1)[0]
        example = json.loads(re.search(r"```json\n(.*?)```", section, re.S).group(1))
        differential.validate_fixture(example)
        corpus = differential.load_corpus(ROOT / "differential/fixtures/asn1-ber.json")
        self.assertIn(example["category"], differential.CATEGORIES)
        self.assertNotIn(example["id"], {fixture["id"] for fixture in corpus["fixtures"]})

    def test_documentation_states_the_committed_corpus_totals(self):
        corpus = differential.load_corpus(ROOT / "differential/fixtures/asn1-ber.json")
        counts = {name: 0 for name in differential.CLASSIFICATIONS}
        for fixture in corpus["fixtures"]:
            counts[fixture["classification"]] += 1
        summary = (f"{counts['shared']} pass, 0 mismatch, {counts['unsupported']} unsupported, "
                   f"{counts['inconclusive']} inconclusive")
        self.assertIn(summary, README.read_text(encoding="utf-8"))

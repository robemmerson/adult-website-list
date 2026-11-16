import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))

import domains  # noqa: E402


class ExtractTests(unittest.TestCase):
    def test_formats(self):
        cases = {
            "example.com": ["example.com"],
            "  Example.COM  ": ["example.com"],
            "0.0.0.0 example.com": ["example.com"],
            "127.0.0.1 a.com b.com # note": ["a.com", "b.com"],
            "||example.com^$third-party": ["example.com"],
            "https://www.example.com:8443/path?q=1": ["www.example.com"],
            "example.com/some/page": ["example.com"],
            "*.example.com": ["example.com"],
            "address=/example.com/0.0.0.0": ["example.com"],
            "example.com.": ["example.com"],
            "example.com # trailing comment": ["example.com"],
            "# comment": [],
            "! adblock comment": [],
            "[Adblock Plus 2.0]": [],
            "@@||allowed.com^": [],
            "": [],
            "127.0.0.1 localhost": [],
            "85.17.187.83": ["85.17.187.83"],
        }
        for line, expected in cases.items():
            with self.subTest(line=line):
                self.assertEqual(domains.extract(line), expected)


class ValidationTests(unittest.TestCase):
    def test_valid(self):
        for domain in ("example.com", "www.example.co.uk", "a-b.example.xxx", "1.hot-dances.com", "0xxx.ws"):
            with self.subTest(domain=domain):
                self.assertIsNone(domains.invalid_reason(domain))

    def test_unifi_rules(self):
        # The entries that were removed from the upstream list by hand.
        cases = {
            "85.17.187.83": "IP address",
            "2001:db8::1": "IP address",
            "forgotten_dark_angel.tripod.com": "underscore",
            "free--webcams.com": "double dash",
            "top.x--x--x.com": "double dash",
            "xn--80ak6aa92e.com": "double dash",
            "hdgaytube.xxx!": "ends in invalid character",
            "pornid.xxx..": "ends in invalid character",
            "example.com-": "ends in invalid character",
            "collectionofbestporn": "no top-level domain",
            "exa$mple.com": "invalid character",
            "a..example.com": "empty label",
            "-a.example.com": "label starts or ends with a dash",
            "example.123": "invalid top-level domain",
            "a" * 64 + ".com": "too long",
        }
        for domain, expected in cases.items():
            with self.subTest(domain=domain):
                self.assertEqual(domains.invalid_reason(domain), expected)


class ProcessTests(unittest.TestCase):
    def test_dedupes_and_rejects(self):
        lines = [
            "new-site.com",
            "NEW-SITE.com",
            "0.0.0.0 already.com",
            "bad_site.com",
            "https://another.net/page",
        ]
        new, rejected = domains.process(lines, existing={"already.com"}, add_www=False)
        self.assertEqual(new, ["another.net", "new-site.com"])
        self.assertEqual(
            rejected,
            [
                ("new-site.com", "duplicate in input"),
                ("already.com", "already in list"),
                ("bad_site.com", "underscore"),
            ],
        )


class WwwTests(unittest.TestCase):
    def test_variant(self):
        cases = {
            "example.com": "www.example.com",
            "example.co.uk": "www.example.co.uk",
            "www.example.com": None,
            "blog.example.com": None,
            "someone.tumblr.com": None,
            "www.example.co.uk": None,
        }
        for domain, expected in cases.items():
            with self.subTest(domain=domain):
                self.assertEqual(domains.www_variant(domain), expected)

    def test_process_adds_www_forms(self):
        lines = ["new-site.com", "already.com", "has-www.com", "www.explicit.com", "sub.site.com", "bad_site.com"]
        existing = {"already.com", "has-www.com", "www.has-www.com"}
        new, rejected = domains.process(lines, existing)
        self.assertEqual(
            new,
            ["new-site.com", "sub.site.com", "www.already.com", "www.explicit.com", "www.new-site.com"],
        )
        self.assertNotIn("duplicate in input", [reason for _, reason in rejected])


class ActivityTests(unittest.TestCase):
    def test_classification(self):
        up = lambda addresses: True
        down = lambda addresses: False
        self.assertEqual(domains.activity("a.com", lambda d: ["1.1.1.1"], up), "active")
        self.assertEqual(domains.activity("a.com", lambda d: ["1.1.1.1"], down), "no web server")
        self.assertEqual(domains.activity("a.com", lambda d: [], up), "no DNS record")
        self.assertEqual(domains.activity("a.com", lambda d: None, up), "lookup failed")

    def test_lookup_is_retried_once(self):
        replies = [None, ["1.1.1.1"]]
        self.assertEqual(domains.activity("a.com", lambda d: replies.pop(0), lambda a: True), "active")


class ImportCommandTests(unittest.TestCase):
    def run_import(self, source_text, list_text, *extra):
        with tempfile.TemporaryDirectory() as folder:
            target = Path(folder, "list.txt")
            target.write_text(list_text)
            source = Path(folder, "source.txt")
            source.write_text(source_text)
            code = domains.main(["--list", str(target), "import", str(source), *extra])
            return code, target.read_text()

    def test_merges_sorted_without_duplicates(self):
        code, result = self.run_import("zeta.com\nalpha.com\nmid.com\nbad--one.com\n", "beta.com\nmid.com\n", "--no-www")
        self.assertEqual(code, 0)
        self.assertEqual(result, "alpha.com\nbeta.com\nmid.com\nzeta.com\n")

    def test_dry_run_leaves_list_alone(self):
        _, result = self.run_import("alpha.com\n", "beta.com\n", "--dry-run")
        self.assertEqual(result, "beta.com\n")


class LintTests(unittest.TestCase):
    def test_clean(self):
        self.assertEqual(domains.lint(["a.com", "b.com"]), [])

    def test_problems(self):
        problems = domains.lint(["b.com", "a.com", "a.com", "bad_one.com"])
        self.assertEqual(len(problems), 3)

    def test_repository_list_is_clean(self):
        lines = domains.DEFAULT_LIST.read_text().splitlines()
        self.assertEqual(domains.lint(lines), [])


if __name__ == "__main__":
    unittest.main()

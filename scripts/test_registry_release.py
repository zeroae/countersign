import base64
import hashlib
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import registry_release as release


class RegistryReleaseTests(unittest.TestCase):
    def test_tag_must_match_every_package(self):
        packages = [{"version": "0.2.0-rc.1"}]
        release.verify_tag("v0.2.0-rc.1", "0.2.0-rc.1", packages)
        for tag, widget in [("v0.2.0", "0.2.0-rc.1"), ("v0.2.0", "0.2.0")]:
            with self.subTest(tag=tag, widget=widget), self.assertRaises(SystemExit):
                release.verify_tag(tag, widget, packages)

    @patch("registry_release.subprocess.run")
    @patch("registry_release.registry_version")
    def test_crates_resume_only_missing_versions(self, lookup, run):
        digest = hashlib.sha256(b"built crate").hexdigest()
        published = {"version": {"checksum": digest, "yanked": False}}
        packages = [{"name": name} for name in ["first", "second"]]
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            for package in packages:
                (directory / f"{package['name']}-1.0.0.crate").write_bytes(b"built crate")
            lookup.side_effect = [published, None]
            release.publish_crates(directory, "1.0.0", packages)
            self.assertEqual(run.call_args.args[0][-2:], ["--package", "second"])
            run.reset_mock()
            for checksum, yanked in [(digest, True), ("different", False)]:
                lookup.side_effect = [None, {"version": {"checksum": checksum, "yanked": yanked}}]
                with self.assertRaises(SystemExit):
                    release.publish_crates(directory, "1.0.0", packages)
                run.assert_not_called()

    @patch("registry_release.subprocess.run")
    @patch("registry_release.registry_version")
    def test_widget_dist_tags_and_retries(self, lookup, run):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            (directory / "widget.tgz").write_bytes(b"widget")
            lookup.return_value = None
            for version, tag in [("1.0.0", "latest"), ("1.0.1-beta.2", "next")]:
                release.publish_widget(directory, version, "@zeroae/countersign-widget")
                self.assertEqual(run.call_args.args[0][-2:], ["--tag", tag])
            run.reset_mock()
            digest = base64.b64encode(hashlib.sha512(b"widget").digest()).decode()
            lookup.return_value = {"dist": {"integrity": "sha512-" + digest}}
            release.publish_widget(directory, "1.0.0", "@zeroae/countersign-widget")
            lookup.return_value = {"dist": {"integrity": "sha512-different"}}
            with self.assertRaises(SystemExit):
                release.publish_widget(directory, "1.0.0", "@zeroae/countersign-widget")
            run.assert_not_called()

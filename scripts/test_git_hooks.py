"""The tracked pre-commit hook and the session-start command that installs it.

Each test copies the hook's files into a throwaway repository, so nothing here
touches the checkout's own Git configuration.
"""

import json
import os
import shutil
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FILES = [
    ".githooks/pre-commit",
    "scripts/install-git-hooks.sh",
    ".claude/settings.json",
    "rust-toolchain.toml",
    "Cargo.toml",
    "eslint.config.mjs",
]
UNFORMATTED = "fn main(){let x=1;}\n"
FORMATTED = "fn main() {\n    let x = 1;\n}\n"


def git_env(extra=None):
    env = dict(os.environ)
    for key in list(env):
        if key.startswith("GIT_"):
            del env[key]
    env.update(
        GIT_CONFIG_GLOBAL=os.devnull,
        GIT_CONFIG_NOSYSTEM="1",
        GIT_AUTHOR_NAME="Test",
        GIT_AUTHOR_EMAIL="test@example.invalid",
        GIT_COMMITTER_NAME="Test",
        GIT_COMMITTER_EMAIL="test@example.invalid",
    )
    env.update(extra or {})
    return env


def run(args, cwd, env=None, check=True):
    result = subprocess.run(
        args, cwd=cwd, env=env or git_env(), capture_output=True, text=True, timeout=60
    )
    if check and result.returncode != 0:
        raise AssertionError(f"{args} failed:\n{result.stdout}\n{result.stderr}")
    return result


def session_start_commands():
    settings = json.loads((ROOT / ".claude/settings.json").read_text())
    return [
        hook["command"]
        for entry in settings["hooks"]["SessionStart"]
        for hook in entry["hooks"]
        if hook["type"] == "command"
    ]


class GitHooksTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.main = self.tmp / "main"
        self.main.mkdir()
        run(["git", "init", "-q", "-b", "main"], self.main)
        for name in FILES:
            target = self.main / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / name, target)
        run(["git", "add", "-A"], self.main)
        run(["git", "commit", "-q", "-m", "init"], self.main)
        self.worktree = self.tmp / "fresh"
        run(["git", "worktree", "add", "-q", "--detach", str(self.worktree)], self.main)

    def start_session(self, directory):
        outputs = []
        for command in session_start_commands():
            result = run(
                ["bash", "-c", command],
                directory,
                env=git_env({"CLAUDE_PROJECT_DIR": str(directory)}),
            )
            outputs.append(result.stdout + result.stderr)
        return "".join(outputs)

    def stage(self, files):
        for name, text in files.items():
            path = self.worktree / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text)
        run(["git", "add", "--", *files], self.worktree)

    def commit(self, files, env=None, prefix=()):
        self.stage(files)
        args = [*prefix, "git", "commit", "-q", "-m", "change"]
        return run(args, self.worktree, env=env, check=False)

    def test_fresh_worktree_refuses_unformatted_rust_after_session_start(self):
        self.start_session(self.worktree)
        result = self.commit({"src/lib.rs": UNFORMATTED})
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("src/lib.rs", result.stderr)
        self.assertIn("cargo fmt", result.stderr)

    def test_hook_checks_the_staged_copy_not_the_working_tree(self):
        self.start_session(self.worktree)
        (self.worktree / "src").mkdir()
        (self.worktree / "src/lib.rs").write_text(UNFORMATTED)
        run(["git", "add", "src/lib.rs"], self.worktree)
        (self.worktree / "src/lib.rs").write_text(FORMATTED)
        result = run(["git", "commit", "-q", "-m", "change"], self.worktree, check=False)
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)

    def link_node_modules(self):
        node_modules = ROOT / "node_modules"
        if not (node_modules / ".bin/eslint").exists():
            common = run(["git", "rev-parse", "--path-format=absolute", "--git-common-dir"], ROOT)
            node_modules = Path(common.stdout.strip()).parent / "node_modules"
        if not (node_modules / ".bin/eslint").exists():
            self.fail("ESLint is not installed: run 'pnpm install' in this checkout")
        (self.worktree / "node_modules").symlink_to(node_modules)

    def test_hook_refuses_javascript_that_fails_eslint(self):
        self.start_session(self.worktree)
        self.link_node_modules()
        result = self.commit({"packages/widget/src/bad.js": "undefinedName();\n"})
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("no-undef", result.stderr)
        run(["git", "rm", "-q", "--cached", "packages/widget/src/bad.js"], self.worktree)
        good = self.commit({"packages/widget/src/good.js": "export const x = 1;\n"})
        self.assertEqual(good.returncode, 0, good.stdout + good.stderr)

    def test_hook_lints_only_what_pnpm_lint_lints(self):
        self.start_session(self.worktree)
        self.link_node_modules()
        for name in ["distribution/npm/launch.cjs", "scripts/tool.mjs", "crates/x/tests/addon.cjs"]:
            with self.subTest(name=name):
                result = self.commit({name: "undefinedName();\n"})
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_hook_without_node_modules_skips_eslint_and_says_so(self):
        self.start_session(self.worktree)
        result = self.commit({"packages/widget/src/bad.js": "undefinedName();\n"})
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("ESLint skipped", result.stderr)

    def test_hook_names_a_pinned_toolchain_that_is_not_installed(self):
        toolchain = self.worktree / "rust-toolchain.toml"
        toolchain.write_text(toolchain.read_text().replace("1.99.0", "0.0.1"))
        run(["git", "commit", "-q", "-am", "pin a missing toolchain"], self.worktree)
        self.start_session(self.worktree)
        result = self.commit({"src/lib.rs": FORMATTED})
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("0.0.1", result.stderr)
        self.assertIn("rustup show", result.stderr)

    def test_one_rust_and_one_markdown_file_commit_in_under_five_seconds(self):
        self.start_session(self.worktree)
        started = time.monotonic()
        result = self.commit({"src/lib.rs": FORMATTED, "NOTES.md": "# Notes\n\nText.\n"})
        elapsed = time.monotonic() - started
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        print(f"\npre-commit: one .rs and one .md file committed in {elapsed:.2f} s")
        self.assertLess(elapsed, 5.0)

    def test_session_start_is_a_no_op_when_already_installed(self):
        self.start_session(self.worktree)
        config = (self.main / ".git/config").read_text()
        self.assertEqual(self.start_session(self.worktree), "")
        self.assertEqual((self.main / ".git/config").read_text(), config)

    def test_session_start_leaves_another_hooks_path_alone(self):
        run(["git", "config", "core.hooksPath", "/elsewhere"], self.main)
        output = self.start_session(self.worktree)
        self.assertIn("/elsewhere", output)
        hooks_path = run(["git", "config", "core.hooksPath"], self.main).stdout.strip()
        self.assertEqual(hooks_path, "/elsewhere")

    def test_session_start_leaves_hooks_in_the_hooks_folder_alone(self):
        target = self.tmp / "managed-hook"
        target.write_text("#!/bin/sh\nexit 0\n")
        target.chmod(0o755)
        for kind in ["file", "symlink"]:
            with self.subTest(kind=kind):
                hook = self.main / ".git/hooks/pre-push"
                hook.unlink(missing_ok=True)
                if kind == "file":
                    shutil.copy2(target, hook)
                else:
                    hook.symlink_to(target)
                output = self.start_session(self.worktree)
                self.assertIn("pre-push", output)
                unset = run(["git", "config", "core.hooksPath"], self.main, check=False)
                self.assertEqual(unset.stdout, "")

    def test_session_start_installs_when_the_hooks_folder_is_a_symlink(self):
        hooks = self.main / ".git/hooks"
        moved = self.tmp / "hooks-folder"
        shutil.move(hooks, moved)
        hooks.symlink_to(moved)
        self.start_session(self.worktree)
        hooks_path = run(["git", "config", "core.hooksPath"], self.main).stdout.strip()
        self.assertEqual(hooks_path, ".githooks")

    def test_hook_runs_no_build_no_test_and_no_network(self):
        self.start_session(self.worktree)
        shims = self.tmp / "shims"
        shims.mkdir()
        log = self.tmp / "forbidden.log"
        for name in ["cargo", "pnpm", "npm", "npx", "curl", "wget", "python3"]:
            shim = shims / name
            shim.write_text(f'#!/bin/sh\necho "{name} $*" >> "{log}"\nexit 1\n')
            shim.chmod(0o755)
        env = git_env({"PATH": f"{shims}{os.pathsep}{os.environ['PATH']}"})
        trace = self.tmp / "trace"
        prefix = ()
        if shutil.which("strace"):
            prefix = ("strace", "-f", "-qq", "-e", "trace=connect", "-o", str(trace))
        files = {"src/lib.rs": FORMATTED, "NOTES.md": "# Notes\n"}
        result = self.commit(files, env=env, prefix=prefix)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse(log.exists(), log.read_text() if log.exists() else "")
        if trace.exists():
            network = [
                line for line in trace.read_text().splitlines()
                if "AF_INET" in line
            ]
            self.assertEqual(network, [])


if __name__ == "__main__":
    unittest.main()

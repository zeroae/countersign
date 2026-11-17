"""Run protected pairing tests using isolated daemon sessions and an encrypted login keyring."""
import json
import os
import pathlib
import secrets
import shutil
import subprocess
import sys
import tempfile

TEST = pathlib.Path(__file__).with_name("addon.cjs").resolve()

def in_session(stage, addon, record):
    if stage != "locked":
        # The unlock secret is supplied on stdin across process boundaries.
        subprocess.run(["gnome-keyring-daemon", "--unlock", "--components=secrets"],
                       input=sys.stdin.buffer.read(), stdout=subprocess.DEVNULL, check=True)
    subprocess.run(["node", str(TEST), addon, stage, record], check=True, timeout=50)
    if stage == "create":
        locator = json.loads(pathlib.Path(record).read_text())["locator"]
        token_password = subprocess.run(["secret-tool", "lookup", "application", "Countersign",
                                         "kind", "pairing", "locator", locator],
                                        capture_output=True, check=True, timeout=10).stdout.rstrip(b"\n")
        assert len(token_password) == 32
        for path in pathlib.Path(os.environ["XDG_DATA_HOME"]).rglob("*"):
            if path.is_file():
                assert token_password not in path.read_bytes(), "plaintext NSS unlock found"

def main():
    if len(sys.argv) == 5:
        in_session(*sys.argv[2:])
        return
    source = pathlib.Path(sys.argv[1]).resolve()
    with tempfile.TemporaryDirectory(prefix="countersign-keyring-") as temp:
        folder = pathlib.Path(temp)
        addon = folder / "countersign.node"
        shutil.copyfile(source, addon)
        password = secrets.token_hex(32).encode()
        env = dict(os.environ, XDG_DATA_HOME=str(folder/"data"), XDG_CONFIG_HOME=str(folder/"config"))
        env.pop("GNOME_KEYRING_CONTROL", None)
        for stage in ("create", "reopen", "locked", "retire"):
            runtime = folder / stage
            runtime.mkdir(mode=0o700)
            env["XDG_RUNTIME_DIR"] = str(runtime)
            subprocess.run(["dbus-run-session", "--", sys.executable, __file__, "--session", stage,
                            str(addon), str(folder/"public.json")], input=password if stage!="locked" else b"",
                           env=env, check=True, timeout=75)
            if stage == "create":
                keyring = folder / "data/keyrings/login.keyring"
                assert keyring.read_bytes().startswith(b"GnomeKeyring\n\r\x00\n"), "expected protected GNOME login keyring format"
                for path in (folder/"data").rglob("*"):
                    if path.is_file():
                        assert password not in path.read_bytes(), "plaintext collection unlock found"
if __name__ == "__main__":
    main()

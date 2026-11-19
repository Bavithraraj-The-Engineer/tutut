"""
Tests for automatic wrapping (tutut/autowrap.py) and the background service
(tutut/service.py): watcher, install, uninstall, status.

All file system effects happen in temporary directories.
"""

import json
import os
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).parent.parent))

from tutut import autowrap, config as config_mod, service
from tutut.config import GuardianConfig

CMD = "/opt/tutut/venv/bin/tutut"
GUI = ["--display", ":0", "--xauthority", "/run/user/1000/gdm/Xauthority"]


def _fs_entry():
    return {"command": "npx", "args": ["-y", "@srv/fs", "/tmp"], "env": {"K": "v"}}


class TestWrapEntry(unittest.TestCase):

    def test_wrap_layout(self):
        wrapped = autowrap.wrap_entry("fs", _fs_entry(), command=CMD, gui=GUI)
        self.assertEqual(wrapped["command"], CMD)
        self.assertEqual(
            wrapped["args"],
            ["stdio", "--server-name", "fs"] + GUI + ["--", "npx", "-y", "@srv/fs", "/tmp"],
        )
        self.assertEqual(wrapped["env"], {"K": "v"})  # env untouched

    def test_roundtrip_is_exact(self):
        original = dict(_fs_entry(), disabled=False)
        wrapped = autowrap.wrap_entry("fs", original, command=CMD, gui=GUI)
        self.assertEqual(autowrap.unwrap_entry(wrapped), original)

    def test_is_wrapped(self):
        wrapped = autowrap.wrap_entry("fs", _fs_entry(), command=CMD, gui=[])
        self.assertTrue(autowrap.is_wrapped(wrapped))
        self.assertTrue(autowrap.is_wrapped(
            {"command": "tutut", "args": ["stdio", "--server-name", "x", "--", "uvx", "y"]}
        ))
        self.assertFalse(autowrap.is_wrapped(_fs_entry()))
        self.assertFalse(autowrap.is_wrapped({"url": "https://example.com/mcp"}))
        self.assertFalse(autowrap.is_wrapped({"command": CMD, "args": ["status"]}))
        self.assertFalse(autowrap.is_wrapped("not a dict"))

    def test_desired_entry_skips_url_and_malformed(self):
        for entry in ({"url": "https://x/mcp"}, {"command": ""}, {"command": "x", "args": "bad"}, None):
            self.assertIsNone(autowrap.desired_entry("s", entry, command=CMD, gui=GUI))

    def test_correct_entry_needs_no_change(self):
        wrapped = autowrap.wrap_entry("fs", _fs_entry(), command=CMD, gui=GUI)
        self.assertIsNone(autowrap.desired_entry("fs", wrapped, command=CMD, gui=GUI))

    def test_old_bare_tutut_entry_is_updated(self):
        old = {"command": "tutut", "args": ["stdio", "--server-name", "fs", "--", "npx", "-y", "@srv/fs"]}
        new = autowrap.desired_entry("fs", old, command=CMD, gui=GUI)
        self.assertEqual(new["command"], CMD)
        self.assertEqual(new["args"][-3:], ["npx", "-y", "@srv/fs"])
        self.assertIn("--display", new["args"])

    def test_display_change_updates_entry(self):
        wrapped = autowrap.wrap_entry("fs", _fs_entry(), command=CMD, gui=["--display", ":0"])
        new = autowrap.desired_entry("fs", wrapped, command=CMD, gui=["--display", ":1"])
        self.assertIn(":1", new["args"])
        self.assertNotIn(":0", new["args"])

    def test_no_display_keeps_recorded_display(self):
        """A watcher started without DISPLAY must not strip working options."""
        wrapped = autowrap.wrap_entry("fs", _fs_entry(), command=CMD, gui=GUI)
        self.assertIsNone(autowrap.desired_entry("fs", wrapped, command=CMD, gui=[]))

    def test_gui_args(self):
        env = {"DISPLAY": ":1", "XAUTHORITY": "/x"}
        with mock.patch.object(autowrap.platform, "system", return_value="Linux"):
            self.assertEqual(autowrap.gui_args(env), ["--display", ":1", "--xauthority", "/x"])
            self.assertEqual(autowrap.gui_args({}), [])
            self.assertEqual(autowrap.gui_args({"XAUTHORITY": "/x"}), [])
        with mock.patch.object(autowrap.platform, "system", return_value="Darwin"):
            self.assertEqual(autowrap.gui_args(env), [])

    def test_tutut_executable_is_absolute(self):
        cmd = autowrap.tutut_executable()
        if cmd != "tutut":
            self.assertTrue(Path(cmd).is_absolute())


class TestReconcile(unittest.TestCase):

    def _config(self):
        return {
            "preferences": {"keep": True},
            "mcpServers": {
                "fs": _fs_entry(),
                "remote": {"url": "https://example.com/mcp"},
                "mine": {"command": "python", "args": ["-m", "srv"]},
            },
        }

    def test_wraps_eligible_servers_only(self):
        cfg = self._config()
        new, changes = autowrap.reconcile(cfg, command=CMD, gui=GUI)
        self.assertEqual(changes, {"fs": "wrapped", "mine": "wrapped"})
        self.assertEqual(new["preferences"], {"keep": True})
        self.assertEqual(new["mcpServers"]["remote"], {"url": "https://example.com/mcp"})
        self.assertEqual(cfg, self._config())  # input not mutated

    def test_idempotent(self):
        new, _ = autowrap.reconcile(self._config(), command=CMD, gui=GUI)
        again, changes = autowrap.reconcile(new, command=CMD, gui=GUI)
        self.assertEqual(changes, {})
        self.assertEqual(again, new)

    def test_exclude_unwraps_and_skips(self):
        new, _ = autowrap.reconcile(self._config(), command=CMD, gui=GUI)
        excluded, changes = autowrap.reconcile(new, command=CMD, gui=GUI, exclude=["fs"])
        self.assertEqual(changes, {"fs": "unwrapped"})
        self.assertEqual(excluded["mcpServers"]["fs"], _fs_entry())

    def test_unwrap_all_restores_original(self):
        new, _ = autowrap.reconcile(self._config(), command=CMD, gui=GUI)
        restored, changes = autowrap.unwrap_all(new)
        self.assertEqual(set(changes), {"fs", "mine"})
        self.assertEqual(restored, self._config())

    def test_no_servers_key(self):
        new, changes = autowrap.reconcile({"preferences": {}}, command=CMD, gui=GUI)
        self.assertEqual(changes, {})
        self.assertEqual(new, {"preferences": {}})


class TestApplyToFile(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "claude_desktop_config.json"
        self.data = {"preferences": {"a": 1}, "mcpServers": {"fs": _fs_entry()}}
        self.path.write_text(json.dumps(self.data))
        self.path.chmod(0o600)

    def tearDown(self):
        self.tmp.cleanup()

    def test_writes_atomically_and_keeps_mode(self):
        changes = autowrap.apply_to_file(self.path, command=CMD, gui=GUI)
        self.assertEqual(changes, {"fs": "wrapped"})
        data = json.loads(self.path.read_text())
        self.assertEqual(data["mcpServers"]["fs"]["command"], CMD)
        self.assertEqual(data["preferences"], {"a": 1})
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)
        self.assertEqual([p.name for p in Path(self.tmp.name).iterdir()], [self.path.name])

    def test_invalid_json_is_left_alone(self):
        self.path.write_text("{ not json")
        self.assertEqual(autowrap.apply_to_file(self.path, command=CMD, gui=GUI), {})
        self.assertEqual(self.path.read_text(), "{ not json")

    def test_missing_file(self):
        self.path.unlink()
        self.assertEqual(autowrap.apply_to_file(self.path, command=CMD, gui=GUI), {})

    def test_concurrent_change_aborts_write(self):
        original_read = autowrap.read_config_text
        calls = []

        def read_then_someone_writes(path):
            text = original_read(path)
            calls.append(1)
            if len(calls) == 1:  # Claude Desktop writes right after our first read
                path.write_text(json.dumps(dict(self.data, preferences={"a": 2})))
            return text

        with mock.patch.object(autowrap, "read_config_text", side_effect=read_then_someone_writes):
            self.assertEqual(autowrap.apply_to_file(self.path, command=CMD, gui=GUI), {})
        self.assertEqual(json.loads(self.path.read_text())["preferences"], {"a": 2})

    def test_unwrap(self):
        autowrap.apply_to_file(self.path, command=CMD, gui=GUI)
        changes = autowrap.apply_to_file(self.path, unwrap=True)
        self.assertEqual(changes, {"fs": "unwrapped"})
        self.assertEqual(json.loads(self.path.read_text()), self.data)


class ServiceTestCase(unittest.TestCase):
    """Redirects every tutut/XDG path into a temporary home."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        home = Path(self.tmp.name)
        self.tutut_dir = home / ".config" / "tutut"
        self.tutut_config = self.tutut_dir / "config.json"
        self.claude_config = home / ".config" / "Claude" / "claude_desktop_config.json"
        self.claude_config.parent.mkdir(parents=True)
        self.claude_config.write_text(json.dumps({"preferences": {}, "mcpServers": {"fs": _fs_entry()}}))
        patches = [
            mock.patch.object(config_mod, "DEFAULT_CONFIG_FILE", self.tutut_config),
            mock.patch.object(service, "DEFAULT_CONFIG_FILE", self.tutut_config),
            mock.patch.object(service, "DEFAULT_CONFIG_DIR", self.tutut_dir),
            mock.patch.object(service, "PID_FILE", self.tutut_dir / "watch.pid"),
            mock.patch.dict(os.environ, {"XDG_CONFIG_HOME": str(home / ".config")}),
            mock.patch.object(autowrap, "tutut_executable", return_value=CMD),
            mock.patch.object(autowrap, "gui_args", return_value=list(GUI)),
            mock.patch.object(service, "notify"),
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)

    def tearDown(self):
        self.tmp.cleanup()

    def servers(self):
        return json.loads(self.claude_config.read_text())["mcpServers"]


class TestInstallUninstall(ServiceTestCase):

    def test_install_creates_config_autostart_and_wraps(self):
        with mock.patch("tutut.gui._TK_AVAILABLE", True), \
                mock.patch.object(service.platform, "system", return_value="Linux"):
            lines = service.install(claude_config=self.claude_config, start=False)

        cfg = GuardianConfig.load(self.tutut_config)
        self.assertEqual(cfg.popup_timeout, service.DEFAULT_POPUP_TIMEOUT)
        entry = service.autostart_path().read_text()
        self.assertIn(f'Exec="{CMD}" watch', entry)
        self.assertTrue(autowrap.is_wrapped(self.servers()["fs"]))
        self.assertTrue(any("Restart Claude Desktop" in line for line in lines))

    def test_install_keeps_existing_config(self):
        GuardianConfig(popup_timeout=7).save(self.tutut_config)
        with mock.patch("tutut.gui._TK_AVAILABLE", True), \
                mock.patch.object(service.platform, "system", return_value="Linux"):
            service.install(claude_config=self.claude_config, start=False)
        self.assertEqual(GuardianConfig.load(self.tutut_config).popup_timeout, 7)

    def test_install_refuses_without_tkinter(self):
        with mock.patch("tutut.gui._TK_AVAILABLE", False), \
                mock.patch.object(service.platform, "system", return_value="Linux"):
            with self.assertRaises(service.InstallError):
                service.install(claude_config=self.claude_config, start=False)
        self.assertFalse(service.autostart_path().exists())

    def test_install_refuses_on_other_os(self):
        with mock.patch.object(service.platform, "system", return_value="Darwin"):
            with self.assertRaises(service.InstallError):
                service.install(claude_config=self.claude_config, start=False)

    def test_uninstall_restores_everything(self):
        with mock.patch("tutut.gui._TK_AVAILABLE", True), \
                mock.patch.object(service.platform, "system", return_value="Linux"):
            service.install(claude_config=self.claude_config, start=False)
        service.uninstall(claude_config=self.claude_config)
        self.assertFalse(service.autostart_path().exists())
        self.assertEqual(self.servers()["fs"], _fs_entry())

    def test_status(self):
        lines = "\n".join(service.status(claude_config=self.claude_config))
        self.assertIn("Watcher:   not running", lines)
        self.assertIn("Unguarded: fs", lines)


class TestWatcher(ServiceTestCase):

    def _run_watcher(self):
        stop = threading.Event()
        thread = threading.Thread(
            target=service.watch,
            args=(self.claude_config,),
            kwargs={"config_path": self.tutut_config, "interval": 0.05, "stop": stop},
        )
        thread.start()
        self.addCleanup(lambda: (stop.set(), thread.join(5)))
        return stop, thread

    def _wait_for(self, predicate, timeout=5.0):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if predicate():
                return True
            time.sleep(0.05)
        return False

    def test_wraps_existing_and_newly_added_servers(self):
        self._run_watcher()
        self.assertTrue(self._wait_for(lambda: autowrap.is_wrapped(self.servers()["fs"])))

        # The user adds a new server while the watcher runs
        data = json.loads(self.claude_config.read_text())
        data["mcpServers"]["github"] = {"command": "npx", "args": ["-y", "@srv/github"]}
        self.claude_config.write_text(json.dumps(data))

        self.assertTrue(self._wait_for(lambda: autowrap.is_wrapped(self.servers().get("github"))))
        service.notify.assert_called()

    def test_exclusion_in_tutut_config_is_honoured_live(self):
        self._run_watcher()
        self.assertTrue(self._wait_for(lambda: autowrap.is_wrapped(self.servers()["fs"])))
        GuardianConfig(autowrap_exclude=["fs"]).save(self.tutut_config)
        self.assertTrue(self._wait_for(lambda: self.servers()["fs"] == _fs_entry()))

    def test_second_watcher_exits_immediately(self):
        self._run_watcher()
        self.assertTrue(self._wait_for(lambda: (self.tutut_dir / "watch.pid").exists()))
        time.sleep(0.1)
        self.assertEqual(
            service.watch(self.claude_config, config_path=self.tutut_config,
                          interval=0.05, stop=threading.Event()),
            0,
        )


class TestStdioDisplayOptions(unittest.TestCase):

    def test_only_fill_missing_env(self):
        from tutut import cli

        with mock.patch.dict(cli.os.environ, {}, clear=True):
            cli._apply_gui_env(":0", "/tmp/xauth")
            self.assertEqual(cli.os.environ["DISPLAY"], ":0")
            self.assertEqual(cli.os.environ["XAUTHORITY"], "/tmp/xauth")
        with mock.patch.dict(cli.os.environ, {"DISPLAY": ":5"}, clear=True):
            cli._apply_gui_env(":0", None)
            self.assertEqual(cli.os.environ["DISPLAY"], ":5")

    def test_config_roundtrip_with_exclude(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "c.json"
            GuardianConfig(autowrap_exclude=["a", "b"]).save(path)
            self.assertEqual(GuardianConfig.load(path).autowrap_exclude, ["a", "b"])


if __name__ == "__main__":
    unittest.main()

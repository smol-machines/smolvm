#!/usr/bin/env python3
"""Boot as a regular host user and verify guest root and mount ownership.

Requires SMOLVM, SMOLVM_AGENT_ROOTFS, bundled libraries and KVM or HVF.
Uses only a private copy of the rootfs and isolated machine state.
"""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


def main():
    assert os.getuid() != 0, "Run as a regular host user; root masks this regression"
    engine = str(Path(os.environ["SMOLVM"]).resolve())
    source = Path(os.environ["SMOLVM_AGENT_ROOTFS"]).resolve()
    root = Path(tempfile.mkdtemp(prefix="smol-root-ownership-"))
    state = root / "state"
    rootfs = root / "rootfs"
    mount = root / "mount"
    env = dict(os.environ, SMOLVM_DATA_DIR=str(state),
               SMOLVM_AGENT_ROOTFS=str(rootfs), XDG_CACHE_HOME=str(root / "cache"))
    name = "ownership"
    steps = []

    def sm(*args):
        result = subprocess.run([engine, "--state-dir", str(state), "machine", *args],
                                env=env, capture_output=True, text=True, timeout=120)
        if result.returncode:
            raise RuntimeError(f"{args[0]} failed: {result.stderr}\n{result.stdout}")
        return result.stdout.strip()

    def ownership():
        text = sm("exec", "--name", name, "--", "stat", "-c", "%n %u %g %a",
                  "/etc", "/usr/local/bin/smolvm-agent", "/usr/bin/crun", "/sbin/init")
        rows = [line.split() for line in text.splitlines()]
        assert len(rows) == 4 and all(r[1:3] == ["0", "0"] for r in rows), text

    try:
        shutil.copytree(source, rootfs, symlinks=True)
        mount.mkdir()
        (mount / "file").write_text("host mount\n")
        explicit = rootfs / "etc/smol-owned-fixture"
        explicit.write_text("original\n")
        if sys.platform == "darwin":
            subprocess.run(["xattr", "-w", "user.containers.override_stat",
                            "1234:5678:0640", str(explicit)], check=True)
        else:
            os.setxattr(explicit, "user.containers.override_stat", b"1234:5678:0640")
        host_before = (explicit.stat().st_uid, explicit.stat().st_gid)
        assert json.loads(sm("ls", "--json")) == []
        sm("create", "--name", name, "--cpus", "1", "--mem", "512", "--storage", "1",
           "--overlay", "1", "--volume", str(mount) + ":/host-check:ro")
        sm("start", "--name", name)
        ownership()
        steps.append("base system and symlinks belong to guest root")
        temporary = sm("exec", "--name", name, "--", "stat", "-c", "%u:%g:%a", "/tmp", "/var/tmp")
        assert temporary.splitlines() == ["0:0:1777", "0:0:1777"], temporary
        explicit_owner = sm("exec", "--name", name, "--", "stat", "-c", "%u:%g:%a",
                            "/etc/smol-owned-fixture")
        assert explicit_owner == "1234:5678:640", explicit_owner
        steps.append("explicit file ownership and permissions take precedence")
        host_owner = sm("exec", "--name", name, "--", "stat", "-c", "%u:%g", "/host-check/file")
        expected = f"{(mount / 'file').stat().st_uid}:{(mount / 'file').stat().st_gid}"
        assert host_owner == expected, (host_owner, expected)
        steps.append("host mounts retain their independent ownership")
        sm("exec", "--name", name, "--", "adduser", "-D", "-u", str(os.getuid()), "smol-owner-test")
        sm("exec", "--name", name, "--", "su", "-s", "/bin/sh", "smol-owner-test", "-c",
           "if touch /etc/smol-unprivileged-write 2>/dev/null; then exit 77; fi; "
           "touch /tmp/smol-user-write")
        steps.append("guest user cannot write system directories and can write tmp")
        sm("pause", "--name", name)
        sm("resume", "--name", name)
        ownership()
        assert sm("exec", "--name", name, "--", "stat", "-c", "%u", "/tmp/smol-user-write") == str(os.getuid())
        assert explicit.read_text() == "original\n"
        assert (explicit.stat().st_uid, explicit.stat().st_gid) == host_before
        steps.append("pause/resume keeps ownership and never changes host files")
    finally:
        rows = json.loads(sm("ls", "--json"))
        assert all(row["name"] == name for row in rows), rows
        if rows:
            sm("delete", "--name", name, "--force")
        assert json.loads(sm("ls", "--json")) == []
        shutil.rmtree(root)
    print(json.dumps({"phase": "passed", "checks": steps, "cleanup_empty": True}))


if __name__ == "__main__":
    main()

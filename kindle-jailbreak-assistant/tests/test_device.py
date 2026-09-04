import json
import os
import plistlib
import shutil
import stat
import subprocess
import sys
import tempfile
import textwrap
import unittest
from dataclasses import dataclass
from pathlib import Path

from kindle_jailbreak_lib.device import probe_devices, read_firmware, redact_serial


PROJECT_ROOT = Path(__file__).resolve().parents[1]
FIXTURES = Path(__file__).parent / "fixtures"
LINUX_ADAPTER = PROJECT_ROOT / "scripts" / "kindle_mtp_linux.sh"
POWERSHELL_ADAPTER = PROJECT_ROOT / "scripts" / "kindle_mtp_windows.ps1"


@dataclass
class RunResult:
    stdout: str
    returncode: int = 0
    stderr: str = ""


class FixtureRunner:
    def __init__(self, responses, path_map=None):
        self.responses = responses
        self.path_map = path_map or {}
        self.calls = []

    def __call__(self, argv):
        if not isinstance(argv, (list, tuple)):
            raise AssertionError("runner 必须接收 argv 列表，不得接收 shell 命令字符串")
        key = tuple(str(item) for item in argv)
        self.calls.append(key)
        response = self.responses.get(key)
        if response is None:
            raise AssertionError(f"未预期的命令：{key!r}")
        return response

    def resolve_path(self, platform_path):
        return self.path_map.get(platform_path, platform_path)


class WindowsProbeRunner:
    def __init__(self, volumes, mtp, path_map):
        self.volumes = volumes
        self.mtp = mtp
        self.path_map = path_map
        self.calls = []

    def __call__(self, argv):
        if not isinstance(argv, (list, tuple)):
            raise AssertionError("Windows runner 必须接收 argv 列表")
        argv = tuple(str(item) for item in argv)
        self.calls.append(argv)
        if "-Command" in argv:
            command = argv[-1]
            if "Win32_LogicalDiskToPartition" not in command:
                raise AssertionError("缺少逻辑盘到分区的 CIM 关联")
            if "Win32_DiskDriveToDiskPartition" not in command:
                raise AssertionError("缺少分区到物理磁盘的 CIM 关联")
            if "MSFT_Disk" not in command:
                raise AssertionError("缺少物理磁盘只读状态查询")
            if "VolumeSerialNumber" in command or "Select-Object" in command:
                raise AssertionError("不得把逻辑卷字段当成物理设备身份")
            return RunResult(self.volumes)
        if "-File" in argv and argv[-1] == "list":
            if "-FixturePath" in argv:
                raise AssertionError("生产探测不得传入 PowerShell fixture 参数")
            return RunResult(self.mtp)
        raise AssertionError(f"未预期的 Windows 命令：{argv!r}")

    def resolve_path(self, platform_path):
        return self.path_map.get(platform_path, platform_path)


def read_sections(name):
    sections = {}
    current = None
    lines = []
    for line in (FIXTURES / name).read_text(encoding="utf-8").splitlines():
        if line.startswith("--- ") and line.endswith(" ---"):
            if current is not None:
                sections[current] = "\n".join(lines) + "\n"
            current = line[4:-4]
            lines = []
        else:
            lines.append(line)
    if current is not None:
        sections[current] = "\n".join(lines) + "\n"
    return sections


class DeviceProbeTest(unittest.TestCase):
    def test_reads_firmware_from_mass_storage_without_modifying_device(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "Kindle"
            (root / "documents").mkdir(parents=True)
            (root / "system").mkdir()
            version = root / "system" / "version.txt"
            version.write_text(
                "Kindle 5.16.2.1.1 (409747 002)\n", encoding="utf-8"
            )
            before = version.read_bytes()

            self.assertEqual(read_firmware(root), "5.16.2.1.1")
            self.assertEqual(version.read_bytes(), before)

    def test_read_firmware_rejects_unrelated_or_missing_version_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "system").mkdir()
            version = root / "system" / "version.txt"
            version.write_text("Linux version 5.16.2\n", encoding="utf-8")

            self.assertIsNone(read_firmware(root))
            version.unlink()
            self.assertIsNone(read_firmware(root))

    def test_macos_combines_diskutil_and_ioreg_without_exposing_serial(self):
        with tempfile.TemporaryDirectory() as tmp:
            local_root = Path(tmp) / "Kindle"
            platform_root = "/Volumes/Kindle"
            (local_root / "documents").mkdir(parents=True)
            (local_root / "system").mkdir()
            (local_root / "system" / "version.txt").write_text(
                "Kindle 5.16.2.1.1 (409747 002)\n", encoding="utf-8"
            )
            sections = {
                key: value.replace("{ROOT}", platform_root)
                for key, value in read_sections("macos-usb.txt").items()
            }
            runner = FixtureRunner({
                ("diskutil", "list", "-plist"): RunResult(sections["DISKUTIL LIST"]),
                ("diskutil", "info", "-plist", platform_root): RunResult(
                    sections["DISKUTIL INFO"]
                ),
                ("ioreg", "-r", "-c", "IOUSBHostDevice", "-l"): RunResult(
                    sections["IOREG"]
                ),
                ("ioreg", "-a", "-r", "-c", "IOUSBHostDevice", "-l"): RunResult(
                    sections["IOREG"]
                ),
            }, path_map={platform_root: local_root})

            devices = probe_devices("Darwin", runner)

            self.assertEqual(len(devices), 1)
            self.assertEqual(devices[0].transport, "usbms")
            self.assertEqual(devices[0].root, platform_root)
            self.assertEqual(devices[0].model, "Kindle Paperwhite")
            self.assertEqual(devices[0].firmware, "5.16.2.1.1")
            self.assertEqual(devices[0].free_bytes, 987654321)
            public_output = json.dumps(devices[0].public_dict(), ensure_ascii=False)
            self.assertNotIn("G090KB0TESTX05TK", public_output)
            self.assertEqual(redact_serial("G090KB0TESTX05TK"), "…05TK")

    def test_macos_without_safe_mass_storage_requires_approval(self):
        empty_plist = (
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            '<plist version="1.0"><dict><key>AllDisksAndPartitions</key>'
            '<array/></dict></plist>\n'
        )
        runner = FixtureRunner({
            ("diskutil", "list", "-plist"): RunResult(empty_plist),
            ("ioreg", "-a", "-r", "-c", "IOUSBHostDevice", "-l"): RunResult(""),
        })

        devices = probe_devices("macOS", runner)

        self.assertEqual(len(devices), 1)
        self.assertEqual(devices[0].transport, "needs_official_tool_or_approval")
        self.assertIsNone(devices[0].root)

    def test_macos_maps_duplicate_names_by_whole_disk_identity(self):
        with tempfile.TemporaryDirectory() as tmp:
            local_roots = [Path(tmp) / "one" / "Kindle", Path(tmp) / "two" / "Kindle"]
            platform_roots = ["/Volumes/Kindle", "/Volumes/Kindle 2"]
            for root in local_roots:
                (root / "documents").mkdir(parents=True)
            list_output = plistlib.dumps({
                "AllDisksAndPartitions": [{
                    "Partitions": [
                        {"MountPoint": platform_roots[0]},
                        {"MountPoint": platform_roots[1]},
                    ],
                }],
            }).decode("utf-8")
            info_outputs = {
                platform_root: plistlib.dumps({
                    "MountPoint": platform_root,
                    "VolumeName": "Kindle",
                    "BusProtocol": "USB",
                    "Internal": False,
                    "Ejectable": True,
                    "ReadOnlyVolume": False,
                    "ParentWholeDisk": f"disk{index + 7}",
                }).decode("utf-8")
                for index, platform_root in enumerate(platform_roots)
            }
            ioreg = plistlib.dumps([
                {
                    "USB Product Name": "Kindle",
                    "USB Serial Number": "SERIAL-FIRST",
                    "USB Vendor Name": "Amazon",
                    "IORegistryEntryChildren": [{"BSD Name": "disk7"}],
                },
                {
                    "USB Product Name": "Kindle",
                    "USB Serial Number": "SERIAL-SECOND",
                    "USB Vendor Name": "Amazon",
                    "IORegistryEntryChildren": [{"BSD Name": "disk8"}],
                },
            ]).decode("utf-8")
            responses = {
                ("diskutil", "list", "-plist"): RunResult(list_output),
                ("ioreg", "-r", "-c", "IOUSBHostDevice", "-l"): RunResult(ioreg),
                ("ioreg", "-a", "-r", "-c", "IOUSBHostDevice", "-l"): RunResult(ioreg),
            }
            responses.update({
                ("diskutil", "info", "-plist", root): RunResult(output)
                for root, output in info_outputs.items()
            })

            devices = probe_devices("Darwin", FixtureRunner(
                responses,
                path_map=dict(zip(platform_roots, local_roots)),
            ))

            self.assertEqual(len(devices), 2)
            self.assertEqual([device.root for device in devices], [
                platform_roots[0], platform_roots[1],
            ])
            self.assertEqual([device.serial for device in devices], [
                "SERIAL-FIRST", "SERIAL-SECOND",
            ])

    def test_macos_rejects_same_name_volume_with_unrelated_ioreg_serial(self):
        with tempfile.TemporaryDirectory() as tmp:
            local_root = Path(tmp) / "Backup"
            platform_root = "/Volumes/Kindle"
            (local_root / "documents").mkdir(parents=True)
            list_output = plistlib.dumps({
                "AllDisksAndPartitions": [{
                    "Partitions": [{"MountPoint": platform_root}],
                }],
            }).decode("utf-8")
            info_output = plistlib.dumps({
                "MountPoint": platform_root,
                "VolumeName": "Kindle",
                "BusProtocol": "USB",
                "Internal": False,
                "Ejectable": True,
                "ParentWholeDisk": "disk8",
            }).decode("utf-8")
            ioreg = plistlib.dumps([{
                "USB Product Name": "Kindle",
                "USB Serial Number": "UNRELATED-SERIAL",
                "USB Vendor Name": "Amazon",
                "IORegistryEntryChildren": [{"BSD Name": "disk7"}],
            }]).decode("utf-8")
            runner = FixtureRunner({
                ("diskutil", "list", "-plist"): RunResult(list_output),
                ("diskutil", "info", "-plist", platform_root): RunResult(info_output),
                ("ioreg", "-r", "-c", "IOUSBHostDevice", "-l"): RunResult(ioreg),
                ("ioreg", "-a", "-r", "-c", "IOUSBHostDevice", "-l"): RunResult(ioreg),
            }, path_map={platform_root: local_root})

            devices = probe_devices("Darwin", runner)

            self.assertEqual(len(devices), 1)
            self.assertEqual(devices[0].transport, "needs_official_tool_or_approval")
            self.assertIsNone(devices[0].serial)

    def test_macos_rejects_kindle_mount_outside_volumes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "Kindle"
            (root / "documents").mkdir(parents=True)
            (root / "system").mkdir()
            (root / "system" / "version.txt").write_text(
                "Kindle 5.16.2.1.1\n", encoding="utf-8"
            )
            list_output = plistlib.dumps({
                "AllDisksAndPartitions": [{
                    "Partitions": [{"MountPoint": str(root)}],
                }],
            }).decode("utf-8")
            info_output = plistlib.dumps({
                "MountPoint": str(root),
                "VolumeName": "Kindle",
                "BusProtocol": "USB",
                "Internal": False,
                "Ejectable": True,
                "ParentWholeDisk": "disk7",
            }).decode("utf-8")
            ioreg = plistlib.dumps([{
                "USB Product Name": "Kindle",
                "USB Serial Number": "MATCHED-SERIAL",
                "USB Vendor Name": "Amazon",
                "IORegistryEntryChildren": [{"BSD Name": "disk7"}],
            }]).decode("utf-8")
            runner = FixtureRunner({
                ("diskutil", "list", "-plist"): RunResult(list_output),
                ("diskutil", "info", "-plist", str(root)): RunResult(info_output),
                ("ioreg", "-a", "-r", "-c", "IOUSBHostDevice", "-l"): RunResult(ioreg),
            })

            devices = probe_devices("Darwin", runner)

            self.assertEqual(len(devices), 1)
            self.assertEqual(devices[0].transport, "needs_official_tool_or_approval")

    def test_linux_rejects_kindle_mount_in_system_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "Kindle"
            home_root = Path(tmp) / "HomeKindle"
            (root / "documents").mkdir(parents=True)
            (home_root / "documents").mkdir(parents=True)
            (root / "system").mkdir()
            (root / "system" / "version.txt").write_text(
                "Kindle 5.16.2.1.1\n", encoding="utf-8"
            )
            linux_mtp = PROJECT_ROOT / "scripts" / "kindle_mtp_linux.sh"
            runner = FixtureRunner({
                ("cat", "/proc/mounts"): RunResult(
                    f"/dev/sdb1 {root} vfat rw,nosuid,nodev 0 0\n"
                    "/dev/sdc1 /home/alice/Kindle vfat rw,nosuid,nodev 0 0\n"
                ),
                (
                    "udevadm", "info", "--query=property", "--name", "/dev/sdb1",
                ): RunResult(
                    "ID_BUS=usb\nID_VENDOR=Amazon\nID_MODEL=Kindle\n"
                    "ID_SERIAL_SHORT=SYSTEM-PATH-SERIAL\n"
                ),
                (str(linux_mtp), "list"): RunResult(
                    '{"ok":true,"action":"list","devices":[]}\n'
                ),
            }, path_map={"/home/alice/Kindle": home_root})

            self.assertEqual(probe_devices("Linux", runner), [])

    def test_linux_preserves_duplicate_kindle_names_and_rejects_system_disk(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            local_system_root = base / "system"
            local_first_root = base / "one" / "Kindle"
            local_second_root = base / "two" / "Kindle"
            for root in (local_system_root, local_first_root, local_second_root):
                (root / "documents").mkdir(parents=True)
            (local_system_root / "system").mkdir()
            (local_system_root / "system" / "version.txt").write_text(
                "Kindle 5.99.0\n", encoding="utf-8"
            )
            platform_system_root = "/"
            platform_first_root = "/media/alice/Kindle"
            platform_second_root = "/run/media/bob/Kindle"
            mounts = (FIXTURES / "linux-mounts.txt").read_text(encoding="utf-8")
            mounts = mounts.format(
                SYSTEM_ROOT=platform_system_root,
                ROOT1=platform_first_root,
                ROOT2=platform_second_root,
            )
            linux_mtp = PROJECT_ROOT / "scripts" / "kindle_mtp_linux.sh"
            runner = FixtureRunner({
                ("cat", "/proc/mounts"): RunResult(mounts),
                (
                    "udevadm", "info", "--query=property", "--name", "/dev/sda2",
                ): RunResult("ID_BUS=ata\nID_MODEL=Internal_SSD\n"),
                (
                    "udevadm", "info", "--query=property", "--name", "/dev/sdb1",
                ): RunResult(
                    "ID_BUS=usb\nID_VENDOR=Amazon\nID_MODEL=Kindle\n"
                    "ID_SERIAL_SHORT=LINUXSERIAL0001\n"
                ),
                (
                    "udevadm", "info", "--query=property", "--name", "/dev/sdc1",
                ): RunResult(
                    "ID_BUS=usb\nID_VENDOR=Amazon\nID_MODEL=Kindle\n"
                    "ID_SERIAL_SHORT=LINUXSERIAL0002\n"
                ),
                (str(linux_mtp), "list"): RunResult(
                    '{"ok":false,"action":"list","error_code":'
                    '"mtp_unavailable","message":"未检测到可用的 MTP 传输能力"}\n',
                    returncode=1,
                ),
            }, path_map={
                platform_system_root: local_system_root,
                platform_first_root: local_first_root,
                platform_second_root: local_second_root,
            })

            devices = probe_devices("Linux", runner)

            self.assertEqual(len(devices), 2)
            self.assertEqual([device.root for device in devices], [
                platform_first_root, platform_second_root,
            ])
            self.assertEqual([device.serial for device in devices], [
                "LINUXSERIAL0001", "LINUXSERIAL0002",
            ])

    def test_windows_combines_removable_volume_and_mtp_devices(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            system_root = base / "system"
            kindle_root = base / "Kindle"
            unknown_root = base / "UnknownKindle"
            for root in (system_root, kindle_root, unknown_root):
                (root / "documents").mkdir(parents=True)
            (unknown_root / "system").mkdir()
            (unknown_root / "system" / "version.txt").write_text(
                "Kindle 5.16.3\n", encoding="utf-8"
            )
            volumes = (FIXTURES / "windows-volumes.json").read_text(encoding="utf-8")
            runner = WindowsProbeRunner(
                volumes,
                '{"ok":true,"action":"list","devices":['
                '{"id":"d467c05e343f7640fe5aa899","name":"Kindle Scribe",'
                '"storage":"Internal Storage"},'
                '{"id":"72a379a9a8a344d21e4704a8","name":"Kindle Scribe",'
                '"storage":"Internal Storage"}]}',
                {"C:\\": system_root, "E:\\": kindle_root, "F:\\": unknown_root},
            )

            devices = probe_devices("Windows", runner)

            self.assertEqual(len(devices), 3)
            self.assertEqual(devices[0].transport, "usbms")
            self.assertEqual(devices[0].root, "E:\\")
            self.assertEqual(devices[0].free_bytes, 777000000)
            self.assertEqual(devices[0].model, "Kindle Internal Storage USB Device")
            self.assertEqual(devices[0].serial, "B0D4A1C200000001")
            self.assertIs(devices[0].read_only, True)
            self.assertEqual(devices[1].root, "F:\\")
            self.assertEqual(devices[1].firmware, "5.16.3")
            self.assertIsNone(devices[1].model)
            self.assertIsNone(devices[1].serial)
            self.assertIsNone(devices[1].read_only)
            self.assertEqual(devices[2].transport, "mtp")
            self.assertIsNone(devices[2].root)
            self.assertEqual(devices[2].transport_id, "72a379a9a8a344d21e4704a8")
            public_output = json.dumps(
                [device.public_dict() for device in devices], ensure_ascii=False
            )
            self.assertNotIn("B0D4A1C200000001", public_output)


class LinuxMtpAdapterTest(unittest.TestCase):
    def make_fake_gio(self, directory):
        fake_gio = directory / "gio"
        fake_gio.write_text(textwrap.dedent("""\
            #!/bin/sh
            printf '%s\\n' "$*" >> "$GIO_LOG"
            if [ "$1" = "mount" ]; then
                printf '%s\\n' \\
                  'Mount(0): Kindle Scribe -> mtp://Amazon_Kindle_Scribe_G090KB0TESTX05TK/' \\
                  '  Type: GProxyMount (GProxyVolumeMonitorMTP)' \\
                  '  default_location=mtp://Amazon_Kindle_Scribe_G090KB0TESTX05TK/'
                exit 0
            fi
            if [ "$1" = "cat" ]; then
                printf '%s\\n' 'Kindle 5.16.2.1.1 (fixture)'
                exit 0
            fi
            if [ "$1" = "info" ] && [ "$2" = "-a" ]; then
                printf '%s\\n' 'attributes:' '  filesystem::free: 424242'
                exit 0
            fi
            if [ "${GIO_MODE:-}" = "missing" ] && [ "$1" = "info" ]; then
                exit 1
            fi
            if [ "${GIO_MODE:-}" = "missing" ] && [ "$1" = "list" ]; then
                printf '%s\\n' 'other-book'
                exit 0
            fi
            if [ "${GIO_MODE:-}" = "disconnected" ] && \
               { [ "$1" = "info" ] || [ "$1" = "list" ]; }; then
                exit 5
            fi
            if [ "${GIO_MODE:-}" = "inaccessible" ] && [ "$1" = "info" ]; then
                exit 1
            fi
            if [ "${GIO_MODE:-}" = "inaccessible" ] && [ "$1" = "list" ]; then
                printf '%s\\n' 'book'
                exit 0
            fi
            if [ "$1" = "list" ] && [ "$2" = "-h" ]; then
                case "$6" in
                  */documents) printf 'book.txt\\t4\\t(regular)\\n' ;;
                  */system) printf 'version.txt\\t28\\t(regular)\\n' ;;
                  *) printf 'documents\\t0\\t(directory)\\nsystem\\t0\\t(directory)\\n' ;;
                esac
                exit 0
            fi
            if [ "$1" = "info" ] || [ "$1" = "copy" ] || [ "$1" = "list" ] || \\
               [ "$1" = "mkdir" ] || [ "$1" = "remove" ]; then
                exit 0
            fi
            exit 2
        """), encoding="utf-8")
        fake_gio.chmod(fake_gio.stat().st_mode | stat.S_IXUSR)
        return fake_gio

    def make_unavailable_gio(self, directory):
        fake_gio = directory / "gio"
        fake_gio.write_text(textwrap.dedent("""\
            #!/bin/sh
            printf '%s\\n' 'fixture-gio-called' >> "$GIO_LOG"
            exit 127
        """), encoding="utf-8")
        fake_gio.chmod(fake_gio.stat().st_mode | stat.S_IXUSR)
        (directory / "python3").symlink_to(Path(sys.executable))
        return fake_gio

    def run_adapter(self, env, *args):
        completed = subprocess.run(
            ["/bin/bash", str(LINUX_ADAPTER), *args],
            check=False,
            capture_output=True,
            text=True,
            env=env,
        )
        lines = completed.stdout.splitlines()
        self.assertEqual(len(lines), 1, completed.stdout)
        return completed, json.loads(lines[0])

    def test_linux_adapter_supports_all_actions_with_one_json_result(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            self.make_fake_gio(base)
            log = base / "gio.log"
            env = dict(os.environ)
            env["PATH"] = f"{base}:/usr/bin:/bin"
            env["GIO_LOG"] = str(log)

            listed, list_payload = self.run_adapter(env, "list")
            self.assertEqual(listed.returncode, 0)
            self.assertTrue(list_payload["ok"])
            self.assertEqual(list_payload["action"], "list")
            self.assertEqual(list_payload["devices"][0]["name"], "Kindle Scribe")
            self.assertEqual(list_payload["devices"][0]["device_code"], "0KB")
            self.assertEqual(list_payload["devices"][0]["firmware"], "5.16.2.1.1")
            self.assertEqual(list_payload["devices"][0]["free_bytes"], 424242)
            self.assertNotIn("G090KB0TESTX05TK", listed.stdout)
            device_id = list_payload["devices"][0]["id"]

            files, files_payload = self.run_adapter(env, "list-files", device_id)
            self.assertEqual(files.returncode, 0, files.stdout + files.stderr)
            self.assertEqual(files_payload["entries"], [
                {"path": "documents", "kind": "directory", "size": None},
                {"path": "documents/book.txt", "kind": "file", "size": 4},
                {"path": "system", "kind": "directory", "size": None},
                {"path": "system/version.txt", "kind": "file", "size": 28},
            ])

            source = base / "payload.bin"
            source.write_bytes(b"payload")
            dangerous_path = "documents/book;touch SHOULD_NOT_EXIST"
            copied_to, copy_to_payload = self.run_adapter(
                env, "copy-to", device_id, str(source), dangerous_path
            )
            self.assertEqual(copied_to.returncode, 0)
            self.assertTrue(copy_to_payload["ok"])
            self.assertFalse((base / "SHOULD_NOT_EXIST").exists())

            destination = base / "backup.bin"
            copied_from, copy_from_payload = self.run_adapter(
                env, "copy-from", device_id, "documents/book", str(destination)
            )
            self.assertEqual(copied_from.returncode, 0)
            self.assertTrue(copy_from_payload["ok"])

            exists_result, exists_payload = self.run_adapter(
                env, "exists", device_id, "documents/book"
            )
            self.assertEqual(exists_result.returncode, 0)
            self.assertIs(exists_payload["exists"], True)

            free_result, free_payload = self.run_adapter(
                env, "free-bytes", device_id
            )
            self.assertEqual(free_result.returncode, 0)
            self.assertEqual(free_payload["free_bytes"], 424242)
            made, made_payload = self.run_adapter(env, "mkdir", device_id, ".adds")
            self.assertEqual(made.returncode, 0, made.stdout + made.stderr)
            self.assertTrue(made_payload["ok"])
            removed, removed_payload = self.run_adapter(
                env, "delete", device_id, "documents/book"
            )
            self.assertEqual(removed.returncode, 0, removed.stdout + removed.stderr)
            self.assertTrue(removed_payload["ok"])
            self.assertIn("%3Btouch%20SHOULD_NOT_EXIST", log.read_text(encoding="utf-8"))

    def test_linux_adapter_reports_unavailable_without_non_json_noise(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            self.make_unavailable_gio(base)
            log = base / "gio.log"
            env = dict(os.environ)
            env["PATH"] = str(base)
            env["GIO_LOG"] = str(log)
            completed, payload = self.run_adapter(env, "list")

            self.assertNotEqual(completed.returncode, 0)
            self.assertFalse(payload["ok"])
            self.assertEqual(payload["action"], "list")
            self.assertEqual(payload["error_code"], "mtp_unavailable")
            self.assertEqual(log.read_text(encoding="utf-8"), "fixture-gio-called\n")

    def test_linux_adapter_rejects_mtp_uri_without_stable_serial_identity(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            fake = self.make_fake_gio(base)
            contents = fake.read_text(encoding="utf-8").replace(
                "Amazon_Kindle_Scribe_G090KB0TESTX05TK",
                "Amazon_Kindle_Scribe_usb_001_004",
            )
            fake.write_text(contents, encoding="utf-8")
            env = dict(os.environ)
            env["PATH"] = f"{base}:/usr/bin:/bin"
            env["GIO_LOG"] = str(base / "gio.log")

            completed, payload = self.run_adapter(env, "list")

            self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
            self.assertEqual(payload["devices"], [])

    def test_linux_exists_only_reports_false_after_listing_parent(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            self.make_fake_gio(base)
            env = dict(os.environ)
            env["PATH"] = f"{base}:/usr/bin:/bin"
            env["GIO_LOG"] = str(base / "gio.log")
            _, list_payload = self.run_adapter(env, "list")
            device_id = list_payload["devices"][0]["id"]

            missing_env = dict(env, GIO_MODE="missing")
            missing, missing_payload = self.run_adapter(
                missing_env, "exists", device_id, "documents/book"
            )
            self.assertEqual(missing.returncode, 0)
            self.assertTrue(missing_payload["ok"])
            self.assertIs(missing_payload["exists"], False)

            for mode in ("disconnected", "inaccessible"):
                failure_env = dict(env, GIO_MODE=mode)
                failed, failure_payload = self.run_adapter(
                    failure_env, "exists", device_id, "documents/book"
                )
                self.assertNotEqual(failed.returncode, 0)
                self.assertFalse(failure_payload["ok"])
                self.assertEqual(failure_payload["error_code"], "mtp_operation_failed")
                self.assertNotIn("SERIALSECRET", failed.stdout)


@unittest.skipUnless(shutil.which("pwsh"), "当前环境无 pwsh")
class WindowsMtpFixtureTest(unittest.TestCase):
    def run_fixture(self, *args):
        env = dict(os.environ)
        env.pop("KINDLE_MTP_FIXTURE", None)
        completed = subprocess.run(
            [
                "pwsh",
                "-NoProfile",
                "-File",
                str(POWERSHELL_ADAPTER),
                "-FixturePath",
                str(FIXTURES / "windows-mtp.json"),
                "-Action",
                *args,
            ],
            check=False,
            capture_output=True,
            text=True,
            env=env,
        )
        lines = completed.stdout.splitlines()
        self.assertEqual(lines, lines[:1], completed.stdout)
        self.assertEqual(len(lines), 1, completed.stderr)
        return completed, json.loads(lines[0])

    def test_fixture_filters_portable_documents_and_preserves_duplicate_names(self):
        completed, payload = self.run_fixture("list")

        self.assertEqual(completed.returncode, 0)
        self.assertTrue(payload["ok"])
        self.assertEqual(len(payload["devices"]), 2)
        self.assertEqual(
            [device["name"] for device in payload["devices"]],
            ["Kindle Scribe", "Kindle Scribe"],
        )
        self.assertEqual(len({device["id"] for device in payload["devices"]}), 2)
        for device in payload["devices"]:
            self.assertRegex(device["id"], r"^[0-9a-f]{24}$")
            self.assertEqual(device["storage"], "Internal Storage")
            self.assertEqual(device["device_code"], "D4")
            self.assertIsInstance(device["firmware"], str)
            self.assertIsInstance(device["free_bytes"], int)
            self.assertIs(device["read_only"], False)
        self.assertNotIn("B0D4A1C200000001", completed.stdout)

        diagnostics = payload["fixture_diagnostics"]
        self.assertNotIn("system-disk", diagnostics["expanded_tags"])
        self.assertIn("bad-portable", diagnostics["expanded_tags"])
        self.assertIn("kindle-one", diagnostics["expanded_tags"])
        self.assertIn("kindle-two", diagnostics["expanded_tags"])
        self.assertEqual(diagnostics["candidate_errors"], 1)

    def test_fixture_rejects_unsafe_path_and_waits_for_copy_completion(self):
        _, listed = self.run_fixture("list")
        device_id = listed["devices"][0]["id"]

        invalid, invalid_payload = self.run_fixture(
            "exists", device_id, "../documents/existing.bin"
        )
        self.assertNotEqual(invalid.returncode, 0)
        self.assertEqual(invalid_payload["error_code"], "invalid_path")

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "payload.bin"
            source.write_bytes(b"payload")
            copied, copied_payload = self.run_fixture(
                "copy-to", device_id, str(source), "documents/payload.bin"
            )
            self.assertEqual(copied.returncode, 0)
            self.assertTrue(copied_payload["ok"])
            self.assertEqual(copied_payload["status"], "complete")
            self.assertEqual(copied_payload["verified_after_polls"], 2)
            self.assertGreaterEqual(copied_payload["timeout_ms"], 15_000)

            destination = root / "existing.bin"
            copied_from, copied_from_payload = self.run_fixture(
                "copy-from", device_id, "documents/existing.bin", str(destination)
            )
            self.assertEqual(copied_from.returncode, 0)
            self.assertEqual(copied_from_payload["verified_after_polls"], 2)
            self.assertTrue(copied_from_payload["test_mode"])
            self.assertFalse(destination.exists())

    def test_fixture_classifies_growing_stalled_and_completed_large_copies(self):
        _, listed = self.run_fixture("list")
        device_id = listed["devices"][0]["id"]

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            outcomes = {}
            for name in ("slow-large.bin", "stalled.bin", "large-complete.bin"):
                source = root / name
                with source.open("wb") as stream:
                    stream.truncate(64 * 1024 * 1024)
                outcomes[name] = self.run_fixture(
                    "copy-to", device_id, str(source), f"documents/{name}"
                )

        growing, growing_payload = outcomes["slow-large.bin"]
        self.assertNotEqual(growing.returncode, 0)
        self.assertEqual(growing_payload["error_code"], "copy_in_progress")
        self.assertTrue(growing_payload["continue_waiting"])
        self.assertFalse(growing_payload["retryable"])
        self.assertGreater(growing_payload["timeout_ms"], 1_000_000)

        stalled, stalled_payload = outcomes["stalled.bin"]
        self.assertNotEqual(stalled.returncode, 0)
        self.assertEqual(stalled_payload["error_code"], "mtp_operation_failed")

        completed, completed_payload = outcomes["large-complete.bin"]
        self.assertEqual(completed.returncode, 0)
        self.assertEqual(completed_payload["status"], "complete")
        self.assertEqual(completed_payload["verified_after_polls"], 2)
        self.assertGreater(completed_payload["timeout_ms"], 1_000_000)

    def test_fixture_exists_and_free_bytes_return_one_json_object(self):
        _, listed = self.run_fixture("list")
        device_id = listed["devices"][0]["id"]

        existing, existing_payload = self.run_fixture(
            "exists", device_id, "documents/existing.bin"
        )
        self.assertEqual(existing.returncode, 0)
        self.assertIs(existing_payload["exists"], True)

        missing, missing_payload = self.run_fixture(
            "exists", device_id, "documents/missing.bin"
        )
        self.assertEqual(missing.returncode, 0)
        self.assertIs(missing_payload["exists"], False)

        free, free_payload = self.run_fixture("free-bytes", device_id)
        self.assertEqual(free.returncode, 0)
        self.assertEqual(free_payload["free_bytes"], 424242)

        listed_files, files_payload = self.run_fixture("list-files", device_id)
        self.assertEqual(listed_files.returncode, 0)
        self.assertIn(
            {"path": "system/version.txt", "kind": "file", "size": 28},
            files_payload["entries"],
        )
        made, made_payload = self.run_fixture("mkdir", device_id, ".adds")
        self.assertEqual(made.returncode, 0)
        self.assertTrue(made_payload["ok"])
        removed, removed_payload = self.run_fixture(
            "delete", device_id, "documents/existing.bin"
        )
        self.assertEqual(removed.returncode, 0)
        self.assertTrue(removed_payload["ok"])

    def test_inherited_fixture_environment_cannot_switch_backend(self):
        env = dict(os.environ)
        env["KINDLE_MTP_FIXTURE"] = str(FIXTURES / "does-not-exist.json")
        completed = subprocess.run(
            [
                "pwsh", "-NoProfile", "-File", str(POWERSHELL_ADAPTER),
                "-Action", "invalid",
            ],
            check=False,
            capture_output=True,
            text=True,
            env=env,
        )
        self.assertNotEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(len(completed.stdout.splitlines()), 1)
        self.assertEqual(json.loads(completed.stdout)["error_code"], "invalid_action")


class ProductionFixtureIsolationTest(unittest.TestCase):
    def test_production_python_module_does_not_expose_windows_fixture_backend(self):
        env = dict(os.environ)
        env["PYTHONPATH"] = str(PROJECT_ROOT / "scripts")
        completed = subprocess.run(
            [
                sys.executable,
                "-m",
                "kindle_jailbreak_lib.device",
                "--windows-mtp-fixture",
                str(FIXTURES / "windows-mtp.json"),
                "list",
            ],
            check=False,
            capture_output=True,
            text=True,
            env=env,
        )

        self.assertEqual(completed.returncode, 0)
        self.assertEqual(completed.stdout, "")


if __name__ == "__main__":
    unittest.main()

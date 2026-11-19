import argparse
import gzip
import hashlib
import io
import json
import lzma
import os
import re
import stat
import subprocess
import tarfile
import tempfile
import zipfile
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath


ROOT = Path(__file__).resolve().parents[1]
PROJECT_URL = "https://github.com/charbelochoa/PAVAROTTI"
DESCRIPTION = "Estacion de trabajo OSINT para Blue Team"
VERSION = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+")
LICENSES = ("Apache-2.0.txt", "DEPENDENCIAS.txt", "NOTICE")
FILE_MODE = 0o644
PROGRAM_MODE = 0o755


def checked_output(*args):
    return subprocess.check_output(args, cwd=ROOT)


def source_file(name):
    return checked_output("git", "show", f"HEAD:{name}")


def read_build(path, target, revision):
    info = json.loads(checked_output("go", "version", "-m", "-json", path))
    settings = {item["Key"]: item["Value"] for item in info["Settings"]}
    expected = {
        "GOOS": target, "GOARCH": "amd64", "CGO_ENABLED": "0", "-trimpath": "true",
        "vcs.revision": revision, "vcs.modified": "false",
    }
    if info["Path"] != "pavarotti" or any(settings.get(key) != value for key, value in expected.items()):
        raise ValueError(f"{path.name} debe ser un binario de PAVAROTTI para {target}/amd64, del commit {revision}, compilado con CGO_ENABLED=0 y -trimpath")
    return info


def product_version(binaries, expected):
    native = binaries["windows" if os.name == "nt" else "linux"]
    output = checked_output(native, "-version").decode("utf-8").strip()
    prefix, _, version = output.partition(" ")
    if prefix != "PAVAROTTI" or not VERSION.fullmatch(version):
        raise ValueError(f"Version del ejecutable invalida: {output}")
    if expected and version != expected:
        raise ValueError(f"La etiqueta espera la version {expected} y el ejecutable contiene {version}")
    return version


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def md5(data):
    return hashlib.md5(data, usedforsecurity=False).hexdigest()


def file_info(data):
    return {"sha256": sha256(data), "bytes": len(data)}


def directories(files):
    return {str(parent) for name in files for parent in PurePosixPath(name).parents if str(parent) != "."}


def write_tar(files, epoch):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for name in sorted(set(files) | directories(files)):
            member = tarfile.TarInfo(name)
            member.mtime = epoch
            member.uname = member.gname = "root"
            if name in files:
                data, member.mode = files[name]
                member.size = len(data)
                archive.addfile(member, io.BytesIO(data))
            else:
                member.type = tarfile.DIRTYPE
                member.mode = PROGRAM_MODE
                archive.addfile(member)
    return buffer.getvalue()


def gzip_bytes(data, epoch):
    buffer = io.BytesIO()
    with gzip.GzipFile(filename="", mode="wb", fileobj=buffer, mtime=epoch) as compressed:
        compressed.write(data)
    return buffer.getvalue()


def write_zip(files, epoch):
    buffer = io.BytesIO()
    date = datetime.fromtimestamp(epoch, timezone.utc)
    timestamp = (date.year, date.month, date.day, date.hour, date.minute, date.second)
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as archive:
        for name, (data, mode) in sorted(files.items()):
            member = zipfile.ZipInfo(name, date_time=timestamp)
            member.create_system = 3
            member.external_attr = (stat.S_IFREG | mode) << 16
            archive.writestr(member, data, compress_type=zipfile.ZIP_DEFLATED, compresslevel=6)
    return buffer.getvalue()


def ar_file(members, epoch):
    buffer = io.BytesIO()
    buffer.write(b"!<arch>\n")
    for name, data in members:
        header = f"{name + '/':<16}{epoch:<12}{0:<6}{0:<6}{'100644':<8}{len(data):<10}`\n"
        encoded = header.encode("ascii")
        if len(encoded) != 60:
            raise ValueError(f"Cabecera ar invalida para {name}")
        buffer.write(encoded)
        buffer.write(data)
        if len(data) % 2:
            buffer.write(b"\n")
    return buffer.getvalue()


def debian_package(files, version, epoch):
    kib = (sum(len(data) for data, _ in files.values()) + 1023) // 1024
    control = (f"Package: pavarotti\nVersion: {version}-1\nSection: utils\nPriority: optional\n"
               f"Architecture: amd64\nInstalled-Size: {kib}\nMaintainer: PAVAROTTI\n"
               f"Suggests: xdg-utils\nHomepage: {PROJECT_URL}\nDescription: {DESCRIPTION}\n")
    checks = "".join(f"{md5(data)}  {name}\n" for name, (data, _) in sorted(files.items()))
    control_files = {"control": (control.encode(), FILE_MODE), "md5sums": (checks.encode(), FILE_MODE)}
    return ar_file([
        ("debian-binary", b"2.0\n"),
        ("control.tar.gz", gzip_bytes(write_tar(control_files, epoch), epoch)),
        ("data.tar.gz", gzip_bytes(write_tar(files, epoch), epoch)),
    ], epoch)


def arch_package(files, version, epoch):
    size = sum(len(data) for data, _ in files.values())
    info = (f"pkgname = pavarotti\npkgbase = pavarotti\npkgver = {version}-1\npkgdesc = {DESCRIPTION}\n"
            f"url = {PROJECT_URL}\nbuilddate = {epoch}\npackager = PAVAROTTI\nsize = {size}\narch = x86_64\n"
            "license = custom\noptdepend = xdg-utils: abrir el navegador\n")
    files = {**files, ".PKGINFO": (info.encode(), FILE_MODE)}
    mtree = ["#mtree"]
    for name in sorted(directories(files)):
        mtree.append(f"./{name} type=dir uid=0 gid=0 mode=755 time={epoch}.0")
    for name, (data, mode) in sorted(files.items()):
        mtree.append(f"./{name} type=file uid=0 gid=0 mode={mode:o} time={epoch}.0 size={len(data)} "
                     f"md5digest={md5(data)} sha256digest={sha256(data)}")
    files[".MTREE"] = (gzip_bytes(("\n".join(mtree) + "\n").encode(), epoch), FILE_MODE)
    return lzma.compress(write_tar(files, epoch), preset=3)


def distributions(linux, windows, version, epoch):
    notices = {name: (source_file("licenses/" + name), FILE_MODE) for name in LICENSES}
    portable = {f"licenses/{name}": part for name, part in notices.items()}
    installed = {
        "usr/bin/pavarotti": (linux, PROGRAM_MODE),
        "usr/share/applications/pavarotti.desktop": (source_file("packaging/pavarotti.desktop"), FILE_MODE),
        "usr/share/pixmaps/pavarotti.png": (source_file("ui/icono.png"), FILE_MODE),
    }
    debian = {**installed, **{f"usr/share/doc/pavarotti/{name}": part for name, part in notices.items()}}
    arch = {**installed, **{f"usr/share/licenses/pavarotti/{name}": part for name, part in notices.items()}}
    yield f"pavarotti_{version}-1_amd64.deb", "deb", debian_package(debian, version, epoch)
    yield f"pavarotti-{version}-1-x86_64.pkg.tar.xz", "pacman", arch_package(arch, version, epoch)
    linux_files = {**portable, "pavarotti": (linux, PROGRAM_MODE)}
    yield f"PAVAROTTI-{version}-linux-x64.tar.gz", "tar.gz", gzip_bytes(write_tar(linux_files, epoch), epoch)
    windows_files = {**portable, "PAVAROTTI.exe": (windows, PROGRAM_MODE)}
    yield f"PAVAROTTI-{version}-windows-x64.zip", "zip", write_zip(windows_files, epoch)


def build_packages(binaries, output, expected_version):
    revision = checked_output("git", "rev-parse", "HEAD").decode("ascii").strip()
    epoch = int(checked_output("git", "show", "-s", "--format=%ct", "HEAD"))
    builds = {target: read_build(path, target, revision) for target, path in binaries.items()}
    toolchain = builds["linux"]["GoVersion"]
    if builds["windows"]["GoVersion"] != toolchain:
        raise ValueError("Los dos binarios deben usar la misma version de Go")
    version = product_version(binaries, expected_version)
    payloads = {target: path.read_bytes() for target, path in binaries.items()}
    names = {"linux": "pavarotti", "windows": "PAVAROTTI.exe"}
    manifest = {
        "schema": "pavarotti.distribution.v1", "version": version, "revision": revision,
        "source_date_epoch": epoch, "go_version": toolchain, "packages": [],
        "targets": {
            f"{target}-amd64": {"name": names[target], **file_info(payload),
                                "modules": builds[target].get("Deps", [])}
            for target, payload in payloads.items()
        },
    }
    output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=output) as stage:
        staged = Path(stage)
        sums = {}
        for name, format_name, data in distributions(payloads["linux"], payloads["windows"], version, epoch):
            (staged / name).write_bytes(data)
            info = file_info(data)
            manifest["packages"].append({"name": name, "format": format_name, **info})
            sums[name] = info["sha256"]
        description = (json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")
        (staged / "build-info.json").write_bytes(description)
        sums["build-info.json"] = sha256(description)
        (staged / "SHA256SUMS").write_text("".join(f"{checksum}  {name}\n" for name, checksum in sorted(sums.items())),
                                        encoding="ascii", newline="\n")
        for name in [*sums, "SHA256SUMS"]:
            (staged / name).replace(output / name)
    print(f"PAVAROTTI {version} · {output}")


def main():
    parser = argparse.ArgumentParser(description="Empaqueta PAVAROTTI para Kali, Arch, Linux portátil y Windows.")
    parser.add_argument("--linux", type=Path, required=True)
    parser.add_argument("--windows", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--version")
    options = parser.parse_args()
    binaries = {"linux": options.linux.resolve(), "windows": options.windows.resolve()}
    try:
        build_packages(binaries, options.out.resolve(), options.version)
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        parser.exit(1, f"Empaquetado: {error}\n")


if __name__ == "__main__":
    main()

import argparse
import hashlib
import json
import re
from pathlib import Path


CHECKSUM = re.compile(r"([0-9a-f]{64})  ([A-Za-z0-9][A-Za-z0-9._-]*)")
VERSION = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+")


def verify(root):
    checks = {}
    for line in (root / "SHA256SUMS").read_text(encoding="ascii").splitlines():
        match = CHECKSUM.fullmatch(line)
        if not match or match[2] in checks:
            raise ValueError("SHA256SUMS contiene un nombre o una huella invalida")
        checks[match[2]] = match[1]
    if "build-info.json" not in checks or len(checks) != 5:
        raise ValueError("SHA256SUMS debe incluir el manifiesto y los cuatro paquetes")
    for name, expected in checks.items():
        with (root / name).open("rb") as file:
            actual = hashlib.file_digest(file, "sha256").hexdigest()
        if actual != expected:
            raise ValueError(f"La huella de {name} difiere de SHA256SUMS")
    manifest = json.loads((root / "build-info.json").read_bytes())
    version = manifest["version"]
    if manifest["schema"] != "pavarotti.distribution.v1" or not VERSION.fullmatch(version):
        raise ValueError("El manifiesto de paquetes es incompatible")
    packages = {
        "deb": f"pavarotti_{version}-1_amd64.deb",
        "pacman": f"pavarotti-{version}-1-x86_64.pkg.tar.xz",
        "tar.gz": f"PAVAROTTI-{version}-linux-x64.tar.gz",
        "zip": f"PAVAROTTI-{version}-windows-x64.zip",
    }
    if len(manifest["packages"]) != len(packages) or set(checks) != set(packages.values()) | {"build-info.json"}:
        raise ValueError("El manifiesto debe describir los cuatro paquetes de la misma version")
    for package in manifest["packages"]:
        name = packages.pop(package["format"])
        if package["name"] != name or package["sha256"] != checks[name] or package["bytes"] != (root / name).stat().st_size:
            raise ValueError(f"Los datos del manifiesto de {name} son incorrectos")
    return manifest


def main():
    parser = argparse.ArgumentParser(description="Comprueba las sumas SHA-256 y el manifiesto de PAVAROTTI.")
    parser.add_argument("carpeta", type=Path)
    options = parser.parse_args()
    try:
        manifest = verify(options.carpeta)
    except (OSError, ValueError, KeyError, TypeError) as error:
        parser.exit(1, f"Verificacion: {error}\n")
    print(f"PAVAROTTI {manifest['version']} · sumas verificadas")


if __name__ == "__main__":
    main()

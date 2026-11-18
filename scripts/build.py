"""Build portable PAVAROTTI bundles from pinned upstream distributions."""
import argparse
import hashlib
import io
import os
from pathlib import Path, PurePosixPath
import shutil
import struct
import subprocess
import tarfile
import tempfile
from urllib.request import Request, urlopen
import xml.etree.ElementTree as ET
import zipfile

ROOT = Path(__file__).resolve().parents[1]
BUILD = ROOT / ".build"
DIST = ROOT / "dist"
HOST = "windows" if os.name == "nt" else "linux"
GHIDRA = "ghidra_12.2_PUBLIC"
JDK = "jdk-25.0.5+8"
TEMURIN = "https://github.com/adoptium/temurin25-binaries/releases/download/jdk-25.0.5%2B8/OpenJDK25U-jdk_x64_"
INPUTS = {
    "ghidra.zip": (
        "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_12.2_build/ghidra_12.2_PUBLIC_20261016.zip",
        "2c2cd776db3c1f6a097ba418922378ac3649cadd5e844a6f5f088ae628a7be67"),
    "jdk-windows.zip": (TEMURIN + "windows_hotspot_25.0.5_8.zip",
                        "636bdc13dc649ddc7d5921c5c7d23cca6e44fd19d662b45cc9c02135a6c96c42"),
    "jdk-linux.tar.gz": (TEMURIN + "linux_hotspot_25.0.5_8.tar.gz",
                         "68982529869257d0ee6b824ec5aa270ff8b118bb438670da0b97ebdab178d7fb"),
}


def sha(path):
    with path.open("rb") as inp:
        return hashlib.file_digest(inp, "sha256").hexdigest()


def fetch(name):
    url, expected = INPUTS[name]
    cache = BUILD / "downloads" / name
    cache.parent.mkdir(parents=True, exist_ok=True)
    if cache.exists() and sha(cache) == expected:
        return cache
    print("Descargando", name, flush=True)
    with tempfile.NamedTemporaryFile(dir=cache.parent, delete=False) as out:
        temp = Path(out.name)
    try:
        with urlopen(Request(url, headers={"User-Agent": "Pavarotti-build"}), timeout=120) as inp, temp.open("wb") as out:
            shutil.copyfileobj(inp, out, 1024 * 1024)
        if sha(temp) != expected:
            raise ValueError(f"SHA-256 incorrecto para {name}")
        temp.replace(cache)
    finally:
        temp.unlink(missing_ok=True)
    return cache


def host_jdk(archive):
    java = BUILD / JDK / "bin" / ("java.exe" if HOST == "windows" else "java")
    if not java.exists():
        if HOST == "windows":
            with zipfile.ZipFile(archive) as src:
                src.extractall(BUILD)
        else:
            with tarfile.open(archive) as src:
                src.extractall(BUILD, filter="data")
    return java.parent


def compile_plugin(work, ghidra, java):
    libs = work / "libs"
    classes, tests = work / "classes", work / "tests"
    classes.mkdir()
    tests.mkdir()
    with zipfile.ZipFile(ghidra) as src:
        for name in src.namelist():
            parts = PurePosixPath(name).parts
            if name.endswith(".jar") and len(parts) == 6 and parts[1] == "Ghidra" and parts[4] == "lib":
                src.extract(name, libs)
    classpath = os.pathsep.join(p.as_posix() for p in sorted(libs.rglob("*.jar")))
    sources = sorted((ROOT / "extension/src").rglob("*.java"))
    opts = ["-proc:none", "-encoding", "UTF-8", "-cp", classpath, "-d", classes.as_posix()]
    argfile = work / "javac.args"
    argfile.write_text("\n".join(f'"{arg}"' for arg in opts + [p.as_posix() for p in sources]), encoding="utf-8")
    subprocess.run([java / "javac", "@" + str(argfile)], check=True)
    gson = next(libs.rglob("gson-*.jar"))
    test_cp = os.pathsep.join(map(str, (classes, gson, tests)))
    subprocess.run([java / "javac", "-encoding", "UTF-8", "-cp", test_cp, "-d", tests,
                    ROOT / "tests/pavarotti/SourceStoreTest.java"], check=True)
    subprocess.run([java / "java", "-cp", test_cp, "pavarotti.SourceStoreTest", tests,
                    ROOT / "ejemplos/hallazgos.json"], check=True)
    shutil.copyfile(ROOT / "assets/sello.png", classes / "pavarotti/sello.png")
    jar = work / "Pavarotti.jar"
    subprocess.run([java / "jar", "--create", "--file", jar, "-C", classes, "."], check=True)
    return jar.read_bytes()


def branded_resources(src, plugin):
    prefix = GHIDRA + "/"
    modified = {}
    props = "Ghidra/application.properties"
    modified[props] = src.read(prefix + props).replace(b"application.name=Ghidra", b"application.name=PAVAROTTI")
    module = "Ghidra/Features/Pavarotti/"
    modified[module + "Module.manifest"] = b"\n"
    modified[module + "lib/Pavarotti.jar"] = plugin

    def patch_jar(path, changes):
        output = io.BytesIO()
        with zipfile.ZipFile(io.BytesIO(src.read(prefix + path))) as original, zipfile.ZipFile(output, "w") as result:
            missing = changes.keys() - set(original.namelist())
            if missing:
                raise ValueError(f"Recursos de Ghidra ausentes: {missing}")
            for entry in original.infolist():
                data = original.read(entry) if entry.filename not in changes else changes[entry.filename]
                result.writestr(entry, data)
        modified[path] = output.getvalue()

    config = "Ghidra/Configurations/Public_Release/lib/Public_Release.jar"
    with zipfile.ZipFile(io.BytesIO(src.read(prefix + config))) as release:
        tool = ET.fromstring(release.read("defaultTools/CodeBrowser.tool"))
    ET.SubElement(tool.find("TOOL"), "PACKAGE", NAME="PAVAROTTI")
    console = tool.find(".//COMPONENT_INFO[@NAME='Console']")
    slot = next(node for node in tool.iter("COMPONENT_NODE") if console in list(node))
    console.set("ACTIVE", "false")
    slot.insert(0, ET.Element("COMPONENT_INFO", NAME="PAVAROTTI", OWNER="PavarottiPlugin",
                              TITLE="PAVAROTTI", ACTIVE="true", GROUP="Default",
                              INSTANCE_ID="6820356914200100101"))
    patch_jar(config, {"defaultTools/CodeBrowser.tool": ET.tostring(tool, encoding="utf-8", xml_declaration=True)})
    patch_jar("Ghidra/Features/Base/lib/Base.jar", {"images/GHIDRA_Splash.png": (ROOT / "assets/portada.png").read_bytes()})
    ico = (ROOT / "assets/pavarotti.ico").read_bytes()
    icons = {}
    for i in range(struct.unpack_from("<H", ico, 4)[0]):
        width, _, _, _, _, _, size, offset = struct.unpack_from("<BBBBHHII", ico, 6 + i * 16)
        png = ico[offset:offset + size]
        if not png.startswith(b"\x89PNG"):
            raise ValueError("El icono debe contener imágenes PNG.")
        icons[f"images/GhidraIcon{width or 256}.png"] = png
    patch_jar("Ghidra/Framework/Gui/lib/Gui.jar", icons)
    return modified


def build_launcher(work, target):
    folder = work / ("launcher-" + target)
    folder.mkdir()
    for file in (ROOT / "launcher").iterdir():
        if file.suffix in (".go", ".mod"):
            shutil.copy(file, folder)
    flags = "-s -w"
    if target == "windows":
        subprocess.run(["go", "run", "github.com/akavel/rsrc@v0.10.2", "-arch", "amd64",
                        "-ico", ROOT / "assets/pavarotti.ico", "-o", folder / "icon_windows_amd64.syso"],
                       cwd=folder, check=True)
        flags += " -H=windowsgui"
    exe = folder / ("PAVAROTTI.exe" if target == "windows" else "PAVAROTTI")
    env = dict(os.environ, GOOS=target, GOARCH="amd64", CGO_ENABLED="0")
    subprocess.run(["go", "build", "-trimpath", "-buildvcs=false", "-ldflags", flags, "-o", exe, "."],
                   cwd=folder, env=env, check=True)
    return exe


class Bundle:
    def __init__(self, output, windows):
        self.windows = windows
        self.archive = (zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED, compresslevel=1)
                        if windows else tarfile.open(output, "w:gz", compresslevel=1))

    def add(self, name, source, size, mode=0o644):
        path = "PAVAROTTI/" + name
        if self.windows:
            entry = zipfile.ZipInfo(path)
            entry.compress_type = zipfile.ZIP_DEFLATED
            entry.external_attr = (0o100000 | mode) << 16
            with self.archive.open(entry, "w") as out:
                shutil.copyfileobj(source, out, 1024 * 1024)
        else:
            entry = tarfile.TarInfo(path)
            entry.mode, entry.size = mode, size
            self.archive.addfile(entry, source)

    def file(self, name, path, mode=0o644):
        with path.open("rb") as inp:
            self.add(name, inp, path.stat().st_size, mode)

    def directory(self, name):
        path = "PAVAROTTI/" + name.rstrip("/") + "/"
        if self.windows:
            self.archive.mkdir(path)
        else:
            entry = tarfile.TarInfo(path)
            entry.type, entry.mode = tarfile.DIRTYPE, 0o755
            self.archive.addfile(entry)

    def runtime(self, archive):
        if self.windows:
            with zipfile.ZipFile(archive) as src:
                for item in src.infolist():
                    if not item.is_dir():
                        with src.open(item) as inp:
                            self.add("runtime/" + item.filename.split("/", 1)[1], inp, item.file_size)
        else:
            with tarfile.open(archive, "r|gz") as src:
                for item in src:
                    if "/" not in item.name:
                        continue
                    original = item.name
                    item.name = "PAVAROTTI/runtime/" + original.split("/", 1)[1]
                    if item.islnk():
                        item.linkname = "PAVAROTTI/runtime/" + item.linkname.split("/", 1)[1]
                    self.archive.addfile(item, src.extractfile(item) if item.isfile() else None)


def build(targets):
    BUILD.mkdir(exist_ok=True)
    DIST.mkdir(exist_ok=True)
    ghidra = fetch("ghidra.zip")
    jdks = {t: fetch("jdk-windows.zip" if t == "windows" else "jdk-linux.tar.gz") for t in set(targets) | {HOST}}
    with tempfile.TemporaryDirectory(dir=BUILD) as tmp, zipfile.ZipFile(ghidra) as src:
        work = Path(tmp)
        plugin = compile_plugin(work, ghidra, host_jdk(jdks[HOST]))
        patches = branded_resources(src, plugin)
        for target in targets:
            windows = target == "windows"
            exe = build_launcher(work, target)
            filename = "PAVAROTTI-" + target + "-x64." + ("zip" if windows else "tar.gz")
            print("Empaquetando", filename, flush=True)
            temp = work / filename
            bundle = Bundle(temp, windows)
            try:
                bundle.file(exe.name, exe, 0o755)
                for item in src.infolist():
                    rel = item.filename.removeprefix(GHIDRA + "/")
                    if item.is_dir():
                        bundle.directory("ghidra/" + rel)
                        continue
                    if rel in patches:
                        continue
                    with src.open(item) as inp:
                        bundle.add("ghidra/" + rel, inp, item.file_size, (item.external_attr >> 16) & 0o777)
                for rel, data in patches.items():
                    bundle.add("ghidra/" + rel, io.BytesIO(data), len(data))
                bundle.runtime(jdks[target])
                for file in [ROOT / "README.md", *sorted((ROOT / "licenses").glob("*")),
                             ROOT / "ejemplos/hallazgos.json"]:
                    bundle.file(file.relative_to(ROOT).as_posix(), file)
            finally:
                bundle.archive.close()
            temp.replace(DIST / filename)
            (DIST / (filename + ".sha256")).write_text(sha(DIST / filename) + "  " + filename + "\n", encoding="ascii")
            print("Listo", DIST / filename, flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", choices=["all", "windows", "linux"], default="all")
    target = parser.parse_args().target
    build(["windows", "linux"] if target == "all" else [target])

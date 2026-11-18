"""Exercise the installed CodeBrowser in an isolated Ghidra project and user profile."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile

package = Path(sys.argv[1]).resolve()
java = package / "runtime/bin"
ghidra = package / "ghidra"
with tempfile.TemporaryDirectory(prefix="pavarotti-test-") as tmp:
    work = Path(tmp)
    module = work / "DesktopTest"
    lib = module / "lib"
    lib.mkdir(parents=True)
    (module / "Module.manifest").touch()
    classes = work / "classes"
    classes.mkdir()
    classpath = os.pathsep.join(p.as_posix() for p in (ghidra / "Ghidra").glob("*/*/lib/*.jar"))
    source = Path(__file__).parent.resolve() / "pavarotti/DesktopTest.java"
    opts = ["-proc:none", "-encoding", "UTF-8", "-classpath", classpath, "-d", classes.as_posix(), source.as_posix()]
    argfile = work / "javac.args"
    argfile.write_text("\n".join(f'"{arg}"' for arg in opts), encoding="utf-8")
    subprocess.run([java / "javac", "@" + str(argfile)], check=True)
    subprocess.run([java / "jar", "cf", lib / "DesktopTest.jar", "-C", classes, "."], check=True)
    flags = subprocess.check_output([java / "java", "-cp", ghidra / "support/LaunchSupport.jar",
                                     "LaunchSupport", ghidra, "-vmargs"], text=True).splitlines()
    cp = ghidra / "Ghidra/Framework/Utility/lib/Utility.jar"
    command = [java / "java", *flags, "-Dghidra.external.modules=" + str(module),
               "-Duser.home=" + str(work), "-Dapplication.settingsdir=" + str(work / "settings"),
               "-Dapplication.cachedir=" + str(work / "cache"), "-cp", cp, "ghidra.Ghidra",
               "pavarotti.DesktopTest", work, package / "ejemplos/hallazgos.json"]
    if len(sys.argv) > 2:
        command.append(Path(sys.argv[2]).resolve())
    result = subprocess.run(command, cwd=ghidra, timeout=150, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, encoding="utf-8", errors="replace")
    print(result.stdout)
    if result.returncode or "PAVAROTTI DESKTOP OK" not in result.stdout:
        sys.exit(1)

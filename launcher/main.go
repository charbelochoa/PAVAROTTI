package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

func launch() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	exe, err = filepath.EvalSymlinks(exe)
	if err != nil {
		return err
	}
	root := filepath.Dir(exe)
	platform := filepath.Join(root, "ghidra")
	java := filepath.Join(root, "runtime", "bin", "java")
	if runtime.GOOS == "windows" {
		java += ".exe"
	}
	check := len(os.Args) == 2 && os.Args[1] == "--check"
	target := "ghidra.GhidraRun"
	var arguments []string
	switch {
	case check:
		target = "pavarotti.CheckInstallation"
		arguments = []string{filepath.Join(root, "ejemplos", "hallazgos.json")}
	case len(os.Args) == 2 && strings.EqualFold(filepath.Ext(os.Args[1]), ".gpr"):
		path, err := filepath.Abs(os.Args[1])
		if err != nil {
			return err
		}
		arguments = []string{path}
	case len(os.Args) != 1:
		return fmt.Errorf("Uso: PAVAROTTI [proyecto.gpr | --check]")
	}
	// LaunchSupport resolves Ghidra's version-specific JVM and platform flags.
	setup := exec.Command(java, "-cp", filepath.Join(platform, "support", "LaunchSupport.jar"),
		"LaunchSupport", platform, "-vmargs")
	prepare(setup)
	flags, err := setup.Output()
	if err != nil {
		return fmt.Errorf("no se pudo iniciar el Java incluido en %s: %w", root, err)
	}
	var opts []string
	for _, line := range strings.Split(string(flags), "\n") {
		if flag := strings.TrimSpace(line); flag != "" {
			opts = append(opts, flag)
		}
	}
	if check {
		opts = append(opts, "-Djava.awt.headless=true")
	}
	opts = append(opts, "-cp", filepath.Join(platform, "Ghidra", "Framework", "Utility", "lib", "Utility.jar"),
		"ghidra.Ghidra", target)
	app := exec.Command(java, append(opts, arguments...)...)
	app.Dir = platform
	app.Env = append(os.Environ(), "JAVA_HOME="+filepath.Join(root, "runtime"))
	app.Stdout, app.Stderr = os.Stdout, os.Stderr
	prepare(app)
	return app.Run()
}

func main() {
	if err := launch(); err != nil {
		fmt.Fprintln(os.Stderr, "PAVAROTTI:", err)
		if len(os.Args) == 1 {
			showError(err.Error())
		}
		os.Exit(1)
	}
}

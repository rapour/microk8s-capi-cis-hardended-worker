#!/usr/bin/env python3

import os
import pathlib
import platform
import shutil
import subprocess

import click
import requests



DIR = pathlib.Path(__file__).parent.absolute()
PLUGINS_DIR = pathlib.Path(os.path.expandvars("$SNAP_COMMON/plugins"))
ARGS_DIR = pathlib.Path(os.path.expandvars("$SNAP_DATA/args"))
CREDS_DIR = pathlib.Path(os.path.expandvars("$SNAP_DATA/credentials"))
CERTS_DIR = pathlib.Path(os.path.expandvars("$SNAP_DATA/certs"))

def NeedsRoot():
    """Require we run the script as root (sudo)."""
    if os.geteuid() != 0:
        click.echo("Elevated permissions are needed for this addon.", err=True)
        click.echo("Please try again, this time using 'sudo'.", err=True)
        exit(1)

def Stop():
    click.echo("Stopping services")
    try:
        subprocess.call("snapctl stop microk8s.daemon-kubelite".split())
    except subprocess.CalledProcessError as e:
        click.echo(f"Failed to stop services: {e}", err=True)
        exit(4)


def Start():
    click.echo("Starting services")
    try:
        subprocess.call("snapctl start microk8s.daemon-kubelite".split())
    except subprocess.CalledProcessError as e:
        click.echo(f"Failed to start services: {e}", err=True)
        exit(4)

def isStrict():
    """Return true if we are on a strict snap"""
    snap_yaml = pathlib.Path(os.path.expandvars("$SNAP/meta/snap.yaml"))
    with open(snap_yaml, "r") as file:
        for line_number, line in enumerate(file, start=1):
            if "confinement" in line and "strict" in line:
                return True
    return False


def FixFilePermissions():
    """Set file permissions to 600 and restrict ownership to root:root."""
    click.echo("Setting file permissions")
    try:
        dirs = [ARGS_DIR, CREDS_DIR, CERTS_DIR]
        if not isStrict():
            service = "/etc/systemd/system/snap.microk8s.daemon-kubelite.service"
            dirs.extend([service])
        for p in dirs:
            subprocess.call(f"chmod -R g-wr {p}".split())
            subprocess.call(f"chmod -R o-wr {p}".split())
            subprocess.call(f"chmod g-x {p}".split())
            subprocess.call(f"chmod o-x {p}".split())
            subprocess.call(f"chown -R root:root {p}".split())
    except subprocess.CalledProcessError as e:
        click.echo(f"Failed to set file permissions: {e}", err=True)
        exit(3)


def addArgument(arg: str, value: str, service: str):
    """
    Add argument to a service.

        Parameters:
            arg (str): arguments
            value (str): value for the argument
            service (str): name of the service to add the argument to

    """
    exists = False
    with open(ARGS_DIR / service, "r") as file:
        for line_number, line in enumerate(file, start=1):
            if arg in line:
                exists = True
                break
    if not exists:
        with open(ARGS_DIR / service, "a+") as file_object:
            file_object.write(f"{arg}={value}\n")


def SetServiceArguments():
    """Set arguments to all services for CIS hardening."""
    click.echo("Setting kubelet arguments")
    args = [
        ("--protect-kernel-defaults", "true"),
        ("--event-qps", "0"),
        (
            "--tls-cipher-suites",
            "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_RSA_WITH_AES_256_GCM_SHA384,TLS_RSA_WITH_AES_128_GCM_SHA256",
        ),
        ("--authorization-mode", "Webhook"),
        ("--tls-cert-file", "${SNAP_DATA}/certs/kubelet.crt"),
        ("--tls-private-key-file", "${SNAP_DATA}/certs/kubelet.key"),
    ]

    for arg in args:
        addArgument(arg[0], arg[1], "kubelet")



def DownloadKubebench(kubebench_version: str):
    """Download kube-bench and place the wrapper script under plugins."""
    click.echo("Downloading kube-bench")
    try:
        tmpdir = pathlib.Path(os.path.expandvars("$SNAP_DATA")) / "var" / "tmp"
        tarbin = pathlib.Path(os.path.expandvars("$SNAP")) / "bin" / "tar"
        shutil.rmtree(tmpdir, ignore_errors=True)
        if not os.path.exists(tmpdir):
            os.makedirs(tmpdir)
        arch = get_arch()
        url = f"https://github.com/aquasecurity/kube-bench/releases/download/v{kubebench_version}/kube-bench_{kubebench_version}_linux_{arch}.tar.gz"
        response = requests.get(url)
        tarball = tmpdir / "kube-bench.tar.gz"
        kubebench = DIR / "tmp"
        open(tarball, "wb").write(response.content)
        if not os.path.exists(kubebench):
            os.mkdir(kubebench)
        subprocess.check_call(
            f"{tarbin} -zxf {tarball}  --no-same-owner -C {kubebench}".split()
        )
        src = kubebench / "kube-bench"
        dst = PLUGINS_DIR / "kube-bench"
        shutil.copyfile(src, dst)
        subprocess.check_call(f"chmod +x {dst}".split())
    except subprocess.CalledProcessError as e:
        click.echo(f"Failed to download kube-bench: {e}", err=True)
        exit(2)


def get_arch():
    """Returns the architecture we are running on."""
    arch_translate = {"aarch64": "arm64", "x86_64": "amd64"}
    return arch_translate[platform.machine()]


def PrintExitMessage(kubebench_installed: bool):
    """Print info at the end of enabling the addon."""
    click.echo()
    click.echo(
        "CIS hardening configuration has been applied. All microk8s commands require sudo from now on."
        "Note: You may need to set up these additional configs in /etc/sysctl.conf:"
            "vm.panic_on_oom=0"
            "vm.overcommit_memory=1"
            "kernel.panic=10"
            "kernel.panic_on_oops=1"
            "kernel.keys.root_maxkeys=1000000"
            "kernel.keys.root_maxbytes=25000000"
    )
    if kubebench_installed:
        click.echo("Inspect the CIS benchmark results with:")
        click.echo()
        click.echo("  sudo microk8s kube-bench")
    click.echo()


@click.command()
@click.option("--kubebench-version", default="0.6.13")
@click.option("--install-kubebench", default="True", hidden=True)
@click.option("--skip-kubebench-installation", is_flag=True, help="Do not install Kubebench.")
def main(kubebench_version: str, install_kubebench:str, skip_kubebench_installation: bool):
    """
        Parameters:
            kubebench_version (str): the version of kubebench we want to install
    """
    NeedsRoot()

    should_install_kubebench = install_kubebench.lower() not in ["", "false"] and not skip_kubebench_installation
    if should_install_kubebench:
        DownloadKubebench(kubebench_version)

    Stop()
    FixFilePermissions()
    SetServiceArguments()
    Start()
    PrintExitMessage(should_install_kubebench)


if __name__ == "__main__":
    main()
<p align="center">
  <img src="./assets/logo.png" alt="pura-logo" width="200"/>
</p>

# PURA - Lightweight & OCI-compliant container runtime

**Pura** is an experimental Linux container runtime written in pure and dependency-minimal Rust. The intent was to explore the OCI runtime spec and see how the integration with Docker would work. It's a hobby project and should be considered as a starting point for learning how container runtimes work and interact with the Linux kernel features.

⚠️  **DON'T USE THIS IN PRODUCTION**

**Pura** works and it's only feature tested, but no official security audit has been done, so please use this code exclusively to learn and expand the codebase. If you want a production-grade container runtime that's written in Rust, use the excellent [Youki](https://github.com/containers/youki) runtime.

## Intro

The goal of **Pura** was to learn how container runtimes work and how container engines integrate an OCI-compliant implementation. The only requirement was to be as dependency free as possible with a small memory footprint. Binaries built for release mode are all **<5MB**.

**Pura** was tested on the following distros (standalone binary and Docker integration):

- Debian 11
- Fedora 29
- CentOS 7
- Ubuntu 18.04 & 20.04
- OpenSUSE 15

**Pura** is the codebase for [Container Runtime in Rust](https://itnext.io/container-runtime-in-rust-part-0-7af709415cda), a 3 part series on container runtimes in general, Linux features that CRs use and some implementation details explained.

## Build

Prerequisites:
- Rust 1.54 or later
- libc:
   - Debian: `apt-get install build-essential`
   - Fedora: `dnf install gcc`
   - CentOS: `yum install gcc`

Build as a usual Rust project:
```
git clone git@github.com:penumbra23/pura.git
cd pura
cargo build --release
```

## Usage

**Pura** can be used as a standalone container runtime like **runc** with the OCI compliant commands:

```sh
cd target/release
./pura create example --bundle /path/to/bundle
./pura start example
./pura state example
./pura delete example
```

If you encounter some error to run pura from build check the NOTES.md

or it can be integrated with Docker:
```bash
# stop the dockerd service (NOTE: this will stop all running containers on your Linux OS)
# init-based
sudo service docker stop
# systemd-based
sudo systemctl stop docker

# try to use this
[Rootless mode](https://docs.docker.com/engine/security/rootless/)

# run dockerd manually
[sudo] dockerd -H unix:///var/run/docker.sock --add-runtime pura=/pura-repo/target/release/pura

docker run -it --runtime pura alpine /bin/sh
/ # cat /etc/os-release
NAME="Alpine Linux"
ID=alpine
VERSION_ID=3.13.5
PRETTY_NAME="Alpine Linux v3.13"
HOME_URL="https://alpinelinux.org/"
BUG_REPORT_URL="https://bugs.alpinelinux.org/"
/ #
```

To avoid halting the Docker daemon everytime you test, you can add it inside the dockerd config file, `/etc/docker/daemon.json`:
```json
{
  ...
  ...
  "default-runtime": "runc",
  "runtimes": {
    "pura": {
      "path": "/pura-repo/target/release/pura"
    }
  }
  ...
  ...
}
```

After adding the runtime section inside `daemon.json` just start the Docker service and specify the `--runtime pura` option when starting a container. This way, when changing the source code just recompile it without restarting the Docker service.

## Contribute

As this is a experimental project intended for learing purposes, anyone can submit PRs or file issues. Features left to implement are:

- cgroups
- seccomp
- apparmor


## License
MIT

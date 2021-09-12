<p align="center">
  <img src="./assets/logo.png" alt="pura-logo" width="200"/>
</p>

# PURA - Lightweight & OCI-compliant container runtime

**Pura** is an experimental Linux container runtime written in pure and dependency-minimal Rust. The intent was to explore the OCI runtime spec and see how the integration with Docker would work. It's a hobby project and should be considered as a starting point for learning how container runtimes work and interact with the Linux kernel features.

⚠️  **DON'T USE THIS IN PRODUCTION**

**Pura** works and it's only feature tested, but no official security audit has been done, so please use this code exclusively to learn and expand the codebase. If you want a production-grade container runtime that's written in Rust, use the excellent [Youki](https://github.com/containers/youki) runtime.

## Build

Prerequisites:
- Rust 1.52 or later
- libc - `apt-get install build-essential`

Build as a usual Rust project:
```
git clone git@github.com:penumbra23/pura.git
cd pura
cargo build --release
```

## Usage

**Pura** can be used as a standalone container runtime like **runc** with the OCI compliant commands:
TODO: explain export bundle
```
cd target/release
./pura create id123456789 --bundle /path/to/bundle
./pura start id123456789
./pura state id123456789
./pura delete id123456789
```

or it can be integrated with Docker:
```bash
# stop the dockerd service (NOTE: this will stop all running containers on your Linux OS)
# init-based
sudo service stop
# systemd-based
sudo systemctl stop docker

# run dockerd manually
sudo dockerd -H unix:///var/run/docker.sock --runtime pura=/pura-repo/target/release/pura

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

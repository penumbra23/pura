use nix::{
    errno::Errno,
    mount::{mount, umount2, MntFlags, MsFlags},
    sys::stat::{makedev, mknod, Mode, SFlag},
    unistd::{chdir, chown, pivot_root, Gid, Uid},
};

use std::{
    convert::TryInto,
    os::unix::fs::symlink,
    path::{Path, PathBuf},
    str::FromStr,
};

use crate::core::common::{exit_msg, Error, ErrorType, Result};

use crate::oci::spec::{Device, Mount};

pub fn symlinks_defaults(rootfs: &Path) {
    let default_symlinks = [
        ("/proc/self/fd", "dev/fd"),
        ("/proc/self/fd/0", "dev/stdin"),
        ("/proc/self/fd/1", "dev/stdout"),
        ("/proc/self/fd/2", "dev/stderr"),
    ];

    for (src, dest) in default_symlinks {
        symlink(src, rootfs.join(dest)).unwrap();
    }
}

fn default_devices() -> Vec<Device> {
    vec![
        Device {
            path: String::from("/dev/null"),
            device_type: String::from("c"),
            major: 1,
            minor: 3,
            file_mode: Some(0o066),
            uid: Some(0),
            gid: Some(0),
        },
        Device {
            path: String::from("/dev/zero"),
            device_type: String::from("c"),
            major: 1,
            minor: 5,
            file_mode: Some(0o066),
            uid: Some(0),
            gid: Some(0),
        },
        Device {
            path: String::from("/dev/full"),
            device_type: String::from("c"),
            major: 1,
            minor: 7,
            file_mode: Some(0o066),
            uid: Some(0),
            gid: Some(0),
        },
        Device {
            path: String::from("/dev/random"),
            device_type: String::from("c"),
            major: 1,
            minor: 8,
            file_mode: Some(0o066),
            uid: Some(0),
            gid: Some(0),
        },
        Device {
            path: String::from("/dev/urandom"),
            device_type: String::from("c"),
            major: 1,
            minor: 9,
            file_mode: Some(0o066),
            uid: Some(0),
            gid: Some(0),
        },
        Device {
            path: String::from("/dev/tty"),
            device_type: String::from("c"),
            major: 5,
            minor: 0,
            file_mode: Some(0o066),
            uid: Some(0),
            gid: Some(0),
        },
        Device {
            path: String::from("/dev/ptmx"),
            device_type: String::from("c"),
            major: 5,
            minor: 2,
            file_mode: Some(0o066),
            uid: Some(0),
            gid: Some(0),
        },
    ]
}

fn to_sflag(flag: &str) -> SFlag {
    match flag {
        "c" | "u" => SFlag::S_IFCHR,
        "b" => SFlag::S_IFBLK,
        "p" => SFlag::S_IFIFO,
        _ => exit_msg(1, "unknown device flag"),
    }
}

fn bind_dev(dev: &Device) {
    let path = PathBuf::from_str(&dev.path).unwrap();

    mount(
        Some(&path),
        &path,
        None::<&str>,
        MsFlags::MS_BIND,
        None::<&str>,
    )
    .unwrap();
}

fn create_dev(dev: &Device, rootfs: &Path) -> Result<()> {
    let path = rootfs.join(&dev.path.trim_start_matches("/"));

    mknod(
        path.as_path(),
        to_sflag(dev.device_type.as_str()),
        Mode::from_bits_truncate(dev.file_mode.unwrap_or(0o066).try_into().unwrap()),
        makedev(dev.major, dev.minor),
    )
    .map_err(|err| Error {
        msg: format!("failed to create dev at {}: {}", dev.path, err.to_string()),
        err_type: ErrorType::Container,
    })?;

    if let Some(uid) = dev.uid {
        chown(path.as_path(), Some(Uid::from_raw(uid)), None).unwrap();
    }

    if let Some(gid) = dev.gid {
        chown(path.as_path(), None, Some(Gid::from_raw(gid))).unwrap();
    }

    Ok(())
}

pub fn create_default_devices(rootfs: &Path) {
    let devices = default_devices();
    let bind = false;

    for dev in devices.iter() {
        if bind {
            bind_dev(dev);
        } else {
            create_dev(dev, rootfs).unwrap();
        }
    }
}

pub fn create_devices(devices: &Vec<Device>, rootfs: &Path) -> Result<()> {
    for d in devices {
        create_dev(d, rootfs).map_err(|err| Error {
            msg: format!("failed to create device: {}", err.to_string()),
            err_type: ErrorType::Container,
        })?;
    }
    Ok(())
}

pub fn mount_rootfs(rootfs: &Path) -> Result<()> {
    // https://man7.org/linux/man-pages/man2/pivot_root.2.html
    mount(
        None::<&str>,
        "/",
        None::<&str>,
        MsFlags::MS_PRIVATE | MsFlags::MS_REC,
        None::<&str>,
    )
    .map_err(|_| Error {
        msg: "mount failed".to_string(),
        err_type: ErrorType::Container,
    })?;

    mount::<Path, Path, str, str>(
        Some(&rootfs),
        &rootfs,
        None::<&str>,
        MsFlags::MS_BIND | MsFlags::MS_REC,
        None::<&str>,
    )
    .map_err(|err| {
        Error {
            msg: format!("mount rootfs failed {} for {:?}", err, rootfs),
            err_type: ErrorType::Container,
        }
    })?;

    Ok(())
}

pub fn pivot_rootfs(rootfs: &Path) -> Result<()> {
    chdir(rootfs).map_err(|_| Error {
        msg: "unable to chdir into container".to_string(),
        err_type: ErrorType::Container,
    })?;

    std::fs::create_dir_all(rootfs.join("oldroot")).map_err(|_| Error {
        msg: "unable to create tmp root".to_string(),
        err_type: ErrorType::Container,
    })?;

    pivot_root(rootfs.as_os_str(), rootfs.join("oldroot").as_os_str()).map_err(|err| Error {
        msg: format!("pivot_root failed {}", err.to_string()).to_string(),
        err_type: ErrorType::Container,
    })?;

    umount2("./oldroot", MntFlags::MNT_DETACH).map_err(|_| Error {
        msg: "unmount old_dir failed".to_string(),
        err_type: ErrorType::Container,
    })?;

    std::fs::remove_dir_all("./oldroot").map_err(|_| Error {
        msg: "rm old_dir failed".to_string(),
        err_type: ErrorType::Container,
    })?;

    chdir("/").map_err(|_| Error {
        msg: "chdir on root(/) failed".to_string(),
        err_type: ErrorType::Container,
    })?;
    Ok(())
}

pub fn mount_devices(mounts: &Vec<Mount>, rootfs: &Path) -> Result<()> {
    for m in mounts {
        let mut flags = MsFlags::empty();

        let dest = rootfs.join(m.destination.trim_start_matches("/"));

        if !std::path::Path::new(&dest).exists() {
            std::fs::create_dir_all(&dest)
                .map_err(|err| Error { msg: format!("{}", err), err_type: ErrorType::Container })?;
        }

        if m.mount_type.as_ref().unwrap() == "bind" {
            flags |= MsFlags::MS_BIND;
        }

        match mount::<str, PathBuf, str, str>(
            Some(m.source.as_ref().unwrap().as_str()),
            &dest,
            Some(m.mount_type.as_ref().unwrap().as_str()),
            flags,
            None::<&str>,
        ) {
            Ok(_) => (),
            Err(err) => {
                // Skip if the device is busy
                // This happens with the cgroup mount
                if err.as_errno() != Some(Errno::EBUSY) {
                    return Err(Error {
                        msg: format!("mount device failed {}", err),
                        err_type: ErrorType::Runtime,
                    });
                }
            }
        };
    }
    Ok(())
}

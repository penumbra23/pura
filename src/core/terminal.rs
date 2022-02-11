use std::{
    os::unix::prelude::{AsRawFd, RawFd},
    path::Path,
};

use nix::{
    fcntl::{open, OFlag},
    pty::{grantpt, posix_openpt, ptsname_r, unlockpt},
    sys::{
        socket::{
            self, connect, sendmsg, AddressFamily, ControlMessage, MsgFlags, SockAddr, SockFlag,
            SockType, UnixAddr,
        },
        stat::Mode,
        uio::IoVec,
    },
    unistd::{close, dup2, setsid},
};

use crate::core::common::{Error, ErrorType, Result};

pub struct Pty {
    master: nix::pty::PtyMaster,
    slave_name: String,
}

impl Pty {
    pub fn new() -> Result<Pty> {
        let master = posix_openpt(OFlag::O_RDWR).map_err(|_| Error {
            msg: "failed to open new terminal".to_string(),
            err_type: ErrorType::Container,
        })?;

        grantpt(&master).map_err(|_| Error {
            msg: "failed to grantpt".to_string(),
            err_type: ErrorType::Container,
        })?;

        unlockpt(&master).map_err(|_| Error {
            msg: "failed to unlock".to_string(),
            err_type: ErrorType::Container,
        })?;

        // Get the name of the slave
        let slave_name = ptsname_r(&master).map_err(|_| Error {
            msg: "failed to get slave pty".to_string(),
            err_type: ErrorType::Container,
        })?;

        Ok(Pty {
            master: master,
            slave_name,
        })
    }

    pub fn connect(&self) -> Result<()> {
        setsid().map_err(|_| Error {
            msg: "failed to set session".to_string(),
            err_type: ErrorType::Container,
        })?;

        let slave_fd =
            open(Path::new(&self.slave_name), OFlag::O_RDWR, Mode::empty()).map_err(|_| Error {
                msg: "failed to open slave pty".to_string(),
                err_type: ErrorType::Container,
            })?;

        dup2(slave_fd.as_raw_fd(), 0).map_err(|_| Error {
            msg: "error dup2 stdin".to_string(),
            err_type: ErrorType::Container,
        })?;
        dup2(slave_fd.as_raw_fd(), 1).map_err(|_| Error {
            msg: "error dup2 stdout".to_string(),
            err_type: ErrorType::Container,
        })?;
        dup2(slave_fd.as_raw_fd(), 2).map_err(|_| Error {
            msg: "error dup2 stderr".to_string(),
            err_type: ErrorType::Container,
        })?;

        Ok(())
    }
}

pub struct PtySocket {
    pub socket_fd: RawFd,
}

impl PtySocket {
    pub fn new(console_socket_path: &String) -> Result<PtySocket> {
        let socket_fd = socket::socket(
            AddressFamily::Unix,
            SockType::Stream,
            SockFlag::empty(),
            None,
        )
        .map_err(|_| Error {
            msg: "".to_string(),
            err_type: ErrorType::Runtime,
        })?;

        connect(
            socket_fd,
            &SockAddr::Unix(UnixAddr::new(console_socket_path.as_str()).unwrap()),
        )
        .map_err(|err| Error {
            msg: format!("error connecting pty {}", err),
            err_type: ErrorType::Runtime,
        })?;

        Ok(PtySocket {
            socket_fd: socket_fd.as_raw_fd(),
        })
    }

    pub fn close(&self) -> Result<()> {
        close(self.socket_fd).map_err(|_| Error {
            msg: "error closing console-socket".to_string(),
            err_type: ErrorType::Runtime,
        })?;

        Ok(())
    }

    pub fn send_pty(&self, pty: &Pty) -> Result<()> {
        let master_fds = [pty.master.as_raw_fd()];
        let master_fd_msg = pty.master.as_raw_fd().to_ne_bytes();

        let iov = [IoVec::from_slice(&master_fd_msg)];
        let cmsg = [ControlMessage::ScmRights(&master_fds)];

        sendmsg(self.socket_fd, &iov, &cmsg, MsgFlags::empty(), None).map_err(|_| Error {
            msg: "failed sending pty fd to socket".to_string(),
            err_type: ErrorType::Container,
        })?;

        Ok(())
    }
}

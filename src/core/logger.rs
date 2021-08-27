
use chrono::Local;
use lazy_static::lazy_static;
use std::{
    fs::OpenOptions,
    io::Write,
    sync::Mutex,
};
use log::{Level, Log, Metadata, Record};
use serde::Serialize;

use crate::core::common::Result;

lazy_static! {
    static ref LOGGER: ContainerLogger = ContainerLogger {
        logger: Mutex::new(None)
    };
}

pub struct ContainerLogger {
    logger: Mutex<Option<Logger>>,
}

impl ContainerLogger {
    pub fn init(path: &String, max_level: Level) -> Result<()> {
        // Make sure the file exists
        let _ = OpenOptions::new()
            .write(true)
            .create(true)
            .open(path)
            .unwrap();

        *LOGGER.logger.lock().unwrap() = Some(Logger {
            max_level: max_level,
            path: path.clone(),
        });

        log::set_logger(&*LOGGER).unwrap();
        log::set_max_level(max_level.to_level_filter());

        Ok(())
    }
}

impl Log for ContainerLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= self.logger.lock().unwrap().as_ref().unwrap().max_level
    }

    fn log(&self, record: &Record) {
        if let Some(ref mut inner) = *self.logger.lock().unwrap() {
            inner.log(record);
        }
    }

    fn flush(&self) {}
}

struct Logger {
    path: String,
    max_level: Level,
}

#[derive(Serialize)]
struct LogEntry {
    level: String,
    msg: String,
    time: String,
}

impl Log for Logger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= self.max_level
    }

    fn log(&self, record: &Record) {
        println!("{}", record.args());
        if self.enabled(record.metadata()) {
            let log_entry = LogEntry {
                level: record.level().to_string(),
                msg: record.args().to_string(),
                time: Local::now().to_rfc3339(),
            };

            let mut file = std::fs::OpenOptions::new()
                .append(true)
                .create(true)
                .open(&self.path)
                .unwrap();

            let log_json = serde_json::to_string(&log_entry).unwrap();
            let _ = file.write(format!("{}\n", log_json).as_bytes());
        }
    }

    fn flush(&self) {}
}

#[cfg(test)]
mod tests {
    use std::io::Read;

    use log::{debug, error, info, trace, warn, Level};

    use super::ContainerLogger;

    fn read_file(path: &str) -> String {
        let mut log_file = std::fs::OpenOptions::new()
            .read(true)
            .create(false)
            .open("log.txt")
            .unwrap();
        let mut logs = String::new();
        log_file.read_to_string(&mut logs).unwrap();
        logs
    }

    #[test]
    fn log() {
        let _ = ContainerLogger::init(&"log.txt".to_string(), Level::Info).unwrap();
        warn!("warn");
        error!("error");
        info!("info");
        debug!("debug");
        trace!("trace");

        let logs = read_file("log.txt");

        assert!(logs.contains("warn"));
        assert!(logs.contains("error"));
        assert!(logs.contains("info"));
        assert!(!logs.contains("debug"));
        assert!(!logs.contains("trace"));

        std::fs::remove_file("log.txt").unwrap();
    }
}

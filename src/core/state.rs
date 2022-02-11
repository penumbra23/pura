use serde::{Deserialize, Serialize};
use std::{collections::HashMap, convert::TryFrom, io::Write, path::{Path, PathBuf}};

use crate::core::common::{Result, Error, ErrorType};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Status {
    Creating,
    Created,
    Running,
    Stopped,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct State {
    pub oci_version: String,
    pub id: String,
    pub status: Status,
    pub pid: u64,
    pub bundle: PathBuf,
    pub annotations: Option<HashMap<String, String>>,
}

const OCI_VERSION: &str = "1.0.2";

impl State {
    pub fn new(id: &String, pid: u64, bundle: &String) -> State {
        State {
            oci_version: String::from(OCI_VERSION),
            id: id.clone(),
            pid: pid,
            status: Status::Creating,
            bundle: Path::new(bundle).canonicalize().unwrap(),
            annotations: Some(HashMap::<String, String>::new()),
        }
    }

    pub fn save(&self, root_path: &Path) -> Result<()> {
        std::fs::create_dir_all(root_path).unwrap();

        let mut state_file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .open(root_path.join("state.json"))
            .map_err(|err| Error {
                msg: format!("save state failed {} for {:?}", err, root_path),
                err_type: ErrorType::Container,
            })?;
        state_file
            .write_all(serde_json::to_string(self).unwrap().as_bytes())
            .map_err(|_| Error {
                msg: "cannot write to state.json file".to_string(),
                err_type: ErrorType::Container,
            })?;
        Ok(())
    }
}

impl TryFrom<&Path> for State {
    type Error = Error;

    fn try_from(path: &Path) -> core::result::Result<Self, Self::Error> {
        let state_json = std::fs::read_to_string(path.join("state.json")).map_err(|err| {
            Error {
                msg: format!("state file not found {} for {:?}", err, path),
                err_type: ErrorType::Runtime,
            }
        })?;
        let state: State = serde_json::from_str(&state_json).map_err(|_| Error {
            msg: "unable to deserialize state file".to_string(),
            err_type: ErrorType::Runtime,
        })?;
        Ok(state)
    }
}

#[cfg(test)]
mod tests {
    use std::{io::Read, path::Path};

    use crate::core::state::State;

    #[test]
    fn serialize() {
        let state = State::new(&String::from("123456"), 23, &String::from("/containers"));

        assert_eq!(serde_json::to_string(&state).unwrap(), "{\"ociVersion\":\"1.0.2\",\"id\":\"123456\",\"status\":\"creating\",\"pid\":23,\"bundle\":\"/containers\",\"annotations\":{}}");
    }

    #[test]
    fn save() {
        let state = State::new(&String::from("123456"), 23, &String::from("/containers"));
        state.save(Path::new(".")).unwrap();

        let mut state_file = std::fs::OpenOptions::new()
            .read(true)
            .open("./state.json")
            .unwrap();
        let mut state_json = String::new();
        state_file.read_to_string(&mut state_json).unwrap();
        let read_state: State = serde_json::from_str(&state_json).unwrap();

        assert_eq!(state.id, read_state.id);
        assert_eq!(state.pid, read_state.pid);
        assert_eq!(state.bundle, read_state.bundle);
        assert_eq!(state.status, read_state.status);
        assert_eq!(state.annotations, read_state.annotations);

        std::fs::remove_file("./state.json").unwrap();
    }
}

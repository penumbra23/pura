pub struct Create {
    pub id: String,
    pub bundle: String,
    pub console_socket: Option<String>,
    pub pid_file: String,
    pub root: String,
}

pub struct Start {
    pub id: String,
    pub root: String,
}

pub struct Delete {
    pub id: String,
    pub root: String,
}

pub struct State {
    pub id: String,
    pub root: String,
}

pub struct Kill {
    pub id: String,
    pub root: String,
    pub signal: i32,
}
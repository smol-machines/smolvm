use containerd_shim_protos::{events::task::*, protobuf::MessageDyn};

pub trait Event: MessageDyn {
    fn topic(&self) -> String;
}

impl Event for TaskCreate {
    fn topic(&self) -> String {
        "/tasks/create".to_string()
    }
}

impl Event for TaskStart {
    fn topic(&self) -> String {
        "/tasks/start".to_string()
    }
}

impl Event for TaskExecAdded {
    fn topic(&self) -> String {
        "/tasks/exec-added".to_string()
    }
}

impl Event for TaskExecStarted {
    fn topic(&self) -> String {
        "/tasks/exec-started".to_string()
    }
}

impl Event for TaskPaused {
    fn topic(&self) -> String {
        "/tasks/paused".to_string()
    }
}

impl Event for TaskResumed {
    fn topic(&self) -> String {
        "/tasks/resumed".to_string()
    }
}

impl Event for TaskExit {
    fn topic(&self) -> String {
        "/tasks/exit".to_string()
    }
}

impl Event for TaskDelete {
    fn topic(&self) -> String {
        "/tasks/delete".to_string()
    }
}

impl Event for TaskOOM {
    fn topic(&self) -> String {
        "/tasks/oom".to_string()
    }
}

impl Event for TaskCheckpointed {
    fn topic(&self) -> String {
        "/tasks/checkpointed".to_string()
    }
}

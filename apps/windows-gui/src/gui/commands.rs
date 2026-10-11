use super::ui_state::OperationKind;
use std::sync::mpsc::Sender;

pub struct CommandCompletion<T> {
    pub operation: OperationKind,
    pub result: Result<T, String>,
}

/// Executes a potentially blocking command away from the Win32 message loop.
/// The caller owns UI updates and receives the completion over a channel that
/// is drained only on the UI thread.
pub fn dispatch<T, F>(sender: Sender<CommandCompletion<T>>, operation: OperationKind, task: F)
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, String> + Send + 'static,
{
    std::thread::spawn(move || {
        let _ = sender.send(CommandCompletion {
            operation,
            result: task(),
        });
    });
}

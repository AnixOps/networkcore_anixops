//! Plugin scripts that run outside HTTP flows (feature `scripts`): `cron`
//! scripts on their schedule in local time, `network-changed` scripts when
//! the client reports a network change, and any of them by hand.
//!
//! Runs are one at a time on the blocking pool, so at most one scheduled
//! script holds a QuickJS heap. The wall clock is read again at least every
//! [`MAX_SLEEP`]: the monotonic clock stops while the device sleeps, and a run
//! missed then happens once on waking.

use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;

use engine_native::{
    NativeQuickJsScriptExecutor, NativeScheduledScriptKind, NativeScheduledScriptRun,
};
use mitm_policy::loon_cron::{CronSchedule, CronTimer, Zoned};
use mitm_policy::loon_plugin::{LoonScheduledScript, LoonScheduledTrigger};
use serde_json::json;
use tokio::sync::mpsc;

use crate::control::{ScheduledScriptView, ScriptControl, ScriptNotificationView};

/// Longest wait between wall-clock checks.
const MAX_SLEEP: Duration = Duration::from_secs(30);
/// Runs asked for by hand or by network changes that wait at once; more are
/// dropped.
const MAX_QUEUED_RUNS: usize = 16;

enum Trigger {
    Script(usize),
    NetworkChanged,
}

pub(crate) struct ScriptScheduler {
    executor: NativeQuickJsScriptExecutor,
    scripts: Vec<LoonScheduledScript>,
    triggers: mpsc::Sender<Trigger>,
    /// Held by the running loop; a restarted tunnel takes it again.
    receiver: tokio::sync::Mutex<mpsc::Receiver<Trigger>>,
    timers: Mutex<Vec<Option<CronTimer>>>,
    last_status: Mutex<Vec<Option<String>>>,
}

impl ScriptScheduler {
    pub(crate) fn new(
        executor: NativeQuickJsScriptExecutor,
        scripts: Vec<LoonScheduledScript>,
    ) -> Self {
        let (triggers, receiver) = mpsc::channel(MAX_QUEUED_RUNS);
        let now = Zoned::now();
        let timers = scripts
            .iter()
            .map(|script| match &script.trigger {
                LoonScheduledTrigger::Cron(expression) => {
                    CronSchedule::parse(expression).map(|schedule| CronTimer::new(schedule, &now))
                }
                _ => None,
            })
            .collect();
        Self {
            executor,
            last_status: Mutex::new(vec![None; scripts.len()]),
            scripts,
            triggers,
            receiver: tokio::sync::Mutex::new(receiver),
            timers: Mutex::new(timers),
        }
    }

    pub(crate) fn control(&self, request: &ScriptControl) -> serde_json::Value {
        match request {
            ScriptControl::Scripts => json!({ "scripts": self.views() }),
            ScriptControl::Notifications => {
                let notifications = self
                    .executor
                    .drain_notifications()
                    .into_iter()
                    .map(|notification| ScriptNotificationView {
                        title: notification.title,
                        subtitle: notification.subtitle,
                        content: notification.content,
                        open_url: notification.open_url,
                    })
                    .collect::<Vec<_>>();
                json!({ "notifications": notifications })
            }
            ScriptControl::NetworkChanged => {
                let count = self
                    .scripts
                    .iter()
                    .filter(|script| script.trigger == LoonScheduledTrigger::NetworkChanged)
                    .count();
                let scheduled =
                    if count > 0 && self.triggers.try_send(Trigger::NetworkChanged).is_ok() {
                        count
                    } else {
                        0
                    };
                json!({ "scheduled": scheduled })
            }
            ScriptControl::Run { tag } => {
                let scheduled = self
                    .scripts
                    .iter()
                    .position(|script| script.tag == *tag)
                    .is_some_and(|index| self.triggers.try_send(Trigger::Script(index)).is_ok());
                json!({ "scheduled": scheduled })
            }
        }
    }

    fn views(&self) -> Vec<ScheduledScriptView> {
        let timers = self
            .timers
            .lock()
            .map(|timers| timers.clone())
            .unwrap_or_default();
        let last = self
            .last_status
            .lock()
            .map(|last| last.clone())
            .unwrap_or_default();
        self.scripts
            .iter()
            .enumerate()
            .map(|(index, script)| {
                let (trigger, cron) = match &script.trigger {
                    LoonScheduledTrigger::Cron(expression) => ("cron", Some(expression.clone())),
                    LoonScheduledTrigger::NetworkChanged => ("network-changed", None),
                    LoonScheduledTrigger::Generic => ("generic", None),
                };
                ScheduledScriptView {
                    tag: script.tag.clone(),
                    trigger,
                    cron,
                    next_run: timers
                        .get(index)
                        .and_then(Option::as_ref)
                        .and_then(CronTimer::next)
                        .map(ToString::to_string),
                    last_status: last.get(index).cloned().flatten(),
                }
            })
            .collect()
    }

    pub(crate) fn has_scripts(&self) -> bool {
        !self.scripts.is_empty()
    }

    /// Runs until the tunnel's runtime stops.
    pub(crate) async fn run(self: Arc<Self>) {
        let mut receiver = self.receiver.lock().await;
        loop {
            let now = Zoned::now();
            let (due, sleep) = match self.timers.lock() {
                Ok(mut timers) => {
                    let due = timers
                        .iter_mut()
                        .enumerate()
                        .filter_map(|(index, timer)| timer.as_mut()?.poll(&now).then_some(index))
                        .collect::<Vec<_>>();
                    let sleep = timers
                        .iter()
                        .flatten()
                        .filter_map(|timer| timer.until_next(&now))
                        .min()
                        .unwrap_or(MAX_SLEEP)
                        .min(MAX_SLEEP);
                    (due, sleep)
                }
                Err(_) => return,
            };
            for index in due {
                self.execute(index).await;
            }
            tokio::select! {
                _ = tokio::time::sleep(sleep) => {}
                trigger = receiver.recv() => match trigger {
                    None => return,
                    Some(Trigger::Script(index)) => self.execute(index).await,
                    Some(Trigger::NetworkChanged) => {
                        let scripts = self
                            .scripts
                            .iter()
                            .enumerate()
                            .filter(|(_, script)| script.trigger == LoonScheduledTrigger::NetworkChanged)
                            .map(|(index, _)| index)
                            .collect::<Vec<_>>();
                        for index in scripts {
                            self.execute(index).await;
                        }
                    }
                },
            }
        }
    }

    async fn execute(&self, index: usize) {
        let Some(script) = self.scripts.get(index) else {
            return;
        };
        let run = NativeScheduledScriptRun {
            script_url: script.script_url.clone(),
            tag: script.tag.clone(),
            argument: script.argument.clone(),
            kind: match &script.trigger {
                LoonScheduledTrigger::Cron(_) => NativeScheduledScriptKind::Cron,
                LoonScheduledTrigger::NetworkChanged => {
                    NativeScheduledScriptKind::Event("network-changed".to_string())
                }
                LoonScheduledTrigger::Generic => NativeScheduledScriptKind::Generic,
            },
            timeout_secs: script.timeout_secs,
        };
        let executor = self.executor.clone();
        let status =
            match tokio::task::spawn_blocking(move || executor.execute_scheduled(&run)).await {
                Ok(report) => report.status,
                Err(_) => "engine".to_string(),
            };
        if let Ok(mut last) = self.last_status.lock() {
            if let Some(slot) = last.get_mut(index) {
                *slot = Some(status);
            }
        }
    }
}

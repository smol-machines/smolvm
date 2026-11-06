/*
   Copyright The containerd Authors.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

use std::{collections::HashMap, sync::LazyLock};

use log::error;
use tokio::sync::{
    mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender},
    Mutex,
};

use crate::{
    error::{Error, Result},
    monitor::{ExitEvent, Subject, Topic},
};

pub static MONITOR: LazyLock<Mutex<Monitor>> = LazyLock::new(|| {
    Mutex::new(Monitor {
        seq_id: 0,
        subscribers: HashMap::new(),
        topic_subs: HashMap::new(),
    })
});

pub async fn monitor_subscribe(topic: Topic) -> Result<Subscription> {
    let mut monitor = MONITOR.lock().await;
    let s = monitor.subscribe(topic)?;
    Ok(s)
}

pub async fn monitor_unsubscribe(sub_id: i64) -> Result<()> {
    let mut monitor = MONITOR.lock().await;
    monitor.unsubscribe(sub_id)
}

pub async fn monitor_notify_by_pid(pid: i32, exit_code: i32) -> Result<()> {
    let monitor = MONITOR.lock().await;
    monitor.notify_by_pid(pid, exit_code).await
}

pub async fn monitor_notify_by_exec(id: &str, exec_id: &str, exit_code: i32) -> Result<()> {
    let monitor = MONITOR.lock().await;
    monitor.notify_by_exec(id, exec_id, exit_code).await
}

pub struct Monitor {
    pub(crate) seq_id: i64,
    pub(crate) subscribers: HashMap<i64, Subscriber>,
    pub(crate) topic_subs: HashMap<Topic, Vec<i64>>,
}

pub(crate) struct Subscriber {
    pub(crate) topic: Topic,
    pub(crate) tx: UnboundedSender<ExitEvent>,
}

pub struct Subscription {
    pub id: i64,
    pub rx: UnboundedReceiver<ExitEvent>,
}

impl Monitor {
    pub fn subscribe(&mut self, topic: Topic) -> Result<Subscription> {
        let (tx, rx) = unbounded_channel::<ExitEvent>();
        let id = self.seq_id;
        self.seq_id += 1;
        let subscriber = Subscriber {
            tx,
            topic: topic.clone(),
        };

        self.subscribers.insert(id, subscriber);
        self.topic_subs.entry(topic).or_default().push(id);
        Ok(Subscription { id, rx })
    }

    pub async fn notify_by_pid(&self, pid: i32, exit_code: i32) -> Result<()> {
        let subject = Subject::Pid(pid);
        self.notify_topic(&Topic::Pid, &subject, exit_code).await;
        self.notify_topic(&Topic::All, &subject, exit_code).await;
        Ok(())
    }

    pub async fn notify_by_exec(&self, cid: &str, exec_id: &str, exit_code: i32) -> Result<()> {
        let subject = Subject::Exec(cid.into(), exec_id.into());
        self.notify_topic(&Topic::Exec, &subject, exit_code).await;
        self.notify_topic(&Topic::All, &subject, exit_code).await;
        Ok(())
    }

    // notify_topic try best to notify exit codes to all subscribers and log errors.
    async fn notify_topic(&self, topic: &Topic, subject: &Subject, exit_code: i32) {
        let mut results = Vec::new();
        if let Some(subs) = self.topic_subs.get(topic) {
            let subscribers = subs.iter().filter_map(|x| self.subscribers.get(x));
            for sub in subscribers {
                let res = sub
                    .tx
                    .send(ExitEvent {
                        subject: subject.clone(),
                        exit_code,
                    })
                    .map_err(other_error!("failed to send exit code"));
                results.push(res);
            }
        }
        let mut result_iter = results.iter();
        while let Some(Err(e)) = result_iter.next() {
            error!("failed to send exit code to subscriber {:?}", e)
        }
    }

    pub fn unsubscribe(&mut self, id: i64) -> Result<()> {
        let sub = self.subscribers.remove(&id);
        if let Some(s) = sub {
            self.topic_subs.get_mut(&s.topic).map(|v| {
                v.iter().position(|&x| x == id).map(|i| {
                    v.remove(i);
                })
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        asynchronous::monitor::{
            monitor_notify_by_exec, monitor_notify_by_pid, monitor_subscribe, monitor_unsubscribe,
        },
        monitor::{ExitEvent, Subject, Topic},
    };

    #[tokio::test]
    async fn test_monitor() {
        let mut s = monitor_subscribe(Topic::Pid).await.unwrap();
        let mut s1 = monitor_subscribe(Topic::All).await.unwrap();
        let mut s2 = monitor_subscribe(Topic::Exec).await.unwrap();
        monitor_notify_by_pid(13, 128).await.unwrap();
        monitor_notify_by_exec("test-container", "test-exec", 139)
            .await
            .unwrap();
        // pid subscription receive only pid event
        if let Some(ExitEvent {
            subject: Subject::Pid(p),
            exit_code: ec,
        }) = s.rx.recv().await
        {
            assert_eq!(ec, 128);
            assert_eq!(p, 13);
        } else {
            panic!("can not receive the notified event");
        }

        // topic all receive all events
        if let Some(ExitEvent {
            subject: Subject::Pid(p),
            exit_code: ec,
        }) = s1.rx.recv().await
        {
            assert_eq!(ec, 128);
            assert_eq!(p, 13);
        } else {
            panic!("can not receive the notified event");
        }
        if let Some(ExitEvent {
            subject: Subject::Exec(cid, eid),
            exit_code: ec,
        }) = s1.rx.recv().await
        {
            assert_eq!(cid, "test-container");
            assert_eq!(eid, "test-exec");
            assert_eq!(ec, 139);
        } else {
            panic!("can not receive the notified event");
        }

        // exec topic only receive exec exit event
        if let Some(ExitEvent {
            subject: Subject::Exec(cid, eid),
            exit_code: ec,
        }) = s2.rx.recv().await
        {
            assert_eq!(cid, "test-container");
            assert_eq!(eid, "test-exec");
            assert_eq!(ec, 139);
        } else {
            panic!("can not receive the notified event");
        }
        monitor_unsubscribe(s.id).await.unwrap();
        monitor_unsubscribe(s1.id).await.unwrap();
        monitor_unsubscribe(s2.id).await.unwrap();
    }
}

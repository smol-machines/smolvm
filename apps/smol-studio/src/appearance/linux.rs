use eframe::egui;
use futures_lite::{StreamExt, future};
use std::{
    collections::HashMap,
    sync::{
        Arc,
        atomic::{AtomicU8, Ordering},
    },
    thread::{self, JoinHandle},
};
use zbus::zvariant::OwnedValue;

const SERVICE: &str = "org.freedesktop.portal.Desktop";
const PATH: &str = "/org/freedesktop/portal/desktop";
const INTERFACE: &str = "org.freedesktop.portal.Settings";
const NAMESPACE: &str = "org.freedesktop.appearance";
const KEY: &str = "color-scheme";

pub struct Appearance {
    theme: Arc<AtomicU8>,
    stop: async_channel::Sender<()>,
    _worker: Option<JoinHandle<()>>,
}
impl Appearance {
    pub fn new(ctx: &egui::Context) -> Self {
        Self::start(ctx.clone(), None)
    }

    fn start(ctx: egui::Context, address: Option<String>) -> Self {
        let theme = Arc::new(AtomicU8::new(0));
        let shared = theme.clone();
        let (stop, cancelled) = async_channel::bounded(1);
        let worker = thread::Builder::new()
            .name("studio-appearance".into())
            .spawn(move || {
                future::block_on(future::race(
                    async {
                        let result = observe(&ctx, &shared, address.as_deref()).await;
                        #[cfg(test)]
                        if let Err(error) = &result {
                            eprintln!("appearance observer: {error}");
                        }
                        let _ = result;
                    },
                    async {
                        let _ = cancelled.recv().await;
                    },
                ));
            })
            .ok();
        Self {
            theme,
            stop,
            _worker: worker,
        }
    }

    pub fn input(&self, raw: &mut egui::RawInput) {
        match self.theme.load(Ordering::Acquire) {
            1 => raw.system_theme = Some(egui::Theme::Dark),
            2 => raw.system_theme = Some(egui::Theme::Light),
            _ => {}
        }
    }
}
impl Drop for Appearance {
    fn drop(&mut self) {
        // Cancels even while connecting or waiting for a portal response; no UI-thread join.
        self.stop.close();
    }
}

fn publish(ctx: &egui::Context, shared: &AtomicU8, value: &OwnedValue) {
    if let Ok(scheme) = u32::try_from(value) {
        // The portal specifies unknown values as no preference; Studio defaults to light.
        let next = if scheme == 1 { 1 } else { 2 };
        if shared.swap(next, Ordering::AcqRel) != next {
            ctx.request_repaint();
        }
    }
}

async fn observe(
    ctx: &egui::Context,
    shared: &AtomicU8,
    address: Option<&str>,
) -> zbus::Result<()> {
    let connection = if let Some(address) = address {
        zbus::connection::Builder::address(address)?.build().await?
    } else {
        zbus::Connection::session().await?
    };
    let proxy = zbus::Proxy::new(&connection, SERVICE, PATH, INTERFACE).await?;
    let mut changes = proxy
        .receive_signal_with_args("SettingChanged", &[(0, NAMESPACE), (1, KEY)])
        .await?;
    // ReadAll works with both portal interface versions and avoids Read's historical
    // double-variant reply; subscribe first so a change during the read is not lost.
    let values: HashMap<String, HashMap<String, OwnedValue>> =
        proxy.call("ReadAll", &(vec![NAMESPACE],)).await?;
    if let Some(value) = values.get(NAMESPACE).and_then(|values| values.get(KEY)) {
        publish(ctx, shared, value);
    }
    while let Some(message) = changes.next().await {
        if let Ok((namespace, key, value)) =
            message.body().deserialize::<(String, String, OwnedValue)>()
            && namespace == NAMESPACE
            && key == KEY
        {
            publish(ctx, shared, &value);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io::{BufRead, BufReader},
        process::{Child, Command, Stdio},
        time::{Duration, Instant},
    };

    struct Bus {
        child: Child,
        address: String,
    }
    impl Bus {
        fn new() -> Self {
            let mut child = Command::new("dbus-daemon")
                .args(["--session", "--nofork", "--print-address=1"])
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()
                .expect("dbus-daemon for private appearance test");
            let mut address = String::new();
            BufReader::new(child.stdout.as_mut().unwrap())
                .read_line(&mut address)
                .unwrap();
            Self {
                child,
                address: address.trim().into(),
            }
        }
    }
    impl Drop for Bus {
        fn drop(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }

    struct Settings {
        entered: Arc<AtomicU8>,
        stall: bool,
    }
    #[zbus::interface(name = "org.freedesktop.portal.Settings")]
    impl Settings {
        async fn read_all(
            &self,
            _namespaces: Vec<String>,
        ) -> HashMap<String, HashMap<String, OwnedValue>> {
            self.entered.store(1, Ordering::Release);
            if self.stall {
                future::pending::<()>().await;
            }
            HashMap::from([(
                NAMESPACE.into(),
                HashMap::from([(KEY.into(), OwnedValue::from(1u32))]),
            )])
        }
    }
    fn server(bus: &Bus, entered: Arc<AtomicU8>, stall: bool) -> zbus::blocking::Connection {
        zbus::blocking::connection::Builder::address(bus.address.as_str())
            .unwrap()
            .name(SERVICE)
            .unwrap()
            .serve_at(PATH, Settings { entered, stall })
            .unwrap()
            .build()
            .unwrap()
    }
    fn wait_until(condition: impl Fn() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(3);
        while !condition() {
            assert!(
                Instant::now() < deadline,
                "appearance worker did not respond"
            );
            thread::sleep(Duration::from_millis(5));
        }
    }
    fn stop(mut appearance: Appearance) {
        let worker = appearance._worker.take().unwrap();
        drop(appearance);
        wait_until(|| worker.is_finished());
        worker.join().unwrap();
    }
    fn seen(appearance: &Appearance) -> Option<egui::Theme> {
        let mut raw = egui::RawInput::default();
        appearance.input(&mut raw);
        raw.system_theme
    }

    #[test]
    fn portal_initial_value_and_changes_reach_input_and_shutdown() {
        let bus = Bus::new();
        let connection = server(&bus, Arc::new(AtomicU8::new(0)), false);
        let appearance = Appearance::start(egui::Context::default(), Some(bus.address.clone()));
        wait_until(|| seen(&appearance) == Some(egui::Theme::Dark));
        for (value, theme) in [
            (2, egui::Theme::Light),
            (1, egui::Theme::Dark),
            (0, egui::Theme::Light),
            (1, egui::Theme::Dark),
            (99, egui::Theme::Light),
        ] {
            connection
                .emit_signal(
                    None::<&str>,
                    PATH,
                    INTERFACE,
                    "SettingChanged",
                    &(NAMESPACE, KEY, OwnedValue::from(value as u32)),
                )
                .unwrap();
            wait_until(|| seen(&appearance) == Some(theme));
        }
        connection
            .emit_signal(
                None::<&str>,
                PATH,
                INTERFACE,
                "SettingChanged",
                &("unrelated", KEY, OwnedValue::from(1u32)),
            )
            .unwrap();
        thread::sleep(Duration::from_millis(30));
        assert_eq!(seen(&appearance), Some(egui::Theme::Light));
        stop(appearance);
    }

    #[test]
    fn shutdown_cancels_an_unresponsive_settings_read() {
        let bus = Bus::new();
        let entered = Arc::new(AtomicU8::new(0));
        let _connection = server(&bus, entered.clone(), true);
        let appearance = Appearance::start(egui::Context::default(), Some(bus.address.clone()));
        wait_until(|| entered.load(Ordering::Acquire) != 0);
        assert_eq!(seen(&appearance), None);
        stop(appearance);
    }
}

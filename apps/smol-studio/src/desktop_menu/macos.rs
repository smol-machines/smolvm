use eframe::egui::{self, Event, Key, Modifiers};
use objc2::rc::Retained;
use objc2::runtime::{AnyClass, AnyObject, Imp, Sel};
use objc2::{DefinedClass, Encode, MainThreadOnly, define_class, msg_send, sel};
use objc2_app_kit::{
    NSApplication, NSApplicationTerminateReply, NSEventModifierFlags, NSMenu, NSMenuItem,
    NSPasteboard, NSPasteboardTypeString,
};
use objc2_foundation::{MainThreadMarker, NSObject, NSObjectProtocol, NSString};
use std::sync::mpsc::{self, Receiver, SyncSender};
use std::{
    cell::{Cell, RefCell},
    ffi::CString,
    rc::{Rc, Weak},
};

struct QuitGuard {
    allowed: Cell<bool>,
    attempted: Cell<bool>,
    ctx: egui::Context,
}
thread_local! {
    static QUIT_GUARD: RefCell<Option<Weak<QuitGuard>>> = const { RefCell::new(None) };
}

// AppKit calls this for native terminate: requests, including Dock/AppleEvent
// quits. Winit 0.30's delegate has no implementation, so those requests otherwise
// bypass egui's CloseRequested guard. Keep Winit's delegate and all its ivars.
unsafe extern "C-unwind" fn should_terminate(
    _delegate: &AnyObject,
    _selector: Sel,
    _app: &NSApplication,
) -> NSApplicationTerminateReply {
    QUIT_GUARD
        .try_with(|slot| {
            let Ok(slot) = slot.try_borrow() else {
                return NSApplicationTerminateReply::TerminateCancel;
            };
            let Some(guard) = slot.as_ref().and_then(Weak::upgrade) else {
                return NSApplicationTerminateReply::TerminateNow;
            };
            if guard.allowed.get() {
                NSApplicationTerminateReply::TerminateNow
            } else {
                guard.attempted.set(true);
                guard.ctx.request_repaint();
                NSApplicationTerminateReply::TerminateCancel
            }
        })
        .unwrap_or(NSApplicationTerminateReply::TerminateCancel)
}

fn install_quit_guard(app: &NSApplication, ctx: &egui::Context) -> Rc<QuitGuard> {
    let delegate = app
        .delegate()
        .expect("winit installs its application delegate before Studio");
    let object: &AnyObject = (*delegate).as_ref();
    let class = object.class();
    let selector = sel!(applicationShouldTerminate:);
    // SAFETY: Objective-C erases IMP signatures. The encoding below describes
    // exactly this callback: NSUInteger return, receiver, selector, NSApplication.
    let implementation: Imp = unsafe {
        std::mem::transmute(
            should_terminate
                as unsafe extern "C-unwind" fn(
                    &AnyObject,
                    Sel,
                    &NSApplication,
                ) -> NSApplicationTerminateReply,
        )
    };
    if let Some(method) = class.instance_method(selector) {
        assert!(
            std::ptr::fn_addr_eq(method.implementation(), implementation),
            "application delegate already handles termination; preserve its policy before installing Studio's guard"
        );
    } else {
        let encoding =
            CString::new(format!("{}@:@", NSApplicationTerminateReply::ENCODING)).unwrap();
        // SAFETY: Add only an absent method to the actual application delegate
        // class on the main thread; no method replacement, layout or isa change.
        assert!(
            unsafe {
                objc2::ffi::class_addMethod(
                    class as *const AnyClass as *mut AnyClass,
                    selector,
                    implementation,
                    encoding.as_ptr(),
                )
            }
            .as_bool()
        );
    }
    let guard = Rc::new(QuitGuard {
        allowed: Cell::new(false),
        attempted: Cell::new(false),
        ctx: ctx.clone(),
    });
    QUIT_GUARD.with(|slot| *slot.borrow_mut() = Some(Rc::downgrade(&guard)));
    guard
}

#[derive(Clone, Copy)]
enum Command {
    Key(Key, bool),
    Copy,
    Cut,
    Paste,
    Close,
}
struct BridgeState {
    commands: Vec<Command>,
    sender: SyncSender<Command>,
    ctx: egui::Context,
}

define_class!(
    // SAFETY: NSObject has no additional subclass invariants. The receiver is main-thread only.
    #[unsafe(super = NSObject)]
    #[thread_kind = MainThreadOnly]
    #[ivars = BridgeState]
    struct StudioMenuTarget;
    unsafe impl NSObjectProtocol for StudioMenuTarget {}
    impl StudioMenuTarget {
        // Keep Studio's dynamic guards when AppKit auto-validates the app menu.
        #[unsafe(method(validateMenuItem:))]
        fn validate(&self, item: &NSMenuItem) -> bool { item.isEnabled() }

        #[unsafe(method(studioMenuAction:))]
        fn activate(&self, item: &NSMenuItem) {
            if !item.isEnabled() { return; }
            let Some(command) = self.ivars().commands.get(item.tag() as usize).copied() else { return; };
            // Native sheets own their text editing. Try the responder chain before
            // sending editing events to egui's custom view, which has no Cocoa editor.
            let native = match command {
                Command::Copy => Some(sel!(copy:)),
                Command::Cut => Some(sel!(cut:)),
                Command::Paste => Some(sel!(paste:)),
                Command::Key(Key::A, false) => Some(sel!(selectAll:)),
                Command::Key(Key::Z, false) => Some(sel!(undo:)),
                Command::Key(Key::Z, true) => Some(sel!(redo:)),
                _ => None,
            };
            if let Some(action) = native {
                // SAFETY: These are standard one-argument responder action selectors;
                // AppKit chooses a responder implementing the selector, or returns false.
                if unsafe { NSApplication::sharedApplication(self.mtm()).sendAction_to_from(action, None, None) } {
                    return;
                }
            }
            if self.ivars().sender.try_send(command).is_ok() {
                self.ivars().ctx.request_repaint();
            }
        }
    }
);

pub struct DesktopMenu {
    // NSMenuItem.target is weak, so retain the receiver as long as Studio is alive.
    _target: Retained<StudioMenuTarget>,
    quit_guard: Rc<QuitGuard>,
    receiver: Receiver<Command>,
    navigation: Vec<Retained<NSMenuItem>>,
    docker: Vec<Retained<NSMenuItem>>,
    close: Vec<Retained<NSMenuItem>>,
}

fn item(
    mtm: MainThreadMarker,
    title: &str,
    key: &str,
    action: Option<Sel>,
) -> Retained<NSMenuItem> {
    // SAFETY: Actions below have the standard menu-action signature and target NSObject responders.
    unsafe {
        NSMenuItem::initWithTitle_action_keyEquivalent(
            mtm.alloc(),
            &NSString::from_str(title),
            action,
            &NSString::from_str(key),
        )
    }
}
fn submenu(mtm: MainThreadMarker, bar: &NSMenu, title: &str) -> Retained<NSMenu> {
    let menu = NSMenu::new(mtm);
    menu.setTitle(&NSString::from_str(title));
    menu.setAutoenablesItems(false);
    let heading = item(mtm, title, "", None);
    heading.setSubmenu(Some(&menu));
    bar.addItem(&heading);
    menu
}

impl DesktopMenu {
    pub fn new(ctx: &egui::Context) -> Self {
        let mtm = MainThreadMarker::new().expect("Studio initializes its menu on the main thread");
        let app = NSApplication::sharedApplication(mtm);
        let quit_guard = install_quit_guard(&app, ctx);
        let bar = app
            .mainMenu()
            .expect("winit initializes the application menu before Studio");
        let app_menu = bar
            .itemAtIndex(0)
            .and_then(|i| i.submenu())
            .expect("application submenu");
        let (sender, receiver) = mpsc::sync_channel(32);
        let mut commands = Vec::new();
        let mut wired = Vec::new();
        let mut add = |menu: &NSMenu, title: &str, key: &str, command: Command| {
            let entry = item(mtm, title, key, Some(sel!(studioMenuAction:)));
            entry.setTag(commands.len() as isize);
            if matches!(command, Command::Key(_, true)) {
                entry.setKeyEquivalentModifierMask(
                    NSEventModifierFlags::Command | NSEventModifierFlags::Shift,
                );
            }
            commands.push(command);
            wired.push(entry.clone());
            menu.addItem(&entry);
            entry
        };
        // Preserve About, Services, Hide and the framework's existing app menu.
        let settings = add(&app_menu, "Settings…", ",", Command::Key(Key::Comma, false));
        app_menu.removeItem(&settings);
        app_menu.insertItem_atIndex(&settings, 1);
        app_menu.insertItem_atIndex(&NSMenuItem::separatorItem(mtm), 2);
        let edit = submenu(mtm, &bar, "Edit");
        add(&edit, "Undo", "z", Command::Key(Key::Z, false));
        add(&edit, "Redo", "z", Command::Key(Key::Z, true));
        edit.addItem(&NSMenuItem::separatorItem(mtm));
        add(&edit, "Cut", "x", Command::Cut);
        add(&edit, "Copy", "c", Command::Copy);
        add(&edit, "Paste", "v", Command::Paste);
        add(&edit, "Select All", "a", Command::Key(Key::A, false));
        let view = submenu(mtm, &bar, "View");
        let mut navigation = vec![
            settings,
            add(&view, "Go to…", "k", Command::Key(Key::K, false)),
        ];
        view.addItem(&NSMenuItem::separatorItem(mtm));
        let mut docker = Vec::new();
        for (title, key, code) in [
            ("Machines", "1", Key::Num1),
            ("Containers", "2", Key::Num2),
            ("Projects", "3", Key::Num3),
            ("Images", "4", Key::Num4),
            ("Volumes", "5", Key::Num5),
            ("Networks", "6", Key::Num6),
            ("Smol Cloud", "7", Key::Num7),
        ] {
            let entry = add(&view, title, key, Command::Key(code, false));
            if matches!(code, Key::Num1 | Key::Num7) {
                navigation.push(entry);
            } else {
                docker.push(entry);
            }
        }
        let window = submenu(mtm, &bar, "Window");
        let mut close = vec![add(&window, "Close Window", "w", Command::Close)];
        // These use AppKit's normal window responder and auto-validation.
        let minimize = item(mtm, "Minimize", "m", Some(sel!(performMiniaturize:)));
        let zoom = item(mtm, "Zoom", "", Some(sel!(performZoom:)));
        window.addItem(&minimize);
        window.addItem(&zoom);
        window.setAutoenablesItems(true);
        app.setWindowsMenu(Some(&window));
        drop(add);
        // Quit must use Studio's close guard, not NSApplication.terminate, which
        // exits the event loop before an in-flight operation can finish.
        for index in 0..app_menu.numberOfItems() {
            let entry = app_menu.itemAtIndex(index).unwrap();
            if entry.action() == Some(sel!(terminate:)) {
                // SAFETY: The receiver below implements studioMenuAction: for NSMenuItem.
                unsafe { entry.setAction(Some(sel!(studioMenuAction:))) };
                entry.setTag(commands.len() as isize);
                commands.push(Command::Close);
                wired.push(entry.clone());
                close.push(entry);
            }
        }
        let allocated = StudioMenuTarget::alloc(mtm).set_ivars(BridgeState {
            commands,
            sender,
            ctx: ctx.clone(),
        });
        // SAFETY: NSObject.init is the designated superclass initializer.
        let target: Retained<StudioMenuTarget> = unsafe { msg_send![super(allocated), init] };
        for entry in wired {
            // SAFETY: Retained target implements the registered action; _target keeps it alive.
            unsafe { entry.setTarget(Some(&target)) };
        }
        // Standard app commands retain AppKit validation; custom entries use Studio guards.
        Self {
            _target: target,
            quit_guard,
            receiver,
            navigation,
            docker,
            close,
        }
    }

    pub fn input(&self, raw: &mut egui::RawInput) -> bool {
        let mut close = self.quit_guard.attempted.replace(false);
        for command in self.receiver.try_iter() {
            let event = match command {
                Command::Key(key, shift) => Event::Key {
                    key,
                    physical_key: None,
                    pressed: true,
                    repeat: false,
                    modifiers: Modifiers {
                        mac_cmd: true,
                        command: true,
                        shift,
                        ..Default::default()
                    },
                },
                Command::Copy => Event::Copy,
                Command::Cut => Event::Cut,
                Command::Paste => {
                    // SAFETY: AppKit's immutable, process-lifetime pasteboard type constant.
                    if let Some(text) = NSPasteboard::generalPasteboard()
                        .stringForType(unsafe { NSPasteboardTypeString })
                    {
                        raw.events.push(Event::Paste(text.to_string()));
                    }
                    continue;
                }
                Command::Close => {
                    close = true;
                    continue;
                }
            };
            raw.events.push(event.clone());
            if let Event::Key { key, modifiers, .. } = event {
                raw.events.push(Event::Key {
                    key,
                    physical_key: None,
                    pressed: false,
                    repeat: false,
                    modifiers,
                });
            }
        }
        close
    }

    pub fn update(&self, navigation: bool, docker: bool, close: bool) {
        self.quit_guard.allowed.set(close);
        for entry in &self.navigation {
            entry.setEnabled(navigation);
        }
        for entry in &self.docker {
            entry.setEnabled(navigation && docker);
        }
        for entry in &self.close {
            entry.setEnabled(close);
        }
    }
}

// AppKit must run on the process main thread, not a Rust test worker.
#[cfg(target_os = "macos")]
#[path = "../src/desktop_menu.rs"]
mod desktop_menu;

#[cfg(target_os = "macos")]
mod native_editor {
    use objc2::rc::Retained;
    use objc2::runtime::AnyObject;
    use objc2::{DefinedClass, MainThreadOnly, define_class, msg_send};
    use objc2_app_kit::NSResponder;
    use objc2_foundation::MainThreadMarker;
    use std::cell::Cell;

    define_class!(
        // SAFETY: NSResponder has no extra subclass invariants; actions stay on the main thread.
        #[unsafe(super = NSResponder)]
        #[thread_kind = MainThreadOnly]
        #[ivars = Cell<bool>]
        pub struct Editor;
        impl Editor {
            #[unsafe(method(copy:))]
            fn copy(&self, _sender: Option<&AnyObject>) { self.ivars().set(true); }
        }
    );
    impl Editor {
        pub fn new(mtm: MainThreadMarker) -> Retained<Self> {
            let this = Self::alloc(mtm).set_ivars(Cell::new(false));
            // SAFETY: NSResponder's designated initializer.
            unsafe { msg_send![super(this), init] }
        }
        pub fn copied(&self) -> bool {
            self.ivars().get()
        }
    }
}

#[cfg(not(target_os = "macos"))]
fn main() {}

#[cfg(target_os = "macos")]
fn main() {
    use eframe::egui::{self, Event, Key};
    use objc2::sel;
    use objc2_app_kit::{NSApplication, NSMenu, NSMenuItem};
    use objc2_foundation::{MainThreadMarker, ns_string};

    let mtm = MainThreadMarker::new().expect("test runs on the main thread");
    let app = NSApplication::sharedApplication(mtm);
    // The same app-menu shape winit supplies before Studio is constructed.
    let bar = NSMenu::new(mtm);
    let app_menu = NSMenu::new(mtm);
    let heading = NSMenuItem::new(mtm);
    heading.setSubmenu(Some(&app_menu));
    bar.addItem(&heading);
    let about = NSMenuItem::new(mtm);
    about.setTitle(ns_string!("About Smol Studio"));
    app_menu.addItem(&about);
    // SAFETY: terminate: is the standard NSApplication action; the test never invokes it.
    let quit = unsafe {
        NSMenuItem::initWithTitle_action_keyEquivalent(
            mtm.alloc(),
            ns_string!("Quit Smol Studio"),
            Some(sel!(terminate:)),
            ns_string!("q"),
        )
    };
    app_menu.addItem(&quit);
    app.setMainMenu(Some(&bar));
    let ctx = egui::Context::default();
    let menu = desktop_menu::DesktopMenu::new(&ctx);
    assert_eq!(bar.numberOfItems(), 4);
    assert_eq!(
        app_menu.itemAtIndex(0).unwrap().title().to_string(),
        "About Smol Studio"
    );
    let settings = app_menu.itemAtIndex(1).unwrap();
    assert_eq!(settings.title().to_string(), "Settings…");
    assert_eq!(settings.keyEquivalent().to_string(), ",");
    assert_ne!(
        quit.action(),
        Some(sel!(terminate:)),
        "Quit must not bypass the operation guard"
    );
    let edit = bar.itemAtIndex(1).unwrap().submenu().unwrap();
    let view = bar.itemAtIndex(2).unwrap().submenu().unwrap();
    let window = bar.itemAtIndex(3).unwrap().submenu().unwrap();
    assert_eq!(view.title().to_string(), "View");
    assert_eq!(window.title().to_string(), "Window");

    menu.update(false, false, false);
    app_menu.update(); // AppKit's automatic validation must not re-enable guarded items.
    assert!(!settings.isEnabled());
    assert!(!quit.isEnabled());
    assert!(!view.itemAtIndex(0).unwrap().isEnabled());
    assert!(!window.itemAtIndex(0).unwrap().isEnabled());
    let mut raw = egui::RawInput::default();
    app_menu.performActionForItemAtIndex(1);
    assert!(!menu.input(&mut raw));
    assert!(
        raw.events.is_empty(),
        "disabled action must never enqueue input"
    );

    menu.update(true, false, true);
    app_menu.update();
    assert!(settings.isEnabled());
    assert!(
        view.itemAtIndex(2).unwrap().isEnabled(),
        "Machines remains available"
    );
    assert!(
        !view.itemAtIndex(3).unwrap().isEnabled(),
        "busy Docker remains guarded"
    );
    assert!(quit.isEnabled());
    app_menu.performActionForItemAtIndex(1);
    assert!(!menu.input(&mut raw));
    assert!(matches!(raw.events.as_slice(), [
        Event::Key { key: Key::Comma, pressed: true, modifiers, .. },
        Event::Key { key: Key::Comma, pressed: false, .. },
    ] if modifiers.mac_cmd && modifiers.command));
    let mut output = ctx.run_ui(raw, |ui| {
        let ctx = ui.ctx();
        assert!(ctx.input(|i| i.key_pressed(Key::Comma)));
        assert!(
            !ctx.input(|i| i.key_down(Key::Comma)),
            "menu shortcuts must not leave held keys"
        );
    });

    output.textures_delta.clear();

    let mut raw = egui::RawInput::default();
    edit.performActionForItemAtIndex(4); // Copy, with no native editor responder.
    assert!(!menu.input(&mut raw));
    assert!(matches!(raw.events.as_slice(), [Event::Copy]));
    raw.events.clear();
    let native = native_editor::Editor::new(mtm);
    // SAFETY: The application and its original responder chain are live on the main thread.
    let previous = unsafe { app.nextResponder() };
    // SAFETY: Retain the native editor throughout its use in the responder chain.
    unsafe {
        app.setNextResponder(Some(&native));
    }
    edit.performActionForItemAtIndex(4);
    assert!(
        native.copied(),
        "native editors must receive their own copy action"
    );
    assert!(!menu.input(&mut raw));
    assert!(
        raw.events.is_empty(),
        "a native edit must not also reach egui"
    );
    // SAFETY: Restore the original retained responder before dropping our editor.
    unsafe {
        app.setNextResponder(previous.as_deref());
    }
    edit.performActionForItemAtIndex(1); // Redo.
    assert!(!menu.input(&mut raw));
    assert!(
        matches!(&raw.events[0], Event::Key { key: Key::Z, modifiers, .. } if modifiers.shift && modifiers.mac_cmd)
    );
    raw.events.clear();
    window.performActionForItemAtIndex(0);
    assert!(
        menu.input(&mut raw),
        "Close must enter Studio's close guard"
    );
    app_menu.performActionForItemAtIndex(app_menu.numberOfItems() - 1);
    assert!(menu.input(&mut raw), "Quit must enter the same close guard");
    println!("Native menu validation, navigation/edit events and guarded Close/Quit passed");
}

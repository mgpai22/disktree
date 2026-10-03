//! "Show more options": Explorer's own context menu for one path, without
//! its Delete and Cut. Removal belongs to the marks and the review screen,
//! where the guards are; a verb that bypassed them would be a second,
//! unguarded way to delete.
//!
//! The app's only `unsafe` outside `main.rs`'s console: COM through raw
//! vtables, because `windows-sys` binds functions and not interfaces.
#![allow(
    unsafe_code,
    reason = "the shell's menu is COM and Win32, which have no safe binding \
              in windows-sys"
)]

use std::cell::Cell;
use std::ffi::c_void;
use std::io;
use std::os::windows::ffi::OsStrExt as _;
use std::path::Path;
use std::ptr::{null, null_mut};

use raw_window_handle::{HasWindowHandle, RawWindowHandle};
use windows_sys::Win32::Foundation::{HWND, LPARAM, LRESULT, POINT, WPARAM};
use windows_sys::Win32::Graphics::Gdi::ClientToScreen;
use windows_sys::Win32::System::Com::{
    COINIT_APARTMENTTHREADED, CoInitializeEx, CoUninitialize,
};
use windows_sys::Win32::UI::Shell::Common::ITEMIDLIST;
use windows_sys::Win32::UI::Shell::{
    CMF_NORMAL, CMINVOKECOMMANDINFO, GCS_VERBW, ILFree, SHBindToParent,
    SHParseDisplayName,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    CallWindowProcW, CreatePopupMenu, DeleteMenu, DestroyMenu, GWLP_WNDPROC,
    GetMenuItemCount, GetMenuItemID, HMENU, MF_BYPOSITION, SW_SHOWNORMAL,
    SetForegroundWindow, SetWindowLongPtrW, TPM_RETURNCMD, TPM_RIGHTBUTTON,
    TrackPopupMenuEx, WM_DRAWITEM, WM_INITMENUPOPUP, WM_MEASUREITEM,
    WM_MENUCHAR, WNDPROC,
};
use windows_sys::core::{GUID, HRESULT};

const IID_ISHELLFOLDER: GUID =
    GUID::from_u128(0x0002_14e6_0000_0000_c000_0000_0000_0046);
const IID_ICONTEXTMENU: GUID =
    GUID::from_u128(0x0002_14e4_0000_0000_c000_0000_0000_0046);
const IID_ICONTEXTMENU3: GUID =
    GUID::from_u128(0xbcfc_e0a0_ec17_11d0_8d10_00a0_c90f_2719);

/// Command ids the shell may hand out. The range only has to be wider than
/// any menu: ids are offsets from the first.
const FIRST_ID: u32 = 1;
const LAST_ID: u32 = 0x7fff;

/// Verbs that only look or open, after which nothing on disk has changed
/// and there is nothing to read again.
const READ_ONLY_VERBS: [&str; 14] = [
    "open",
    "openas",
    "opennewwindow",
    "opennewprocess",
    "opennewtab",
    "explore",
    "find",
    "properties",
    "copyaspath",
    "copy",
    "share",
    "pintohome",
    "pintostartscreen",
    "print",
];

/// Whether the folder must be read again after `verb` ran. A verb a
/// handler would not name is assumed to have changed something.
pub fn changes_disk(verb: &str) -> bool {
    !READ_ONLY_VERBS
        .iter()
        .any(|known| known.eq_ignore_ascii_case(verb))
}

/// The window's HWND, as a plain number so it can wait for the menu in a
/// task.
pub fn hwnd(window: &gpui_kit::Window) -> Option<isize> {
    match HasWindowHandle::window_handle(window).ok()?.as_raw() {
        RawWindowHandle::Win32(handle) => Some(handle.hwnd.get()),
        _ => None,
    }
}

#[repr(C)]
struct UnknownVtbl {
    query_interface: unsafe extern "system" fn(
        *mut c_void,
        *const GUID,
        *mut *mut c_void,
    ) -> HRESULT,
    add_ref: unsafe extern "system" fn(*mut c_void) -> u32,
    release: unsafe extern "system" fn(*mut c_void) -> u32,
}

/// `IShellFolder` up to the one method used; later slots are never read.
#[repr(C)]
struct ShellFolderVtbl {
    unknown: UnknownVtbl,
    parse_display_name: usize,
    enum_objects: usize,
    bind_to_object: usize,
    bind_to_storage: usize,
    compare_ids: usize,
    create_view_object: usize,
    get_attributes_of: usize,
    get_ui_object_of: unsafe extern "system" fn(
        *mut c_void,
        HWND,
        u32,
        *const *const ITEMIDLIST,
        *const GUID,
        *mut u32,
        *mut *mut c_void,
    ) -> HRESULT,
}

#[repr(C)]
struct ContextMenuVtbl {
    unknown: UnknownVtbl,
    query_context_menu: unsafe extern "system" fn(
        *mut c_void,
        HMENU,
        u32,
        u32,
        u32,
        u32,
    ) -> HRESULT,
    invoke_command: unsafe extern "system" fn(
        *mut c_void,
        *const CMINVOKECOMMANDINFO,
    ) -> HRESULT,
    get_command_string: unsafe extern "system" fn(
        *mut c_void,
        usize,
        u32,
        *const u32,
        *mut u8,
        u32,
    ) -> HRESULT,
}

/// `IContextMenu3`: `IContextMenu2::HandleMenuMsg`, then `HandleMenuMsg2`.
#[repr(C)]
struct ContextMenu3Vtbl {
    menu: ContextMenuVtbl,
    handle_menu_msg:
        unsafe extern "system" fn(*mut c_void, u32, WPARAM, LPARAM) -> HRESULT,
    handle_menu_msg2: unsafe extern "system" fn(
        *mut c_void,
        u32,
        WPARAM,
        LPARAM,
        *mut LRESULT,
    ) -> HRESULT,
}

/// An owned interface pointer, released on drop.
struct Com(*mut c_void);

impl Com {
    /// SAFETY: the caller names the vtable layout of the interface this
    /// pointer was asked for.
    const unsafe fn vtbl<V>(&self) -> &V {
        // SAFETY: a COM object starts with its vtable pointer.
        unsafe { &**self.0.cast::<*const V>() }
    }
}

impl Drop for Com {
    fn drop(&mut self) {
        // SAFETY: the pointer came from a successful query, which owes one
        // release; every interface starts with IUnknown.
        unsafe { (self.vtbl::<UnknownVtbl>().release)(self.0) };
    }
}

fn check(result: HRESULT) -> io::Result<()> {
    if result < 0 {
        Err(io::Error::from_raw_os_error(result))
    } else {
        Ok(())
    }
}

thread_local! {
    /// The open menu's `IContextMenu3` and the window procedure it was
    /// slipped in front of, while `TrackPopupMenuEx` runs. Without this,
    /// submenus such as "Open with" and "Send to" are drawn empty.
    static MENU3: Cell<*mut c_void> = const { Cell::new(null_mut()) };
    static PREVIOUS: Cell<isize> = const { Cell::new(0) };
}

unsafe extern "system" fn forward(
    hwnd: HWND,
    message: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    let menu3 = MENU3.get();
    if !menu3.is_null()
        && matches!(
            message,
            WM_INITMENUPOPUP | WM_DRAWITEM | WM_MEASUREITEM | WM_MENUCHAR
        )
    {
        let mut result: LRESULT = 0;
        // SAFETY: `MENU3` holds a live IContextMenu3 for as long as it is
        // set; `show` clears it before releasing the interface.
        let handled = unsafe {
            let vtbl = &**menu3.cast::<*const ContextMenu3Vtbl>();
            (vtbl.handle_menu_msg2)(
                menu3,
                message,
                wparam,
                lparam,
                &raw mut result,
            )
        };
        if handled >= 0 {
            return result;
        }
    }
    // SAFETY: `PREVIOUS` is the procedure `SetWindowLongPtrW` returned,
    // the same width as a `WNDPROC`.
    unsafe {
        let previous = std::mem::transmute::<isize, WNDPROC>(PREVIOUS.get());
        CallWindowProcW(previous, hwnd, message, wparam, lparam)
    }
}

/// Removes the forwarding procedure and lets go of the menu on every exit.
struct Subclass(HWND);

impl Drop for Subclass {
    fn drop(&mut self) {
        // SAFETY: puts back exactly the procedure that was replaced.
        unsafe { SetWindowLongPtrW(self.0, GWLP_WNDPROC, PREVIOUS.get()) };
        MENU3.set(null_mut());
    }
}

/// Show Explorer's menu for `path` at `(x, y)`, client pixels of the window
/// `hwnd`, run what is picked, and return its verb: `None` when the menu
/// was dismissed, an empty verb when the handler would not name it.
///
/// Must not run inside an entity update: the menu's modal loop lets GPUI
/// draw and run tasks, which would find the app already borrowed.
pub fn show(
    hwnd: isize,
    path: &Path,
    x: i32,
    y: i32,
) -> io::Result<Option<String>> {
    let hwnd = hwnd as HWND;
    // SAFETY: plain calls; a successful initialisation, including the
    // S_FALSE of one already done on this thread, is balanced below.
    let initialised = unsafe {
        CoInitializeEx(null(), COINIT_APARTMENTTHREADED.cast_unsigned())
    } >= 0;
    let result = show_initialised(hwnd, path, x, y);
    if initialised {
        // SAFETY: balances the successful CoInitializeEx above.
        unsafe { CoUninitialize() };
    }
    result
}

fn show_initialised(
    hwnd: HWND,
    path: &Path,
    x: i32,
    y: i32,
) -> io::Result<Option<String>> {
    let wide: Vec<u16> =
        path.as_os_str().encode_wide().chain(Some(0)).collect();
    let mut pidl: *mut ITEMIDLIST = null_mut();
    // SAFETY: `wide` is NUL-terminated and outlives the call.
    check(unsafe {
        SHParseDisplayName(
            wide.as_ptr(),
            null_mut(),
            &raw mut pidl,
            0,
            null_mut(),
        )
    })?;
    let result = menu_for(hwnd, pidl, x, y);
    // SAFETY: the shell allocated `pidl`, and nothing refers to it now.
    unsafe { ILFree(pidl) };
    result
}

fn menu_for(
    hwnd: HWND,
    pidl: *const ITEMIDLIST,
    x: i32,
    y: i32,
) -> io::Result<Option<String>> {
    let mut folder = null_mut();
    let mut child: *mut ITEMIDLIST = null_mut();
    // SAFETY: `pidl` is valid; `child` points into it and is not freed.
    check(unsafe {
        SHBindToParent(pidl, &IID_ISHELLFOLDER, &raw mut folder, &raw mut child)
    })?;
    let folder = Com(folder);
    let mut menu = null_mut();
    let children = [child.cast_const()];
    // SAFETY: an IShellFolder, asked for one child it holds.
    check(unsafe {
        (folder.vtbl::<ShellFolderVtbl>().get_ui_object_of)(
            folder.0,
            hwnd,
            1,
            children.as_ptr(),
            &IID_ICONTEXTMENU,
            null_mut(),
            &raw mut menu,
        )
    })?;
    let menu = Com(menu);
    // SAFETY: plain call; destroyed by the guard below.
    let popup = unsafe { CreatePopupMenu() };
    if popup.is_null() {
        return Err(io::Error::last_os_error());
    }
    let _popup = Popup(popup);
    // SAFETY: an IContextMenu filling a menu it is given.
    check(unsafe {
        (menu.vtbl::<ContextMenuVtbl>().query_context_menu)(
            menu.0, popup, 0, FIRST_ID, LAST_ID, CMF_NORMAL,
        )
    })?;
    remove_removal_verbs(&menu, popup);

    let mut menu3 = null_mut();
    // SAFETY: IUnknown's query; a menu without IContextMenu3 says so.
    let menu3 = (unsafe {
        (menu.vtbl::<UnknownVtbl>().query_interface)(
            menu.0,
            &IID_ICONTEXTMENU3,
            &raw mut menu3,
        )
    } >= 0)
        .then(|| Com(menu3));

    let mut at = POINT { x, y };
    // SAFETY: `at` is a valid POINT for the call to fill.
    unsafe { ClientToScreen(hwnd, &raw mut at) };
    let chosen = {
        // SAFETY: the window procedure is swapped only for this block and
        // put back by `Subclass`'s drop, before `menu3` is released.
        let _subclass = unsafe {
            MENU3.set(menu3.as_ref().map_or(null_mut(), |menu3| menu3.0));
            let forward: unsafe extern "system" fn(
                HWND,
                u32,
                WPARAM,
                LPARAM,
            ) -> LRESULT = forward;
            PREVIOUS.set(SetWindowLongPtrW(
                hwnd,
                GWLP_WNDPROC,
                (forward as usize).cast_signed(),
            ));
            Subclass(hwnd)
        };
        // SAFETY: a menu owned by this window; the foreground call is what
        // lets a click elsewhere dismiss it.
        unsafe {
            SetForegroundWindow(hwnd);
            TrackPopupMenuEx(
                popup,
                TPM_RETURNCMD | TPM_RIGHTBUTTON,
                at.x,
                at.y,
                hwnd,
                null(),
            )
        }
    };
    let Ok(id) = u32::try_from(chosen) else {
        return Ok(None);
    };
    if id < FIRST_ID {
        return Ok(None);
    }
    let offset = id - FIRST_ID;
    let verb = verb(&menu, offset).unwrap_or_default();
    let info = CMINVOKECOMMANDINFO {
        cbSize: size_of::<CMINVOKECOMMANDINFO>() as u32,
        hwnd,
        // MAKEINTRESOURCEA: the command by its offset, not its verb.
        lpVerb: offset as usize as *const u8,
        nShow: SW_SHOWNORMAL,
        ..CMINVOKECOMMANDINFO::default()
    };
    // SAFETY: `info` is complete and outlives the call.
    check(unsafe {
        (menu.vtbl::<ContextMenuVtbl>().invoke_command)(menu.0, &raw const info)
    })?;
    Ok(Some(verb))
}

/// A popup menu, destroyed on drop.
struct Popup(HMENU);

impl Drop for Popup {
    fn drop(&mut self) {
        // SAFETY: created by CreatePopupMenu and not destroyed elsewhere.
        unsafe { DestroyMenu(self.0) };
    }
}

/// The language-independent name of the command at `offset`.
fn verb(menu: &Com, offset: u32) -> Option<String> {
    let mut name = [0_u16; 256];
    // SAFETY: GCS_VERBW writes at most `name.len()` UTF-16 units.
    let result = unsafe {
        (menu.vtbl::<ContextMenuVtbl>().get_command_string)(
            menu.0,
            offset as usize,
            GCS_VERBW,
            null(),
            name.as_mut_ptr().cast(),
            name.len() as u32,
        )
    };
    if result < 0 {
        return None;
    }
    let end = name
        .iter()
        .position(|&unit| unit == 0)
        .unwrap_or(name.len());
    Some(String::from_utf16_lossy(&name[..end]))
}

/// Take Delete and Cut out of the top level, where the shell puts them.
fn remove_removal_verbs(menu: &Com, popup: HMENU) {
    // SAFETY: a live menu handle.
    let count = unsafe { GetMenuItemCount(popup) };
    // Backwards, so a removal does not shift what is still to be looked at.
    for position in (0..count).rev() {
        // SAFETY: a position within the count just read.
        let id = unsafe { GetMenuItemID(popup, position) };
        // Separators are 0 and submenus u32::MAX: neither is a verb.
        if !(FIRST_ID..=LAST_ID).contains(&id) {
            continue;
        }
        let removal = verb(menu, id - FIRST_ID).is_some_and(|verb| {
            verb.eq_ignore_ascii_case("delete")
                || verb.eq_ignore_ascii_case("cut")
        });
        if removal {
            // SAFETY: the same live menu and an existing position.
            unsafe { DeleteMenu(popup, position as u32, MF_BYPOSITION) };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::changes_disk;

    #[test]
    fn only_verbs_that_look_skip_the_refresh() {
        assert!(!changes_disk("properties"));
        assert!(!changes_disk("CopyAsPath"));
        assert!(changes_disk("rename"));
        assert!(changes_disk("paste"));
        assert!(changes_disk(""));
    }
}

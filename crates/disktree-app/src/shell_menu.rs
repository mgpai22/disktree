//! Explorer's rows for the right-click menu on Windows, read into plain
//! data that disktree's own menu draws. The shell builds them into a Win32
//! menu that is never shown; this reads it, and runs the row picked by its
//! command id. Explorer's part comes without its Delete and Cut: removal
//! belongs to the marks and the review screen, where the guards are; a verb
//! that bypassed them would be a second, unguarded way to delete.
//!
//! The app's only `unsafe` outside `main.rs`'s console: COM through raw
//! vtables, because `windows-sys` binds functions and not interfaces.
#![allow(
    unsafe_code,
    reason = "the shell's menu is COM and Win32, which have no safe binding \
              in windows-sys"
)]

use std::cell::RefCell;
use std::ffi::c_void;
use std::io;
use std::os::windows::ffi::OsStrExt as _;
use std::path::Path;
use std::ptr::{null, null_mut};
use std::rc::Rc;
use std::sync::Arc;

use gpui_kit::RenderImage;
use image::{Frame, RgbaImage};
use raw_window_handle::{HasWindowHandle, RawWindowHandle};
use windows_sys::Win32::Foundation::{HWND, LPARAM, WPARAM};
use windows_sys::Win32::Graphics::Gdi::{
    BI_RGB, BITMAP, BITMAPINFO, BITMAPINFOHEADER, DIB_RGB_COLORS, GetDC,
    GetDIBits, GetObjectW, HBITMAP, ReleaseDC,
};
use windows_sys::Win32::System::Com::{
    COINIT_APARTMENTTHREADED, CoInitializeEx, CoUninitialize,
};
use windows_sys::Win32::UI::Shell::Common::ITEMIDLIST;
use windows_sys::Win32::UI::Shell::{
    CMF_NORMAL, CMINVOKECOMMANDINFO, GCS_HELPTEXTW, GCS_VERBW, ILFree,
    SHBindToParent, SHParseDisplayName,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    CreatePopupMenu, DestroyMenu, GetMenuItemCount, GetMenuItemInfoW,
    HBMMENU_CALLBACK, HBMMENU_POPUP_MINIMIZE, HMENU, MENUITEMINFOW,
    MFS_CHECKED, MFS_DEFAULT, MFS_DISABLED, MFT_OWNERDRAW, MFT_SEPARATOR,
    MIIM_BITMAP, MIIM_FTYPE, MIIM_ID, MIIM_STATE, MIIM_STRING, MIIM_SUBMENU,
    SW_SHOWNORMAL, WM_INITMENUPOPUP,
};
use windows_sys::core::{GUID, HRESULT};

/// One entry of Explorer's menu, as disktree's menu draws it.
#[derive(Clone, Debug)]
pub enum ShellItem {
    Separator,
    Row(ShellRow),
}

/// A row of Explorer's menu.
#[derive(Clone, Debug)]
pub struct ShellRow {
    /// The command id [`ShellMenu::invoke`] takes; a submenu's is unused.
    pub id: u32,
    pub label: String,
    pub enabled: bool,
    pub checked: bool,
    /// What a double click in Explorer does, drawn in bold.
    pub default: bool,
    pub icon: Option<Arc<RenderImage>>,
    /// The rows of its submenu, if it opens one.
    pub children: Option<Rc<[ShellItem]>>,
}

const IID_ISHELLFOLDER: GUID =
    GUID::from_u128(0x0002_14e6_0000_0000_c000_0000_0000_0046);
const IID_ICONTEXTMENU: GUID =
    GUID::from_u128(0x0002_14e4_0000_0000_c000_0000_0000_0046);
const IID_ICONTEXTMENU2: GUID =
    GUID::from_u128(0x0002_14f4_0000_0000_c000_0000_0000_0046);

/// Command ids the shell may hand out. The range only has to be wider than
/// any menu: ids are offsets from the first.
const FIRST_ID: u32 = 1;
const LAST_ID: u32 = 0x7fff;
/// How deep submenus are read: Explorer's go two levels at most, and a
/// handler that nests forever must not hang the menu.
const MAX_DEPTH: u32 = 3;

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

/// Delete and Cut, which the menu leaves out.
const fn removes(verb: &str) -> bool {
    verb.eq_ignore_ascii_case("delete") || verb.eq_ignore_ascii_case("cut")
}

/// The window's HWND, as a plain number the menu's task can carry.
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

/// `IContextMenu2`, whose `HandleMenuMsg` `IContextMenu3` keeps.
#[repr(C)]
struct ContextMenu2Vtbl {
    menu: ContextMenuVtbl,
    handle_menu_msg:
        unsafe extern "system" fn(*mut c_void, u32, WPARAM, LPARAM) -> HRESULT,
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

/// This thread's COM apartment, joined for as long as the menu lives.
struct Apartment(bool);

impl Apartment {
    fn join() -> Self {
        // SAFETY: plain call; a success, including the S_FALSE of one
        // already joined on this thread, is balanced on drop.
        Self(
            unsafe {
                CoInitializeEx(null(), COINIT_APARTMENTTHREADED.cast_unsigned())
            } >= 0,
        )
    }
}

impl Drop for Apartment {
    fn drop(&mut self) {
        if self.0 {
            // SAFETY: balances the successful CoInitializeEx in `join`.
            unsafe { CoUninitialize() };
        }
    }
}

/// An item list the shell allocated, freed on drop.
struct Pidl(*mut ITEMIDLIST);

impl Drop for Pidl {
    fn drop(&mut self) {
        // SAFETY: the shell allocated it, and nothing refers to it now.
        unsafe { ILFree(self.0) };
    }
}

/// A popup menu, destroyed on drop.
struct Popup(HMENU);

impl Drop for Popup {
    fn drop(&mut self) {
        // SAFETY: created by CreatePopupMenu and not destroyed elsewhere.
        unsafe { DestroyMenu(self.0) };
    }
}

/// Explorer's menu for one path, kept alive while disktree's menu shows
/// its rows: a handler may expect its menu to outlive the pick, and some
/// go on filling it after it was made. Fields drop in order: the handler
/// before the menu handle, folder, item list and apartment it was made
/// with.
pub struct ShellMenu {
    menu2: Option<Com>,
    menu: Com,
    _folder: Com,
    _pidl: Pidl,
    popup: Popup,
    _apartment: Apartment,
    hwnd: HWND,
    /// Submenus already told they are about to open: told again, a
    /// handler may start its filling over.
    opened: RefCell<Vec<HMENU>>,
}

impl std::fmt::Debug for ShellMenu {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ShellMenu")
    }
}

/// Explorer's menu for `path`, owned by the window `hwnd`. Runs on the UI
/// thread, whose apartment the shell's objects live in, and outside any
/// entity update: a handler may pump messages while it fills its rows.
pub fn load(hwnd: isize, path: &Path) -> io::Result<ShellMenu> {
    let hwnd = hwnd as HWND;
    let apartment = Apartment::join();
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
    let pidl = Pidl(pidl);
    let mut folder = null_mut();
    let mut child: *mut ITEMIDLIST = null_mut();
    // SAFETY: `pidl` is valid; `child` points into it and is not freed.
    check(unsafe {
        SHBindToParent(
            pidl.0,
            &IID_ISHELLFOLDER,
            &raw mut folder,
            &raw mut child,
        )
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
    // SAFETY: plain call; destroyed by the guard.
    let popup = Popup(unsafe { CreatePopupMenu() });
    if popup.0.is_null() {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: an IContextMenu filling a menu it is given.
    check(unsafe {
        (menu.vtbl::<ContextMenuVtbl>().query_context_menu)(
            menu.0, popup.0, 0, FIRST_ID, LAST_ID, CMF_NORMAL,
        )
    })?;
    let mut menu2 = null_mut();
    // SAFETY: IUnknown's query; a menu without IContextMenu2 says so, and
    // then fills its submenus up front or not at all.
    let menu2 = (unsafe {
        (menu.vtbl::<UnknownVtbl>().query_interface)(
            menu.0,
            &IID_ICONTEXTMENU2,
            &raw mut menu2,
        )
    } >= 0)
        .then(|| Com(menu2));
    Ok(ShellMenu {
        menu2,
        menu,
        _folder: folder,
        _pidl: pidl,
        popup,
        _apartment: apartment,
        hwnd,
        opened: RefCell::new(Vec::new()),
    })
}

impl ShellMenu {
    /// Explorer's rows as they stand, without Delete and Cut. Some
    /// handlers fill theirs over the next moments, from messages this
    /// thread's loop delivers, as "Send to" does: a later call finds more.
    /// Outside any entity update, as `load`.
    pub fn rows(&self) -> Vec<ShellItem> {
        read(self, self.popup.0, 0)
    }

    /// Run the row with command `id`, and name its verb: empty when the
    /// handler would not name it. Outside any entity update, as `load`.
    pub fn invoke(&self, id: u32) -> io::Result<String> {
        let offset = id
            .checked_sub(FIRST_ID)
            .ok_or_else(|| io::Error::other("not a shell command"))?;
        let verb =
            command_string(&self.menu, offset, GCS_VERBW).unwrap_or_default();
        let info = CMINVOKECOMMANDINFO {
            cbSize: size_of::<CMINVOKECOMMANDINFO>() as u32,
            hwnd: self.hwnd,
            // MAKEINTRESOURCEA: the command by its offset, not its verb.
            lpVerb: offset as usize as *const u8,
            nShow: SW_SHOWNORMAL,
            ..CMINVOKECOMMANDINFO::default()
        };
        // SAFETY: `info` is complete and outlives the call.
        check(unsafe {
            (self.menu.vtbl::<ContextMenuVtbl>().invoke_command)(
                self.menu.0,
                &raw const info,
            )
        })?;
        Ok(verb)
    }
}

/// The rows of `popup`, a level `depth` submenus down in `shell`.
fn read(shell: &ShellMenu, popup: HMENU, depth: u32) -> Vec<ShellItem> {
    let menu = &shell.menu;
    // SAFETY: a live menu handle.
    let count =
        u32::try_from(unsafe { GetMenuItemCount(popup) }).unwrap_or_default();
    let mut items = Vec::new();
    for position in 0..count {
        // SAFETY: MENUITEMINFOW is plain data, valid all zero.
        let mut info: MENUITEMINFOW = unsafe { std::mem::zeroed() };
        info.cbSize = size_of::<MENUITEMINFOW>() as u32;
        info.fMask = MIIM_FTYPE
            | MIIM_STATE
            | MIIM_ID
            | MIIM_SUBMENU
            | MIIM_STRING
            | MIIM_BITMAP;
        // SAFETY: a position within the count; with no buffer the call
        // only measures the text, into `cch`.
        if unsafe { GetMenuItemInfoW(popup, position, 1, &raw mut info) } == 0 {
            continue;
        }
        if info.fType & MFT_SEPARATOR != 0 {
            items.push(ShellItem::Separator);
            continue;
        }
        let leaf = info.hSubMenu.is_null();
        // A leaf outside the range is nothing `invoke` could run.
        let offset = (FIRST_ID..=LAST_ID)
            .contains(&info.wID)
            .then(|| info.wID - FIRST_ID);
        if leaf && offset.is_none() {
            continue;
        }
        let verb = offset
            .filter(|_| leaf)
            .and_then(|offset| command_string(menu, offset, GCS_VERBW));
        if verb.as_deref().is_some_and(removes) {
            continue;
        }
        // An owner-drawn row keeps its own data where the text would be.
        let text = if info.fType & MFT_OWNERDRAW == 0 {
            text(popup, position, info.cch)
        } else {
            String::new()
        };
        let text = if text.is_empty() {
            // A row the handler draws itself: named by its help text or
            // verb, or left out when it has neither.
            offset
                .filter(|_| leaf)
                .and_then(|offset| command_string(menu, offset, GCS_HELPTEXTW))
                .filter(|help| !help.is_empty())
                .or(verb)
                .unwrap_or_default()
        } else {
            text
        };
        if text.is_empty() {
            continue;
        }
        let children = if leaf {
            None
        } else {
            if depth + 1 >= MAX_DEPTH {
                continue;
            }
            let fresh = !shell.opened.borrow().contains(&info.hSubMenu);
            if let Some(menu2) = &shell.menu2
                && fresh
            {
                shell.opened.borrow_mut().push(info.hSubMenu);
                // "Open with" and "Send to" fill themselves only once told
                // their submenu is about to open, as Explorer tells them.
                // SAFETY: an IContextMenu2 and a submenu of its menu.
                unsafe {
                    (menu2.vtbl::<ContextMenu2Vtbl>().handle_menu_msg)(
                        menu2.0,
                        WM_INITMENUPOPUP,
                        info.hSubMenu as WPARAM,
                        LPARAM::try_from(position).unwrap_or_default(),
                    )
                };
            }
            let children = read(shell, info.hSubMenu, depth + 1);
            if children.is_empty() {
                continue;
            }
            Some(children.into())
        };
        items.push(ShellItem::Row(ShellRow {
            id: info.wID,
            label: label(&text),
            enabled: info.fState & MFS_DISABLED == 0,
            checked: info.fState & MFS_CHECKED != 0,
            default: info.fState & MFS_DEFAULT != 0,
            icon: icon(info.hbmpItem),
            children,
        }));
    }
    tidy(items)
}

/// The text of the row at `position`, `cch` UTF-16 units long.
fn text(popup: HMENU, position: u32, cch: u32) -> String {
    if cch == 0 {
        return String::new();
    }
    let mut buffer = vec![0_u16; cch as usize + 1];
    // SAFETY: MENUITEMINFOW is plain data, valid all zero.
    let mut info: MENUITEMINFOW = unsafe { std::mem::zeroed() };
    info.cbSize = size_of::<MENUITEMINFOW>() as u32;
    info.fMask = MIIM_STRING;
    info.dwTypeData = buffer.as_mut_ptr();
    info.cch = buffer.len() as u32;
    // SAFETY: `buffer` holds `cch` units and outlives the call.
    if unsafe { GetMenuItemInfoW(popup, position, 1, &raw mut info) } == 0 {
        return String::new();
    }
    let end = (info.cch as usize).min(buffer.len());
    String::from_utf16_lossy(&buffer[..end])
}

/// A menu string as drawn here: `&` marks the next letter as the access
/// key and is dropped, `&&` is a literal `&`. A key hint after a tab is
/// dropped too: the shell's rows have no keys in disktree.
fn label(text: &str) -> String {
    let text = text.split_once('\t').map_or(text, |(label, _)| label);
    let mut plain = String::with_capacity(text.len());
    let mut chars = text.chars();
    while let Some(char) = chars.next() {
        if char == '&' {
            plain.extend(chars.next());
        } else {
            plain.push(char);
        }
    }
    plain
}

/// Whether two reads found the same rows, icons aside: each read makes
/// new images of the same bitmaps.
pub fn same_rows(a: &[ShellItem], b: &[ShellItem]) -> bool {
    a.len() == b.len()
        && a.iter().zip(b).all(|pair| match pair {
            (ShellItem::Separator, ShellItem::Separator) => true,
            (ShellItem::Row(a), ShellItem::Row(b)) => {
                (a.id, &a.label, a.enabled, a.checked, a.default)
                    == (b.id, &b.label, b.enabled, b.checked, b.default)
                    && match (&a.children, &b.children) {
                        (Some(a), Some(b)) => same_rows(a, b),
                        (a, b) => a.is_none() && b.is_none(),
                    }
            }
            _ => false,
        })
}

/// No separator first, last or after another: the rows left out may have
/// stood between them.
fn tidy(items: Vec<ShellItem>) -> Vec<ShellItem> {
    let mut tidy: Vec<ShellItem> = Vec::with_capacity(items.len());
    for item in items {
        let after_rows = matches!(tidy.last(), Some(ShellItem::Row(_)));
        if after_rows || matches!(item, ShellItem::Row(_)) {
            tidy.push(item);
        }
    }
    if matches!(tidy.last(), Some(ShellItem::Separator)) {
        tidy.pop();
    }
    tidy
}

/// A string the handler gives for the command at `offset`: its verb or
/// its help text.
fn command_string(menu: &Com, offset: u32, kind: u32) -> Option<String> {
    let mut name = [0_u16; 256];
    // SAFETY: the W kinds write at most `name.len()` UTF-16 units.
    let result = unsafe {
        (menu.vtbl::<ContextMenuVtbl>().get_command_string)(
            menu.0,
            offset as usize,
            kind,
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

/// The row's bitmap as an image GPUI draws: none for the stock
/// `HBMMENU_*` glyphs, which are small numbers, or for one the handler
/// would draw itself.
fn icon(bitmap: HBITMAP) -> Option<Arc<RenderImage>> {
    if bitmap.is_null()
        || bitmap == HBMMENU_CALLBACK
        || bitmap as isize <= HBMMENU_POPUP_MINIMIZE as isize
    {
        return None;
    }
    // SAFETY: BITMAP is plain data, valid all zero.
    let mut header: BITMAP = unsafe { std::mem::zeroed() };
    let size = i32::try_from(size_of::<BITMAP>()).ok()?;
    // SAFETY: `header` is a BITMAP for the call to fill.
    let filled = unsafe { GetObjectW(bitmap, size, (&raw mut header).cast()) };
    let width = u32::try_from(header.bmWidth).ok()?;
    let height = header.bmHeight.unsigned_abs();
    if filled == 0 || width == 0 || height == 0 {
        return None;
    }
    // SAFETY: BITMAPINFO is plain data, valid all zero.
    let mut info: BITMAPINFO = unsafe { std::mem::zeroed() };
    info.bmiHeader = BITMAPINFOHEADER {
        biSize: size_of::<BITMAPINFOHEADER>() as u32,
        biWidth: header.bmWidth,
        // Negative: top row first, as an image is stored.
        biHeight: -header.bmHeight.abs(),
        biPlanes: 1,
        biBitCount: 32,
        biCompression: BI_RGB,
        ..BITMAPINFOHEADER::default()
    };
    let mut pixels = vec![0_u8; width as usize * height as usize * 4];
    // SAFETY: the screen's DC, released below; `pixels` holds every row
    // of 32-bit pixels the header asks for.
    let lines = unsafe {
        let dc = GetDC(null_mut());
        let lines = GetDIBits(
            dc,
            bitmap,
            0,
            height,
            pixels.as_mut_ptr().cast(),
            &raw mut info,
            DIB_RGB_COLORS,
        );
        ReleaseDC(null_mut(), dc);
        lines
    };
    if lines == 0 {
        return None;
    }
    straighten(&mut pixels, header.bmBitsPixel == 32);
    // GPUI reads the buffer as BGRA, the order GDI wrote it in.
    let image = RgbaImage::from_raw(width, height, pixels)?;
    Some(Arc::new(RenderImage::new([Frame::new(image)])))
}

/// Undo the premultiplied alpha the shell's 32-bit bitmaps carry, for
/// GPUI, which wants it straight. A bitmap with no alpha at all, as any of
/// fewer bits, is opaque.
fn straighten(pixels: &mut [u8], has_alpha: bool) {
    let has_alpha =
        has_alpha && pixels.chunks_exact(4).any(|pixel| pixel[3] != 0);
    for pixel in pixels.chunks_exact_mut(4) {
        if !has_alpha {
            pixel[3] = u8::MAX;
            continue;
        }
        let alpha = u16::from(pixel[3]);
        if alpha == 0 {
            continue;
        }
        for channel in &mut pixel[..3] {
            let straight = u16::from(*channel) * 255 / alpha;
            *channel = u8::try_from(straight).unwrap_or(u8::MAX);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        FIRST_ID, GCS_VERBW, ShellItem, ShellMenu, ShellRow, changes_disk,
        command_string, label, load, removes, same_rows, straighten, tidy,
    };

    fn row(name: &str) -> ShellItem {
        ShellItem::Row(ShellRow {
            id: FIRST_ID,
            label: name.to_string(),
            enabled: true,
            checked: false,
            default: false,
            icon: None,
            children: None,
        })
    }

    fn shape(items: &[ShellItem]) -> String {
        items
            .iter()
            .map(|item| match item {
                ShellItem::Separator => "-".to_string(),
                ShellItem::Row(row) => row.label.clone(),
            })
            .collect()
    }

    #[test]
    fn only_verbs_that_look_skip_the_refresh() {
        assert!(!changes_disk("properties"));
        assert!(!changes_disk("CopyAsPath"));
        assert!(changes_disk("rename"));
        assert!(changes_disk("paste"));
        assert!(changes_disk(""));
    }

    #[test]
    fn access_keys_and_key_hints_are_dropped() {
        assert_eq!(label("&Open"), "Open");
        assert_eq!(label("Save && &Quit"), "Save & Quit");
        assert_eq!(label("Trailing&"), "Trailing");
        assert_eq!(label("Cu&t\tCtrl+X"), "Cut");
    }

    #[test]
    fn a_read_that_found_more_is_not_the_same() {
        let send_to = |children: Vec<ShellItem>| {
            let ShellItem::Row(row) = row("Send to") else {
                unreachable!()
            };
            ShellItem::Row(ShellRow {
                children: Some(children.into()),
                ..row
            })
        };
        let early = [row("a"), send_to(vec![row("zip")])];
        let late = [row("a"), send_to(vec![row("zip"), row("mail")])];
        assert!(same_rows(&early, &early.clone()));
        assert!(!same_rows(&early, &late));
        assert!(!same_rows(&early, &[row("a")]));
        assert!(!same_rows(&[row("a")], &[ShellItem::Separator]));
    }

    #[test]
    fn separators_never_lead_trail_or_double() {
        let sep = || ShellItem::Separator;
        let items = vec![sep(), row("a"), sep(), sep(), row("b"), sep(), sep()];
        assert_eq!(shape(&tidy(items)), "a-b");
        assert_eq!(shape(&tidy(vec![sep(), sep()])), "");
        assert_eq!(shape(&tidy(Vec::new())), "");
    }

    #[test]
    fn premultiplied_pixels_come_out_straight() {
        let mut pixels = [64, 32, 0, 128, 10, 20, 30, 0];
        straighten(&mut pixels, true);
        assert_eq!(pixels, [127, 63, 0, 128, 10, 20, 30, 0]);
        let mut flat = [1, 2, 3, 0];
        straighten(&mut flat, true);
        assert_eq!(flat, [1, 2, 3, 255], "no alpha at all is opaque");
    }

    /// Explorer's own menu for a real file: Properties is always there,
    /// Delete and Cut never are. Reads whatever extensions this machine
    /// has, so it asserts nothing about them.
    #[test]
    fn explorer_offers_properties_but_never_delete_or_cut() {
        fn verbs(
            menu: &ShellMenu,
            items: &[ShellItem],
            into: &mut Vec<String>,
        ) {
            for item in items {
                let ShellItem::Row(row) = item else { continue };
                match &row.children {
                    Some(children) => verbs(menu, children, into),
                    None => into.extend(command_string(
                        &menu.menu,
                        row.id - FIRST_ID,
                        GCS_VERBW,
                    )),
                }
            }
        }
        let file = tempfile::NamedTempFile::new().expect("a temp file");
        // No owner window: the shell accepts none for a menu never shown.
        let menu = load(0, file.path()).expect("explorer's menu");
        let items = menu.rows();
        assert!(!items.is_empty());
        let mut found = Vec::new();
        verbs(&menu, &items, &mut found);
        assert!(
            found
                .iter()
                .any(|verb| verb.eq_ignore_ascii_case("properties")),
            "{found:?}"
        );
        assert!(!found.iter().any(|verb| removes(verb)), "{found:?}");
    }
}

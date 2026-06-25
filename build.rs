// Embed the requireAdministrator manifest (so the packaged exe self-elevates via
// UAC, replacing PyInstaller's --uac-admin) and the app icon.
//
// Only for release builds: a requireAdministrator manifest makes the binary
// un-launchable from a non-elevated shell, which would break `cargo test` and
// `cargo run` during development (where the runtime admin check guides the user
// instead). The packaged exe is built in release, so it still self-elevates.
//
// Best-effort: if no resource compiler is available the build still succeeds;
// only the embedded manifest/icon are skipped.
fn main() {
    #[cfg(windows)]
    {
        let release = std::env::var("PROFILE").as_deref() == Ok("release");
        if release {
            println!("cargo:rerun-if-changed=freegsm.rc");
            println!("cargo:rerun-if-changed=freegsm.manifest");
            println!("cargo:rerun-if-changed=freegsm.ico");
            let _ = embed_resource::compile("freegsm.rc", embed_resource::NONE);
        }
    }
}

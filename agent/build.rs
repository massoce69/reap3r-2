// build.rs — Embed Windows PE metadata & manifest to prevent AV false positives
// This gives the binary a proper publisher, description, version, and icon
// which signals to antivirus heuristics that it is a legitimate application.

#[cfg(windows)]
fn main() {
    let mut res = winresource::WindowsResource::new();

    // ── PE Version Information ────────────────────────────────
    // All fields must be filled — blank fields increase AV heuristic score
    res.set("ProductName", "MassVision Enterprise Agent");
    res.set("FileDescription", "MassVision IT Infrastructure Monitoring and Management Service");
    res.set("CompanyName", "MassVision SAS");
    res.set("LegalCopyright", "Copyright \u{00a9} 2024-2026 MassVision SAS. All rights reserved.");
    res.set("LegalTrademarks", "MassVision is a trademark of MassVision SAS");
    // Keep PE metadata consistent with the actual output binary name to reduce heuristic flags.
    res.set("OriginalFilename", "massvision-agent.exe");
    res.set("InternalName", "massvision-agent");
    res.set("FileVersion", env!("CARGO_PKG_VERSION"));
    res.set("ProductVersion", env!("CARGO_PKG_VERSION"));
    res.set("Comments", "Enterprise endpoint management and monitoring agent");

    // ── Windows Application Manifest ─────────────────────────
    // Declares proper UAC level, DPI awareness, and OS compatibility
    res.set_manifest_file("massvision.manifest");

    // ── Optional: Application Icon ───────────────────────────
    // Uncomment when massvision.ico is available:
    // res.set_icon("resources/massvision.ico");

    res.compile()
        .expect("Failed to compile Windows resources. Ensure rc.exe is available (install Windows SDK).");
}

#[cfg(not(windows))]
fn main() {
    // No resource embedding needed on Linux/macOS
}

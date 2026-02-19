fn main() {
    #[cfg(windows)]
    {
        let mut res = winres::WindowsResource::new();
        res.set("ProductName", "MASSVISION Reap3r Agent");
        res.set("FileDescription", "Enterprise remote monitoring and management agent");
        res.set("CompanyName", "MASSVISION");
        res.set("LegalCopyright", "Copyright (c) MASSVISION");
        if let Err(e) = res.compile() {
            panic!("Failed to compile Windows resources: {}", e);
        }
    }
}

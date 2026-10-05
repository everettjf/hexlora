fn main() {
    println!("cargo:rerun-if-changed=../../packaging/windows/Hexlora.ico");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }

    let icon = std::path::PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").unwrap())
        .join("../../packaging/windows/Hexlora.ico")
        .canonicalize()
        .expect("Hexlora Windows icon must exist");
    let resource =
        std::path::PathBuf::from(std::env::var_os("OUT_DIR").unwrap()).join("hexlora-icon.rc");
    let icon_path = icon.to_str().unwrap().replace('\\', "/");
    std::fs::write(&resource, format!("1 ICON \"{icon_path}\"\n")).unwrap();
    embed_resource::compile(&resource, embed_resource::NONE)
        .manifest_required()
        .expect("compile Hexlora Windows icon resource");
}

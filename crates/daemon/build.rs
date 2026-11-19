//! `omnitund --setup` and `--teardown` run inside the Windows installer,
//! whose custom actions may fail to start a program that loads user32
//! (STATUS_DLL_INIT_FAILED): setupapi and ole32, which load it, wait for
//! the network code that needs them.

fn main() {
    if std::env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("msvc") {
        for dll in ["setupapi.dll", "ole32.dll", "cfgmgr32.dll"] {
            println!("cargo:rustc-link-arg-bins=/DELAYLOAD:{dll}");
        }
        println!("cargo:rustc-link-arg-bins=delayimp.lib");
    }
}

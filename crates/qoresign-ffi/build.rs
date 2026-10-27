// SPDX-License-Identifier: Apache-2.0
//
// macOS: give the dynamic library a relative install name. The linker default
// is the absolute path of the build directory, which would ship inside the
// Kotlin and Python packages.

fn main() {
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("macos") {
        println!("cargo:rustc-cdylib-link-arg=-Wl,-install_name,@rpath/libqoresign_ffi.dylib");
    }
}

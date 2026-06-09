fn main() {
    let dir = std::env::current_dir().unwrap();
    println!("cargo:rustc-link-search=native={}", dir.display());
    println!("cargo:rustc-link-lib=static=proton");

    // Go runtime dependencies
    println!("cargo:rustc-link-lib=dylib=pthread");
    println!("cargo:rustc-link-lib=dylib=m");

    println!("cargo:rerun-if-changed=libproton.a");
    println!("cargo:rerun-if-changed=libproton.h");
}

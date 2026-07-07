use std::env;
use std::path::PathBuf;

fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let source_root = manifest_dir.join("../../third_party/mitm_anixops/mitm_anixops");
    let include_dir = source_root.join("include");
    let source_file = source_root.join("src/mitm_anixops.c");

    println!(
        "cargo:rerun-if-changed={}",
        include_dir.join("mitm_anixops.h").display()
    );
    println!("cargo:rerun-if-changed={}", source_file.display());

    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let target_env = env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default();
    let mingw_prefix = if target_os == "windows" {
        assert!(
            target_env == "gnu",
            "mitm-anixops-sys requires the x86_64-pc-windows-gnu target on Windows"
        );
        Some(find_mingw_prefix())
    } else {
        None
    };

    let mut build = cc::Build::new();
    build
        .file(&source_file)
        .include(&include_dir)
        .define("ANIXOPS_STATIC", None)
        .flag_if_supported("-std=c99")
        .warnings(true);

    if let Some(prefix) = mingw_prefix.as_ref() {
        build.include(prefix.join("include"));
        build.compiler(prefix.join("bin").join("gcc.exe"));
    }

    build.compile("mitm_anixops");

    if let Some(prefix) = mingw_prefix {
        println!(
            "cargo:rustc-link-search=native={}",
            prefix.join("lib").display()
        );
        println!("cargo:rustc-link-lib=static=systre");
        println!("cargo:rustc-link-lib=static=tre");
        println!("cargo:rustc-link-lib=static=intl");
        println!("cargo:rustc-link-lib=static=iconv");
    }
}

fn find_mingw_prefix() -> PathBuf {
    let mut candidates = Vec::new();
    if let Ok(prefix) = env::var("MINGW_PREFIX") {
        candidates.push(PathBuf::from(prefix));
    }
    if let Ok(location) = env::var("MSYS2_LOCATION") {
        let location = PathBuf::from(location);
        candidates.push(location.join("mingw64"));
        candidates.push(location.join("ucrt64"));
    }
    candidates.push(PathBuf::from("C:/msys64/mingw64"));
    candidates.push(PathBuf::from("C:/msys64/ucrt64"));

    let missing_regex_message =
        "unable to locate MinGW regex.h; install MSYS2 MINGW64 and mingw-w64-x86_64-libsystre";

    candidates
        .into_iter()
        .find(|candidate| candidate.join("include").join("regex.h").is_file())
        .expect(missing_regex_message)
}

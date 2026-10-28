use std::{
    env,
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

fn git(arguments: &[&str]) -> Option<String> {
    let output = Command::new("git").args(arguments).output().ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

fn main() {
    #[cfg(feature = "gui")]
    if env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        winresource::WindowsResource::new()
            .set_icon("assets/logo.ico")
            .compile()
            .expect("embedding the Windows application icon");
    }
    let inputs = [
        "build.rs",
        "Cargo.toml",
        "Cargo.lock",
        "src",
        "locales",
        "assets",
        "certs",
        "packaging",
    ];
    let compiler = Command::new(env::var_os("RUSTC").expect("RUSTC"))
        .arg("--version")
        .output()
        .expect("reading compiler version");
    assert!(compiler.status.success(), "reading compiler version failed");
    let compiler = String::from_utf8(compiler.stdout).expect("UTF-8 compiler version");
    println!("cargo:rustc-env=ZALIVKA_COMPILER={}", compiler.trim());
    println!(
        "cargo:rustc-env=ZALIVKA_TARGET={}",
        env::var("TARGET").expect("target")
    );
    println!(
        "cargo:rustc-env=ZALIVKA_PROFILE={}",
        env::var("PROFILE").expect("profile")
    );
    for input in inputs {
        println!("cargo:rerun-if-changed={input}");
    }
    // Source paths and HEAD cover source changes, staging and commits. Merely
    // refreshing Git's stat cache must not rebuild the executable.
    if let Some(path) = git(&["rev-parse", "--git-path", "HEAD"]) {
        println!("cargo:rerun-if-changed={path}");
    }
    if let Some(path) = git(&["rev-parse", "--git-path", "packed-refs"]) {
        println!("cargo:rerun-if-changed={path}");
    }
    if let Some(reference) = git(&["symbolic-ref", "-q", "HEAD"])
        && let Some(path) = git(&["rev-parse", "--git-path", &reference])
    {
        println!("cargo:rerun-if-changed={path}");
    }
    let revision = git(&["rev-parse", "--short=8", "HEAD"]).unwrap_or_else(|| "unknown".into());
    let mut status = vec!["status", "--porcelain", "--untracked-files=normal", "--"];
    status.extend(inputs);
    let dirty = git(&status).is_some_and(|status| !status.is_empty());
    let built_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("build time before Unix epoch")
        .as_nanos();
    let id = format!("{revision}{}.{built_at}", if dirty { ".dirty" } else { "" });
    println!("cargo:rustc-env=ZALIVKA_BUILT_AT={built_at}");
    println!(
        "cargo:rustc-env=ZALIVKA_VERSION={}+{id}",
        env::var("CARGO_PKG_VERSION").expect("package version")
    );
}

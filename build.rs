use sha2::{Digest, Sha256};
use std::{
    env, fs,
    path::Path,
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

fn hash_path(path: &Path, hash: &mut Sha256) {
    println!("cargo:rerun-if-changed={}", path.display());
    if path.is_dir() {
        let mut paths: Vec<_> = fs::read_dir(path)
            .expect("reading build inputs")
            .map(|entry| entry.expect("reading build input").path())
            .collect();
        paths.sort();
        for child in paths {
            hash_path(&child, hash);
        }
    } else {
        let name = path.to_str().expect("UTF-8 source path").replace('\\', "/");
        let data = fs::read(path).expect("reading build input");
        hash.update((name.len() as u64).to_le_bytes());
        hash.update(name.as_bytes());
        hash.update((data.len() as u64).to_le_bytes());
        hash.update(data);
    }
}

fn main() {
    let inputs = [
        "build.rs",
        "Cargo.toml",
        "Cargo.lock",
        "src",
        "certs",
        "packaging",
    ];
    let mut hash = Sha256::new();
    for key in ["TARGET", "PROFILE", "CARGO_ENCODED_RUSTFLAGS"] {
        hash.update(env::var(key).unwrap_or_default());
        hash.update([0]);
    }
    let mut features: Vec<_> = env::vars()
        .filter(|(key, _)| key.starts_with("CARGO_FEATURE_"))
        .collect();
    features.sort();
    for (key, value) in features {
        hash.update(key);
        hash.update(value);
        hash.update([0]);
    }
    let compiler = Command::new(env::var_os("RUSTC").expect("RUSTC"))
        .arg("--version")
        .output()
        .expect("reading compiler version");
    assert!(compiler.status.success(), "reading compiler version failed");
    let compiler = String::from_utf8(compiler.stdout).expect("UTF-8 compiler version");
    hash.update(compiler.as_bytes());
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
        hash_path(Path::new(input), &mut hash);
    }
    // Source paths and HEAD cover source changes, staging and commits. Merely
    // refreshing Git's stat cache must not rebuild the executable.
    if let Some(path) = git(&["rev-parse", "--git-path", "HEAD"]) {
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
    let fingerprint = format!("{:x}", hash.finalize());
    let built_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("build time before Unix epoch")
        .as_nanos();
    let id = format!(
        "{revision}{}.{}.{built_at}",
        if dirty { ".dirty" } else { "" },
        &fingerprint[..12]
    );
    println!("cargo:rustc-env=ZALIVKA_SOURCE_FINGERPRINT={fingerprint}");
    println!("cargo:rustc-env=ZALIVKA_BUILT_AT={built_at}");
    println!("cargo:rustc-env=ZALIVKA_BUILD_ID={id}");
    println!(
        "cargo:rustc-env=ZALIVKA_VERSION={}+{id}",
        env::var("CARGO_PKG_VERSION").expect("package version")
    );
}

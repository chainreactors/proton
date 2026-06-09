use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int, c_void};
use std::{env, process};

use serde::Deserialize;

extern "C" {
    fn ProtonVersion() -> *mut c_char;
    fn ProtonNewScanner(category: *const c_char) -> c_int;
    fn ProtonNewScannerFromPath(path: *const c_char) -> c_int;
    fn ProtonScanDir(handle: c_int, target: *const c_char) -> *mut c_char;
    fn ProtonScanData(
        handle: c_int,
        data: *const c_void,
        data_len: c_int,
        file_path: *const c_char,
    ) -> *mut c_char;
    fn ProtonFreeScanner(handle: c_int);
    fn ProtonFreeString(s: *mut c_char);
}

#[derive(Debug, Deserialize)]
struct Finding {
    #[serde(rename = "template-id")]
    template_id: String,
    #[serde(rename = "template-name")]
    template_name: String,
    severity: String,
    file: String,
    #[serde(default)]
    matches: serde_json::Value,
    #[serde(default)]
    extracts: serde_json::Value,
}

fn proton_version() -> String {
    unsafe {
        let ptr = ProtonVersion();
        let s = CStr::from_ptr(ptr).to_string_lossy().into_owned();
        ProtonFreeString(ptr);
        s
    }
}

fn proton_new_scanner(category: &str) -> Option<c_int> {
    let c_cat = CString::new(category).ok()?;
    let handle = unsafe { ProtonNewScanner(c_cat.as_ptr()) };
    if handle > 0 { Some(handle) } else { None }
}

fn proton_new_scanner_from_path(path: &str) -> Option<c_int> {
    let c_path = CString::new(path).ok()?;
    let handle = unsafe { ProtonNewScannerFromPath(c_path.as_ptr()) };
    if handle > 0 { Some(handle) } else { None }
}

fn proton_scan_dir(handle: c_int, target: &str) -> Vec<Finding> {
    let c_target = CString::new(target).unwrap();
    unsafe {
        let ptr = ProtonScanDir(handle, c_target.as_ptr());
        let json = CStr::from_ptr(ptr).to_string_lossy().into_owned();
        ProtonFreeString(ptr);
        serde_json::from_str(&json).unwrap_or_default()
    }
}

fn proton_scan_data(handle: c_int, data: &[u8], file_path: &str) -> Vec<Finding> {
    let c_path = CString::new(file_path).unwrap();
    unsafe {
        let ptr = ProtonScanData(
            handle,
            data.as_ptr() as *const c_void,
            data.len() as c_int,
            c_path.as_ptr(),
        );
        let json = CStr::from_ptr(ptr).to_string_lossy().into_owned();
        ProtonFreeString(ptr);
        serde_json::from_str(&json).unwrap_or_default()
    }
}

fn severity_color(sev: &str) -> &str {
    match sev {
        "critical" => "\x1b[1;31m",
        "high" => "\x1b[31m",
        "medium" => "\x1b[33m",
        "low" => "\x1b[36m",
        "info" => "\x1b[34m",
        _ => "",
    }
}

const RESET: &str = "\x1b[0m";
const GREEN: &str = "\x1b[32m";
const CYAN: &str = "\x1b[36m";

fn print_finding(f: &Finding) {
    let sev_c = severity_color(&f.severity);
    println!(
        "[{GREEN}{}{RESET}] [{sev_c}{}{RESET}] [{CYAN}{}{RESET}] {}",
        f.template_name, f.severity, f.template_id, f.file,
    );

    if let Some(matches) = f.matches.as_object() {
        for (name, events) in matches {
            if let Some(arr) = events.as_array() {
                for ev in arr {
                    let line = ev.get("line").and_then(|v| v.as_i64()).unwrap_or(0);
                    let mut val = ev
                        .get("value")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                    if val.len() > 200 {
                        val.truncate(200);
                        val.push_str("...");
                    }
                    println!("   [{name}] [L{line}] {val}");
                }
            }
        }
    }

    if let Some(arr) = f.extracts.as_array() {
        for ev in arr {
            let line = ev.get("line").and_then(|v| v.as_i64()).unwrap_or(0);
            let mut val = ev
                .get("value")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            if val.len() > 200 {
                val.truncate(200);
                val.push_str("...");
            }
            println!("   [L{line}] {val}");
        }
    }
}

fn print_usage() {
    eprintln!("Usage:");
    eprintln!("  proton-demo scan <target-dir> [category]     Scan directory (category: keys/spray/all, default: keys)");
    eprintln!("  proton-demo scan-tmpl <target-dir> <template-path>  Scan with custom template");
    eprintln!("  proton-demo scan-data <file-path>             Scan a single file via ScanData");
    eprintln!("  proton-demo version                           Print version");
}

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        print_usage();
        process::exit(1);
    }

    match args[1].as_str() {
        "version" => {
            println!("proton {}", proton_version());
        }

        "scan" => {
            if args.len() < 3 {
                eprintln!("Error: target directory required");
                print_usage();
                process::exit(1);
            }
            let target = &args[2];
            let category = args.get(3).map(|s| s.as_str()).unwrap_or("keys");

            println!("   ____                  __");
            println!("  / __/__  __ _____  ___/ /");
            println!(" / _// _ \\/ // / _ \\/ _  /");
            println!("/_/  \\___/\\_,_/_//_/\\_,_/  {} (rust-ffi)\n", proton_version());

            let handle = proton_new_scanner(category).unwrap_or_else(|| {
                eprintln!("Error: failed to create scanner with category '{category}'");
                process::exit(1);
            });

            println!("[*] Scanner created (category: {category})");
            println!("[*] Scanning: {target}\n");

            let findings = proton_scan_dir(handle, target);

            for f in &findings {
                print_finding(f);
            }

            println!("\n{}", "─".repeat(60));
            println!("Findings: {}", findings.len());

            let mut sev_count = std::collections::HashMap::new();
            for f in &findings {
                *sev_count.entry(f.severity.clone()).or_insert(0usize) += 1;
            }
            if !sev_count.is_empty() {
                let parts: Vec<String> = ["critical", "high", "medium", "low", "info"]
                    .iter()
                    .filter_map(|s| sev_count.get(*s).map(|c| format!("{s}={c}")))
                    .collect();
                println!("Severity: {}", parts.join(" "));
            }

            unsafe { ProtonFreeScanner(handle) };
        }

        "scan-tmpl" => {
            if args.len() < 4 {
                eprintln!("Error: target directory and template path required");
                print_usage();
                process::exit(1);
            }
            let target = &args[2];
            let tmpl_path = &args[3];

            let handle = proton_new_scanner_from_path(tmpl_path).unwrap_or_else(|| {
                eprintln!("Error: failed to load templates from '{tmpl_path}'");
                process::exit(1);
            });

            println!("[*] Templates loaded from: {tmpl_path}");
            println!("[*] Scanning: {target}\n");

            let findings = proton_scan_dir(handle, target);
            for f in &findings {
                print_finding(f);
            }
            println!("\nFindings: {}", findings.len());

            unsafe { ProtonFreeScanner(handle) };
        }

        "scan-data" => {
            if args.len() < 3 {
                eprintln!("Error: file path required");
                print_usage();
                process::exit(1);
            }
            let file_path = &args[2];
            let data = std::fs::read(file_path).unwrap_or_else(|e| {
                eprintln!("Error: cannot read '{file_path}': {e}");
                process::exit(1);
            });

            let handle = proton_new_scanner("keys").unwrap_or_else(|| {
                eprintln!("Error: failed to create scanner");
                process::exit(1);
            });

            println!("[*] Scanning file: {file_path} ({} bytes)\n", data.len());

            let findings = proton_scan_data(handle, &data, file_path);
            for f in &findings {
                print_finding(f);
            }
            println!("\nFindings: {}", findings.len());

            unsafe { ProtonFreeScanner(handle) };
        }

        _ => {
            eprintln!("Unknown command: {}", args[1]);
            print_usage();
            process::exit(1);
        }
    }
}

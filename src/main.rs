use std::time::{SystemTime, UNIX_EPOCH};
use std::{
    collections::{HashMap, HashSet},
    fmt::Debug,
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::{Context, Result};
use ariadne::{Label, Report, ReportKind};
use base64::{Engine as _, engine::general_purpose};
use clap::{Args, Parser};
use colour::{cyan, cyan_ln, green, green_ln, grey_ln, red, red_ln, yellow, yellow_ln};
use comfy_table::{ContentArrangement, Table, modifiers::UTF8_ROUND_CORNERS, presets::UTF8_FULL};
use dialoguer::Select;
use path_slash::PathExt as _;
use pathdiff::diff_paths;
use reqwest::blocking::{Client, Response};
use semver::Version;
use serde::{Deserialize, Serialize};
use spinners::Spinner;
use walkdir::DirEntry;

use everscan_verify::utils;
use everscan_verify::{ContractPath, get_paths, resolve_deps};
use shared_models::{
    CompileRequest, CompileResponse, CompilerInfo, LinkerInfo, Source, SourceType,
};

#[derive(Parser, Debug)]
#[clap(version)]
struct Cli {
    #[clap(subcommand)]
    subcommands: Subcommands,
    #[clap(long = "api-url", default_value = "https://verify.everscan.io")]
    api_url: String,
}

#[derive(Parser, Debug)]
#[allow(clippy::large_enum_variant)]
enum Subcommands {
    /// Verify a contract
    Verify(Verify),
    /// Get info about supported compiler versions
    Info(Info),
    /// Upload abi if you have api key
    Upload(Upload),
}

#[derive(Args, Debug)]
struct Upload {
    /// Path to the directory containing build artifacts (.abi.json, .tvc files)
    #[clap(short, long, value_name = "ARTIFACTS_DIR")]
    artifacts_dir: PathBuf,

    /// Path to the project source directory
    #[clap(short, long, value_name = "SOURCE_DIR")]
    source_dir: PathBuf,

    /// SPDX license identifier. More info: https://spdx.org/licenses/
    #[clap(short = 'l', long = "license")]
    license: String,

    /// URL to the audit report
    #[clap(short = 'a', long = "audit-url")]
    audit_url: Option<String>,

    /// Compiler commit hash (e.g. bbbbeca6e6f22f9a2cd3f30021ca83aac1a1428d). All versions could be obtained with `everscan-verify info`
    #[clap(long = "compiler-version")]
    compiler_version: String,

    /// Link to the project info
    #[clap(long = "project-link")]
    project_link: Option<String>,

    /// Linker version (e.g. 0.15.35) All versions could be obtained with `everscan-verify info`
    #[clap(long = "linker-version")]
    linker_version: String,

    /// Include path. Works like in solc
    #[clap(short = 'I', long = "include-path")]
    include_paths: Vec<PathBuf>,

    /// Sources will be uploaded to the server but data won't be stored in db
    #[clap(long = "anon-sources")]
    anonymous_sources: bool,

    /// API key for authentication
    #[clap(long = "api-key")]
    api_key: Option<String>,

    /// Secret for authentication
    #[clap(long)]
    secret: Option<String>,
}

#[derive(Args, Debug)]
struct Info;

#[derive(Args, Debug)]
struct Verify {
    #[clap(short = 'i')]
    /// Path to verified project root
    input: PathBuf,
    #[clap(short = 'o', default_value = ".")]
    /// Output directory
    output: PathBuf,
    /// Include path. Works like in solc
    #[clap(short = 'I', long = "include-path")]
    include_paths: Vec<PathBuf>,
    /// SPDX license identifier. More info: https://spdx.org/licenses/
    #[clap(short = 'l', long = "license")]
    license: String,
    #[clap(short = 'a', long = "audit-url")]
    audit_url: Option<String>,
    /// Compiler commit hash (e.g. bbbbeca6e6f22f9a2cd3f30021ca83aac1a1428d). All versions could be obtained with `tonscan-path-resolver info`
    #[clap(long = "compiler-version")]
    compiler_version: String,
    /// flags to pass to solc. e.g. --tvm-optimize
    #[clap(long = "cf")]
    compiler_flag: Vec<String>,
    /// Link to the project info
    #[clap(long = "project-link")]
    project_link: Option<String>,
    /// Linker version (e.g.  0.15.35) All versions could be obtained with `tonscan-path-resolver info`
    #[clap(long = "linker-version")]
    linker_version: String,
    /// contracts will be compiled, but not verified
    #[clap(long = "dry-run")]
    dry_run: bool,
    /// If set will ignore any resolve errors
    #[clap(long = "ignore-errors")]
    ignore_errors: bool,

    /// We try to verify all contracts in the project
    #[clap(long = "compile-all")]
    compile_all: bool,

    /// if set will skip all interactive questions
    #[clap(long = "assume-yes", short = 'y')]
    assume_yes: bool,

    /// Sources will be uploaded to the server for verification but data won't be stored in db.
    /// Anonymous contracts can be converted to normal via verification without this flag set
    #[clap(long = "anon-sources")]
    anonymous_sources: bool,

    #[clap(long = "api-key")]
    api_key: Option<String>,
    #[clap(long)]
    secret: Option<String>,
}

impl Verify {
    pub fn verify(&mut self, url: &str) -> Result<()> {
        let (supported_linkers, supported_compilers) = get_supported_versions(url)?;
        if spdx::license_id(&self.license).is_none() {
            anyhow::bail!("Invalid license {}", self.license);
        }
        let is_ok_compiler = supported_compilers
            .iter()
            .any(|(_, commit)| commit == &self.compiler_version);

        if !is_ok_compiler {
            red!("Compiler version");
            cyan!(" {} ", self.compiler_version);
            red_ln!("is not supported");
            let looking_similar = supported_compilers
                .iter()
                .filter(|(_, commit)| commit.starts_with(&self.compiler_version))
                .collect::<Vec<_>>();
            if !looking_similar.is_empty() {
                yellow_ln!("Looking for similar versions:");

                self.compiler_version = if looking_similar.len() == 1 {
                    yellow!("Compiler ");
                    cyan!(" {} ", looking_similar[0].1);
                    yellow_ln!("is looking similar. Using it.");
                    looking_similar[0].1.clone()
                } else {
                    let choice = Select::with_theme(&dialoguer::theme::ColorfulTheme::default())
                        .with_prompt("Select version")
                        .items(
                            &looking_similar
                                .iter()
                                .map(|(v, commit)| (format!("{commit} - {v}")))
                                .collect::<Vec<_>>(),
                        )
                        .default(0)
                        .interact()?;
                    looking_similar[choice].1.clone()
                };
            }
        }

        let linker_version =
            Version::parse(&self.linker_version).context("Invalid linker version")?;

        if !supported_linkers.contains(&linker_version) {
            red!("Linker version");
            cyan!(" {} ", self.linker_version);
            red_ln!("is not supported");

            yellow!("Tip: ");
            cyan_ln!("check `everscan-verify info` for supported versions");
            std::process::exit(1);
        }

        Ok(())
    }
}

/// # Algorithm:
/// 1. traverse all sol files
/// 2. for each sol file:
///     - get all paths
///     - canonicalize paths
/// 3. find common parent path
/// 4. Remap all paths to the common parent path
/// 6. Make this common parent path the root
/// # Project structure:
/// ```
/// /
/// /src for project sources
/// /external for external dependencies
/// ```
fn main() -> Result<()> {
    use crossterm::execute;
    use crossterm::style::{Attribute, SetAttribute};

    //prepare signal handling
    let attribute = SetAttribute(Attribute::Reset);
    let reset_stdout = move || {
        execute!(std::io::stdout(), attribute).expect("Failed to reset stdout");
        execute!(std::io::stderr(), attribute).expect("Failed to reset stderr");
    };

    #[cfg(not(target_os = "windows"))]
    {
        use signal_hook::{
            consts::{SIGINT, SIGTERM},
            iterator::Signals,
        };
        let mut signals = Signals::new([SIGTERM, SIGINT])?;
        std::thread::spawn(move || {
            signals.into_iter().next().expect("always returns Some");
            reset_stdout();
            std::process::exit(1);
        });
    }

    let args = Cli::parse();
    let res = match args.subcommands {
        Subcommands::Verify(v) => handle_verify(v, args.api_url),
        Subcommands::Info(_) => handle_info(args.api_url),
        Subcommands::Upload(u) => handle_upload(u, args.api_url),
    };
    reset_stdout();

    res
}

fn handle_upload(u: Upload, api_url: String) -> Result<()> {
    #[derive(Serialize)]
    pub struct UploadPayload {
        pub abi: serde_json::Value,
        pub contract_name: String,
        pub project_link: Option<String>,
        pub sources: serde_json::Value,
        pub tvc: String,
        pub code_hash: String,
        pub compiler_version: String,
        pub linker_version: String,
        pub license: String,
        pub audit_url: Option<String>,
        pub anonymous_sources: bool,
    }

    // Get credentials
    let (api_key, secret) = utils::get_credentials(u.api_key, u.secret);

    // Validate input paths
    let artifacts_dir = u.artifacts_dir.canonicalize().with_context(|| {
        format!(
            "Failed to find artifacts directory: {}",
            u.artifacts_dir.display()
        )
    })?;

    let source_dir = u.source_dir.canonicalize().with_context(|| {
        format!(
            "Failed to find source directory: {}",
            u.source_dir.display()
        )
    })?;

    if !artifacts_dir.is_dir() {
        anyhow::bail!(
            "Artifacts path is not a directory: {}",
            artifacts_dir.display()
        );
    }

    if !source_dir.is_dir() {
        anyhow::bail!("Source path is not a directory: {}", source_dir.display());
    }

    // Discover artifacts
    println!("Discovering artifacts in {}", artifacts_dir.display());

    // Find all .abi.json files
    let json_files: Vec<PathBuf> = walkdir::WalkDir::new(&artifacts_dir)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| {
            let path = e.path();
            path.is_file()
                && path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .map(|s| s.ends_with(".abi.json"))
                    .unwrap_or(false)
        })
        .map(|e| e.path().to_path_buf())
        .collect();

    if json_files.is_empty() {
        anyhow::bail!("No .abi.json files found in {}", artifacts_dir.display());
    }

    println!("Found {} .abi.json files", json_files.len());

    // Resolve sources
    println!("Resolving source files from {}", source_dir.display());
    let sources = resolve_sources(&source_dir, &u.include_paths, false)
        .with_context(|| "Failed to resolve source files")?;

    println!("Found {} source files", sources.len());

    let client = default_client()?;

    let mut success_count = 0;
    let mut already_exists_count = 0;
    let mut failed_count = 0;

    // Process each artifact
    for abi_path in &json_files {
        // Get contract base name
        let contract_base = match utils::file_prefix(abi_path) {
            Some(p) => p.to_string_lossy().to_string(),
            None => {
                eprintln!(
                    "Failed to get contract base name for {}",
                    abi_path.display()
                );
                failed_count += 1;
                continue;
            }
        };

        // Find corresponding .tvc file
        let tvc_path = abi_path.with_file_name(format!("{}.tvc", contract_base));
        if !tvc_path.exists() {
            println!(
                "Missing TVC file for {}: {}",
                contract_base,
                tvc_path.display()
            );
            failed_count += 1;
            continue;
        }

        println!("Processing contract: {}", contract_base);

        // Find matching source file
        let matched_sources: Vec<&Source> = sources
            .iter()
            .filter_map(|s| {
                utils::file_prefix(&s.path)
                    .map(|prefix| (prefix.to_string_lossy() == contract_base, s))
                    .filter(|(matches, _)| *matches)
                    .map(|(_, s)| s)
            })
            .collect();

        if matched_sources.is_empty() {
            println!("No matching source file found for {}", contract_base);
            failed_count += 1;
            continue;
        }

        if matched_sources.len() > 1 {
            println!(
                "Multiple matching source files found for {}:",
                contract_base
            );
            for source in &matched_sources {
                println!("  {}", source.path.display());
            }
            println!("Using the first match");
        }

        let source = matched_sources[0];

        // Read artifacts
        let abi = match std::fs::read_to_string(abi_path) {
            Ok(content) => content,
            Err(e) => {
                eprintln!("Failed to read ABI file {}: {}", abi_path.display(), e);
                failed_count += 1;
                continue;
            }
        };

        let abi_value = match serde_json::from_str::<serde_json::Value>(&abi) {
            Ok(value) => value,
            Err(e) => {
                eprintln!("Failed to parse ABI JSON {}: {}", abi_path.display(), e);
                failed_count += 1;
                continue;
            }
        };

        let tvc = match std::fs::read(&tvc_path) {
            Ok(content) => content,
            Err(e) => {
                eprintln!("Failed to read TVC file {}: {}", tvc_path.display(), e);
                failed_count += 1;
                continue;
            }
        };

        // Resolve dependencies
        let source_path = source.path.clone();
        let deps = resolve_deps(source_path.clone(), &u.include_paths);

        // Prepare sources payload
        let sources_payload: Vec<Source> = deps
            .into_iter()
            .map(|path| {
                let content = std::fs::read_to_string(&path)
                    .unwrap_or_else(|_| format!("Failed to read source file: {}", path.display()));

                Source {
                    content,
                    source_type: if path == source_path {
                        SourceType::VerifyTarget
                    } else {
                        SourceType::Dependency
                    },
                    path,
                }
            })
            .collect();

        let sources_value =
            serde_json::to_value(&sources_payload).expect("Failed to serialize sources");

        // Construct upload payload
        let payload = UploadPayload {
            abi: abi_value,
            contract_name: source.path.to_string_lossy().to_string(),
            project_link: u.project_link.clone(),
            sources: sources_value,
            tvc: general_purpose::STANDARD.encode(tvc),
            code_hash: "".to_string(), // Server will calculate this
            compiler_version: u.compiler_version.clone(),
            linker_version: u.linker_version.clone(),
            license: u.license.clone(),
            audit_url: u.audit_url.clone(),
            anonymous_sources: u.anonymous_sources,
        };

        println!("Uploading contract: {}", contract_base);

        let body_bytes = serde_json::to_string(&payload)?;
        let hash = hex::encode(hmac_sha256::Hash::hash(body_bytes.as_bytes()));
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis() as u64;

        let concat = format!("{}{}{}", &api_key, &hash, nonce);
        let signature = hex::encode(hmac_sha256::HMAC::mac(concat.as_bytes(), secret.as_bytes()));

        let response = client
            .put(format!("{}/authorized/upload", api_url))
            .header("X-API-KEY", &api_key)
            .header("signature", &signature)
            .header("nonce", &nonce.to_string())
            .json(&payload)
            .send();

        match response {
            Ok(r) => {
                let status = r.status();
                if status.is_success() {
                    let code_hash = r.text().unwrap_or_default();
                    println!(
                        "✅ Successfully uploaded {}. Code hash: {}",
                        contract_base, code_hash
                    );
                    success_count += 1;
                } else if status.as_u16() == 409 {
                    println!("⚠️  Contract {} already exists", contract_base);
                    already_exists_count += 1;
                } else {
                    let error_text = r.text().unwrap_or_default();
                    println!(
                        "❌ Failed to upload {}: HTTP {} - {}",
                        contract_base, status, error_text
                    );
                    failed_count += 1;
                }
            }
            Err(e) => {
                if e.is_connect() {
                    anyhow::bail!("Failed to connect to server: {}", e);
                }

                match e.status() {
                    Some(status) => {
                        if status.as_u16() == 409 {
                            println!("⚠️  Contract {} already exists", contract_base);
                            already_exists_count += 1;
                        } else {
                            println!("❌ Failed to upload {}: {} - {}", contract_base, status, e);
                            failed_count += 1;
                        }
                    }
                    None => {
                        println!("❌ Failed to upload {}: {}", contract_base, e);
                        failed_count += 1;
                    }
                }
            }
        }
    }

    // Print summary
    println!("\nUpload Summary:");
    println!("  ✅ Successfully uploaded: {}", success_count);
    println!("  ⚠️  Already existed: {}", already_exists_count);
    println!("  ❌ Failed: {}", failed_count);
    println!("  📊 Total processed: {}", json_files.len());

    Ok(())
}

fn handle_verify(mut args: Verify, api_url: String) -> Result<()> {
    args.verify(&api_url)?;

    let (api_key, secret) = utils::get_credentials(args.api_key, args.secret);

    let mut contracts = resolve_sources(&args.input, &args.include_paths, args.ignore_errors)?;

    args.output
        .parent()
        .as_ref()
        .and_then(|x| std::fs::create_dir_all(x).ok());
    let outfile_path = args.output.join("sources.json");
    let outfile = std::fs::File::create(&outfile_path).with_context(|| {
        format!(
            "Failed to create output file. Path: {}",
            outfile_path.display()
        )
    })?;

    let filtered_contracts = contracts
        .iter()
        .filter(|x| !x.path.starts_with("/app/contracts/external"))
        .cloned()
        .collect::<Vec<_>>();

    let idxs = if args.compile_all {
        (0..filtered_contracts.len()).collect::<Vec<_>>()
    } else {
        dialoguer::MultiSelect::with_theme(&dialoguer::theme::ColorfulTheme::default())
            .with_prompt("Select contracts to verify with space")
            .items(&filtered_contracts)
            .interact()
            .with_context(|| "Failed to select contracts")?
    };

    if idxs.is_empty() {
        yellow_ln!("No contracts selected");
        return Ok(());
    }

    let checked: HashSet<_> = idxs
        .into_iter()
        .map(|x| filtered_contracts[x].path.clone())
        .collect();

    for contract in contracts.iter_mut() {
        contract.source_type = if args.dry_run && checked.contains(&contract.path) {
            SourceType::CompileTarget
        } else {
            SourceType::VerifyTarget
        };
    }
    let compile_request = CompileRequest {
        compiler: CompilerInfo {
            version: args.compiler_version,
            flags: args.compiler_flag,
        },
        license: args.license,
        audit_url: args.audit_url,
        sources: contracts
            .into_iter()
            .map(|mut x| {
                x.path = PathBuf::from(x.path.to_slash_lossy().as_ref());
                x
            })
            .collect(),
        project_link: args.project_link,
        linker: LinkerInfo {
            version: args.linker_version,
        },
        anonymous_sources: args.anonymous_sources,
    };

    serde_json::to_writer_pretty(outfile, &compile_request)?;
    green_ln!("✅ All done");

    let submit = if !args.assume_yes {
        yellow_ln!("⚠️  Don't forget to check the output file before submission");
        cyan_ln!("File: {}", outfile_path.display());

        dialoguer::Confirm::with_theme(&dialoguer::theme::ColorfulTheme::default())
            .with_prompt("Do you want to submit this request to the verifier?")
            .interact()
            .with_context(|| "Failed to confirm")?
    } else {
        true
    };

    if submit {
        let resp = send_request(api_url, &api_key, &secret, &compile_request)?;

        if resp.status().is_success() {
            let text = resp.text().context("Failed to get server response")?;

            let json = serde_json::from_str(&text).context("Invalid server answer")?;
            render_markdown(json, checked)?;
            std::fs::remove_file(outfile_path)?;
        } else {
            red_ln!("❌ Failed to send request: {:?} ", resp.status());
            let text = resp.text().context("Failed to get server response")?;
            red_ln!("Response: {}", text);
        }
    } else {
        yellow_ln!("Verification request was not submitted")
    }

    Ok(())
}

fn send_request(
    api_url: String,
    api_key: &str,
    secret: &str,
    compile_request: &CompileRequest,
) -> Result<Response> {
    let client = default_client()?;

    let mut spinner = Spinner::with_timer(
        spinners::Spinners::TimeTravel,
        "Waiting for verification result...".to_string(),
    );

    let body_bytes = serde_json::to_string(&compile_request)?;
    let hash = hex::encode(hmac_sha256::Hash::hash(body_bytes.as_bytes()));
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;

    let concat = format!("{}{}{}", &api_key, &hash, nonce);
    let signature = hex::encode(hmac_sha256::HMAC::mac(concat.as_bytes(), secret.as_bytes()));

    let url = api_url + "/authorized/compile";

    let resp = client
        .post(url)
        .header("X-API-KEY", api_key)
        .header("signature", signature)
        .header("nonce", &nonce.to_string())
        .json(&compile_request)
        .send()
        .context("Failed to send request")?;
    spinner.stop_with_newline();

    Ok(resp)
}

fn handle_info(api_url: String) -> Result<()> {
    let (supported_linkers, supported_compilers) = get_supported_versions(&api_url)?;

    cyan_ln!("\nSupported linkers:");
    for linker in supported_linkers {
        green_ln!("- {}", linker);
    }

    cyan_ln!("\nSupported compilers");

    for (version, commit) in supported_compilers {
        green!("- {} ", version);
        cyan!("Commit: ");
        green_ln!("{}", commit);
    }

    Ok(())
}

type SupportedVersions = (Vec<Version>, Vec<(Version, String)>);

fn get_supported_versions(api_url: &str) -> Result<SupportedVersions> {
    let client = default_client()?;

    let supported_linkers: Vec<String> = client
        .get(format!("{}/supported/linker", api_url))
        .send()
        .context("Failed to get supported linkers")?
        .json()
        .context("Failed to router supported linkers")?;

    let mut supported_linkers = supported_linkers
        .into_iter()
        .map(|linker| Version::parse(&linker).expect("Failed to router linker version"))
        .collect::<Vec<Version>>();
    supported_linkers.sort();

    let supported_compilers: HashMap<String, String> = client
        .get(format!("{}/supported/solc", api_url))
        .send()
        .context("Failed to get supported compilers")?
        .json()
        .context("Failed to router supported compilers")?;

    let mut supported_compilers = supported_compilers
        .into_iter()
        .map(|(commit, version)| {
            let version = version
                .split("Version: ")
                .last()
                .unwrap()
                .split('+')
                .next()
                .unwrap();
            let version = Version::parse(version).expect("Failed to router compiler version");
            (version, commit)
        })
        .collect::<Vec<_>>();
    supported_compilers.sort_by(|a, b| a.0.cmp(&b.0));
    Ok((supported_linkers, supported_compilers))
}

fn resolve_sources(
    input: &Path,
    include_paths: &[PathBuf],
    ignore_errors: bool,
) -> Result<Vec<Source>> {
    let project_root = input.canonicalize().context("Bad project root")?;

    let includes = include_paths
        .iter()
        .map(|x| {
            x.canonicalize()
                .with_context(|| format!("Bad include path {}", x.display()))
        })
        .collect::<Result<Vec<_>>>()?;

    green_ln!("✨ Starting to resolve paths");
    let (contracts, lib_root) = extract_imports(&project_root, &includes)?;
    let mut failed = false;
    let mut contracts: Vec<_> = contracts
        .into_iter()
        // rewriting imports to updated
        .filter_map(
            |mut contract| match contract.remap(&lib_root, &project_root, &includes) {
                Err(e) => {
                    red!("❌ Failed to remap imports. ");
                    cyan!("Contract: {}", contract.path.display());
                    red_ln!(" Error: {:?}", e);
                    failed = true;
                    None
                }
                Ok(_) => Some(contract),
            },
        )
        .map(|x| x.into())
        .collect();

    if contracts.is_empty() {
        anyhow::bail!("No contracts processed");
    }

    if failed && !ignore_errors {
        red_ln!("❌ Failed to resolve paths.");
        grey_ln!("Tip: Run with --ignore-errors to ignore errors");
        return Err(anyhow::anyhow!("Failed to remap paths"));
    }

    contracts.sort_by(|a: &Source, b| a.path.cmp(&b.path));
    Ok(contracts)
}

fn default_client() -> Result<Client> {
    let client = Client::builder()
        .timeout(Duration::from_secs(300))
        .gzip(true)
        .build()
        .unwrap();

    Ok(client)
}

fn render_markdown(response: CompileResponse, checked_to_compile: HashSet<PathBuf>) -> Result<()> {
    let checked_to_compile: HashSet<_> = checked_to_compile
        .iter()
        .map(|x| x.to_string_lossy().to_string())
        .collect();

    let compiled = response.compiled;
    if !compiled.is_empty() {
        let mut table = Table::new();
        table
            .load_preset(UTF8_FULL)
            .apply_modifier(UTF8_ROUND_CORNERS)
            .set_content_arrangement(ContentArrangement::Dynamic);
        table.set_header(vec!["Contract path", "Code hash"]);

        green_ln!("✅ Verified contracts:");
        for contract in compiled {
            table.add_row(vec![
                contract.contract_name,
                contract.code_hash.expect("No code hash"),
            ]);
        }
        println!("{table}\n");
    }

    if response
        .failed_to_verify
        .iter()
        .filter(|(_, res)| !res.compiler_output.stderr.contains("no output requested."))
        .any(|x| checked_to_compile.contains(x.0))
    {
        yellow_ln!("⚠️  These contracts failed to compile:");

        for (path, result) in response
            .failed_to_verify
            .into_iter()
            .filter(|x| checked_to_compile.contains(&x.0))
            .filter(|(_, res)| !res.compiler_output.stderr.contains("no output requested."))
        {
            println!("Contract path: {path}");
            println!("Compiler stdout:");
            yellow_ln!("{}\n", result.compiler_output.stdout);
            println!("Compiler stderr:");
            yellow_ln!("{}\n", result.compiler_output.stderr);

            if let Some(out) = result.linker_output {
                println!("Linker stdout:");
                yellow_ln!("{}\n", out.stdout);
                println!("Linker stderr:");
                yellow_ln!("{}\n", out.stderr);
            }
        }
    }

    if !response.already_verified.is_empty() {
        let mut table = Table::new();
        table
            .load_preset(UTF8_FULL)
            .apply_modifier(UTF8_ROUND_CORNERS)
            .set_content_arrangement(ContentArrangement::Dynamic);
        table.set_header(vec!["Contract path", "Code hash"]);

        yellow_ln!("These contracts were already verified:");
        for (path, code_hash) in response.already_verified {
            table.add_row(vec![path, code_hash]);
        }
        println!("{table}");
    }

    Ok(())
}

fn extract_imports(
    project_root: &Path,
    includes: &[PathBuf],
) -> Result<(Vec<ContractInfo>, Option<PathBuf>)> {
    let mut contracts_list = Vec::new();

    let mut lib_roots = HashSet::new();
    let mut visited_contracts = HashSet::new();

    for file in walkdir::WalkDir::new(project_root)
        .into_iter()
        .filter_map(|x| x.ok())
        .filter(is_sol)
    {
        if let Err(e) = process_contract(
            file.path(),
            &mut visited_contracts,
            &mut lib_roots,
            &mut contracts_list,
            project_root,
            includes,
        ) {
            red_ln!("❌ Failed to process {}: {:?}", file.path().display(), e);
        }
    }

    let lib_roots = common_path_all(lib_roots);

    Ok((contracts_list, lib_roots))
}

fn process_contract(
    contract_path: &Path,
    visited_contracts: &mut HashSet<PathBuf>,
    lib_roots: &mut HashSet<PathBuf>,
    contracts_list: &mut Vec<ContractInfo>,
    project_root: &Path,
    includes: &[PathBuf],
) -> Result<()> {
    let contract_path = contract_path.canonicalize().with_context(|| {
        format!(
            "Failed canonicalization path for {}",
            contract_path.display()
        )
    })?;

    if visited_contracts.contains(&contract_path) {
        return Ok(());
    } else {
        visited_contracts.insert(contract_path.clone());
    }
    green!("🤹 Processing ");
    cyan_ln!("{}", contract_path.display());

    std::thread::sleep(Duration::from_millis(1));
    let content = match std::fs::read_to_string(&contract_path) {
        Ok(content) => content,
        Err(err) => {
            red_ln!(
                "❌ Failed to process {}: {:?}",
                contract_path.display(),
                err
            );
            return Ok(());
        }
    };

    let imports = get_paths(&content);
    let contract_dir = contract_path
        .parent()
        .with_context(|| format!("Failed getting parent dir for {}", contract_path.display()))?;
    let mut resolve_paths = vec![contract_dir.to_path_buf()];
    resolve_paths.extend(includes.iter().cloned());

    let imports = get_canonical_paths(imports, &resolve_paths, Some(&contract_path));
    for import in &imports {
        process_contract(
            &import.absolute_path,
            visited_contracts,
            lib_roots,
            contracts_list,
            project_root,
            includes,
        )
        .with_context(|| {
            format!(
                "Failed processing contract: {}",
                import.absolute_path.display()
            )
        })?;
    }
    let imports = ClassifiedImports::new(imports, project_root);

    if let Some(imports_root) =
        common_path_all(imports.outer_libs.iter().map(|x| x.absolute_path.as_path()))
    {
        lib_roots.insert(imports_root);
    }

    contracts_list.push(ContractInfo {
        path: contract_path,
        imports,
        content,
    });

    Ok(())
}

#[derive(Serialize, Deserialize, Debug)]
struct CompilerInput {
    path: PathBuf,
    content: String,
    verify: bool,
}

#[allow(clippy::from_over_into)]
impl Into<Source> for ContractInfo {
    fn into(self) -> Source {
        Source {
            path: self.path,
            content: self.content,
            source_type: SourceType::Dependency,
        }
    }
}

#[derive(Serialize, Deserialize)]
struct ContractInfo {
    path: PathBuf,
    imports: ClassifiedImports,
    content: String,
}

impl ContractInfo {
    fn default_paths() -> (PathBuf, PathBuf) {
        let root = PathBuf::from("/app/contracts/src");
        let lib = PathBuf::from("/app/contracts/external");
        (root, lib)
    }
    fn update_self_path(&mut self, lib_path: &Option<PathBuf>, project_root: &Path) -> Result<()> {
        let (root, lib) = Self::default_paths();

        self.path = match ClassifiedImports::classify_import(&self.path, project_root) {
            ImportKind::External => {
                let lib_path = lib_path.as_ref().context("No lib")?;
                let pat = self.path.strip_prefix(lib_path).with_context(|| {
                    format!(
                        "Failed stripping. Lib: {}. Self: {}",
                        lib_path.display(),
                        self.path.display(),
                    )
                })?;
                lib.join(pat)
            }
            ImportKind::Internal => {
                let pat = self
                    .path
                    .strip_prefix(project_root)
                    .context("Bad project root")?;
                root.join(pat)
            }
        };
        Ok(())
    }

    fn remap(
        &mut self,
        lib_path: &Option<PathBuf>,
        project_root: &Path,
        includes: &[PathBuf],
    ) -> Result<()> {
        let old_path = self.path.clone();
        self.update_self_path(lib_path, project_root)?;

        let mut resolve_paths = vec![old_path];
        resolve_paths.extend(includes.iter().cloned());

        let mut remaped_list = HashSet::new();

        'outer: loop {
            let imports = get_paths(&self.content);
            let imports = get_canonical_paths(imports, &resolve_paths, None);

            for import in imports {
                if remaped_list.contains(&import.old_path) {
                    continue;
                }
                let import_path = import.absolute_path;
                let import_path = update_abs_path(&import_path, lib_path, project_root)
                    .context("Failed updating import")?;
                let new_path = get_relative_path(&self.path, &import_path)?;
                let new_path = new_path.to_slash().context("Failed to convert path")?;

                self.content
                    .replace_range(import.start..import.end, &new_path);

                let new_path = PathBuf::from(new_path.as_ref());
                remaped_list.insert(new_path);
                continue 'outer;
            }
            break;
        }

        Ok(())
    }
}

fn update_abs_path(
    import_path: &Path,
    lib_path: &Option<PathBuf>,
    project_root: &Path,
) -> Result<PathBuf> {
    let (root, lib) = ContractInfo::default_paths();

    match ClassifiedImports::classify_import(import_path, project_root) {
        ImportKind::External => {
            let lib_path = lib_path.as_ref().context("No lib")?;
            let import_path = import_path.strip_prefix(lib_path).with_context(|| {
                format!(
                    "Failed stripping. Lib: {}. Self: {}",
                    lib_path.display(),
                    import_path.display(),
                )
            })?;
            Ok(lib.join(import_path))
        }
        ImportKind::Internal => {
            let import_path = import_path.strip_prefix(project_root).with_context(|| {
                format!(
                    "Bad project root. Import: {}. Project root: {}",
                    import_path.display(),
                    project_root.display(),
                )
            })?;
            Ok(root.join(import_path))
        }
    }
}

impl Debug for ContractInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ContractInfo")
            .field("path", &self.path)
            .field("imports", &self.imports)
            .field("content", &"{...}")
            .finish()
    }
}

fn get_canonical_paths(
    paths: Vec<ContractPath>,
    resolve_paths: &[PathBuf],
    contract_path: Option<&Path>,
) -> Vec<Import> {
    paths
        .into_iter()
        .filter_map(|contract_import| {
            // todo: show error if nothing matches
            for pat in resolve_paths {
                let joined = pat.join(&contract_import.path);
                let canonical = joined.canonicalize().ok();
                if let Some(canonical) = canonical {
                    return Some(Import {
                        absolute_path: canonical,
                        old_path: contract_import.path,
                        start: contract_import.import_start,
                        end: contract_import.import_end,
                    });
                }
            }

            if let Some(contract_path) = contract_path {
                let path_str = contract_path.to_path_buf().display().to_string();
                let contract_content = std::fs::read_to_string(contract_path).unwrap();
                let sources = [(path_str.clone(), contract_content)];
                let sources = ariadne::sources(sources);
                let tested_paths = resolve_paths
                    .iter()
                    .map(|p| p.join(&contract_import.path))
                    .map(|x| x.display().to_string());

                let pad = " ".repeat(5);
                let tested_paths = tested_paths
                    .map(|s| format!("{pad}{s}"))
                    .collect::<Vec<String>>()
                    .join("\n");
                let note = format!("Checked paths:\n{}", tested_paths);
                Report::build(ReportKind::Error, path_str.clone(), 34)
                    .with_message("Failed to resolve import")
                    .with_label(
                        Label::new((
                            path_str,
                            contract_import.import_start..contract_import.import_end,
                        ))
                        .with_message("This import"),
                    )
                    .with_help("Maybe you forgot to set `--include-path`?")
                    .with_note(note)
                    .finish()
                    .eprint(sources)
                    .unwrap();
                std::process::exit(1);
            }

            None
        })
        .collect()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Import {
    absolute_path: PathBuf,
    old_path: PathBuf,
    start: usize,
    end: usize,
}

#[derive(Serialize, Deserialize, Debug, Default)]
struct ClassifiedImports {
    outer_libs: Vec<Import>,
    imports: Vec<Import>,
}

impl ClassifiedImports {
    fn new(imports: Vec<Import>, root_path: &Path) -> Self {
        let mut all_imports = Self::default();

        for import in imports {
            match Self::classify_import(&import.absolute_path, root_path) {
                ImportKind::External => {
                    all_imports.add_outer_lib(import);
                }
                ImportKind::Internal => {
                    all_imports.add_import(import);
                }
            }
        }
        all_imports
    }

    fn classify_import<P1, P2>(import: P1, root_path: P2) -> ImportKind
    where
        P1: AsRef<Path>,
        P2: AsRef<Path>,
    {
        for (import_component, root_component) in import
            .as_ref()
            .components()
            .zip(root_path.as_ref().components())
        {
            if import_component != root_component {
                return ImportKind::External;
            }
        }
        ImportKind::Internal
    }

    fn add_import(&mut self, import: Import) {
        self.imports.push(import);
    }

    fn add_outer_lib(&mut self, import: Import) {
        self.outer_libs.push(import);
    }
}

enum ImportKind {
    External,
    Internal,
}

fn is_sol(entry: &DirEntry) -> bool {
    if !entry.file_type().is_file() {
        return false;
    }
    let extension = entry
        .path()
        .extension()
        .unwrap_or_default()
        .to_string_lossy();
    extension == "sol" || extension == "tsol"
}

pub fn common_path_all<Pat>(paths: impl IntoIterator<Item = Pat>) -> Option<PathBuf>
where
    Pat: AsRef<Path>,
{
    let mut path_iter = paths.into_iter();
    let mut result = path_iter.next()?.as_ref().to_path_buf();
    for path in path_iter {
        if let Some(r) = common_path(result, path) {
            result = r;
        } else {
            return None;
        }
    }
    Some(result)
}

pub fn common_path<P, Q>(one: P, two: Q) -> Option<PathBuf>
where
    P: AsRef<Path>,
    Q: AsRef<Path>,
{
    let one = one.as_ref();
    let two = two.as_ref();
    let one = one.components();
    let two = two.components();
    let mut final_path = PathBuf::new();
    let mut found = false;
    let paths = one.zip(two);
    for (l, r) in paths {
        if l == r {
            final_path.push(l.as_os_str());
            found = true;
        } else {
            break;
        }
    }
    if found { Some(final_path) } else { None }
}

fn get_relative_path(contract_path: &Path, import_path: &Path) -> Result<PathBuf> {
    let relative_root_path =
        diff_paths(import_path, contract_path).context("Failed to diff paths")?;
    Ok(relative_root_path
        .strip_prefix("../")
        .context("Failed to strip prefix")?
        .to_owned())
}

#[cfg(test)]
mod test {
    use std::{
        collections::HashMap,
        path::{Path, PathBuf},
    };

    use shared_models::{
        CompileOutput, CompileResponse, CompileResult, LinkerOutput, VerificationResponse,
    };

    use crate::{
        ClassifiedImports, ImportKind, get_relative_path, render_markdown, update_abs_path,
    };

    #[test]
    fn classify() {
        let res = ClassifiedImports::classify_import(
            "/home/vladimir/dev/work/token-contracts/contracts/TokenRoot.sol",
            "/home/vladimir/dev/work/token-contracts/contracts/",
        );
        assert!(matches!(res, ImportKind::Internal));
    }

    #[test]
    fn test_path() {
        let import = PathBuf::from("/app/contracts/src/libraries/TokenMsgFlag.sol");
        let contract = PathBuf::from("/app/contracts/src/TokenWalletPlatform.sol");
        let rel = get_relative_path(&contract, &import).unwrap();
        assert_eq!(rel, PathBuf::from("libraries/TokenMsgFlag.sol"));
        println!("{:?}", rel);

        let import = PathBuf::from("/app/contracts/src/TokenMsgFlag.sol");
        let contract = PathBuf::from("/app/contracts/src/TokenWalletPlatform.sol");
        let rel = get_relative_path(&contract, &import).unwrap();
        assert_eq!(rel, PathBuf::from("TokenMsgFlag.sol"));
    }

    #[test]
    fn update_abs() {
        let path = PathBuf::from(
            "/home/user/dev/work/token-contracts/contracts/interfaces/IBurnPausableTokenRoot.sol",
        );
        let root_path = PathBuf::from("/home/user/dev/work/token-contracts/contracts/");

        let res = update_abs_path(&path, &None, &root_path).unwrap();
        assert_eq!(
            res,
            Path::new("/app/contracts/src/interfaces/IBurnPausableTokenRoot.sol")
        );
        println!("{:?}", res);
    }

    fn test_data() -> CompileResponse {
        CompileResponse {
            compiled: vec![VerificationResponse {
                contract_name: "TokenMsgFlag".to_string(),
                code_hash: Some(
                    "80d6c47c4a25543c9b397b71716f3fae1e2c5d247174c52e2c19bd896442b105".to_string(),
                ),
                tvc: Some("0x0".to_string()),
                success: true,
                dependencies_list: vec![],
            }],
            already_verified: HashMap::from([(
                "TestTest".to_owned(),
                "0xe430erio30ri3i".to_owned(),
            )]),
            failed_to_verify: HashMap::from([(
                "TestTest".to_owned(),
                CompileResult {
                    linker_output: Some(LinkerOutput {
                        stdout: "unlucky(".to_string(),
                        stderr: "u died".to_string(),
                        success: false,
                        tvc: None,
                        code_hash: None,
                    }),
                    compiler_output: CompileOutput {
                        stdout: "u dumb".to_string(),
                        stderr: "plz die".to_string(),
                        success: false,
                        abi: None,
                        code: None,
                        dependencies_list: vec![],
                    },
                },
            )]),
        }
    }

    #[test]
    fn display() {
        render_markdown(test_data(), Default::default()).unwrap();
    }
}

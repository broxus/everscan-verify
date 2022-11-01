use std::{
    collections::{HashMap, HashSet},
    fmt::Debug,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use clap::{Args, Parser};
use comfy_table::{ContentArrangement, modifiers::UTF8_ROUND_CORNERS, presets::UTF8_FULL, Table};
use console::style;
use crossterm::style::Stylize;
use dialoguer::Select;
use pathdiff::diff_paths;
use semver::Version;
use serde::{Deserialize, Serialize};
use spinners::Spinner;
use ureq::{Agent, Error};
use walkdir::DirEntry;

use everscan_verify::{ContractPath, get_paths, resolve_deps};
use everscan_verify::utils;
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
    #[clap(long = "api-key")]
    api_key: Option<String>,
    #[clap(long)]
    secret: Option<String>,
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
    /// Path to the contracts directory
    #[clap(short, long)]
    build: PathBuf,

    #[clap(short, long)]
    project_root: PathBuf,

    /// SPDX license identifier. More info: https://spdx.org/licenses/
    #[clap(short = 'l', long = "license")]
    license: String,
    #[clap(short = 'a', long = "audit-url")]
    audit_url: Option<String>,
    /// Compiler commit hash (e.g. bbbbeca6e6f22f9a2cd3f30021ca83aac1a1428d). All versions could be obtained with `tonscan-path-resolver info`
    #[clap(long = "compiler-version")]
    compiler_version: String,
    /// Link to the project info
    #[clap(long = "project-link")]
    project_link: Option<String>,
    /// Linker version (e.g.  0.15.35) All versions could be obtained with `tonscan-path-resolver info`
    #[clap(long = "linker-version")]
    linker_version: String,
    /// Include path. Works like in solc
    #[clap(short = 'I', long = "include-path")]
    include_paths: Option<Vec<PathBuf>>,
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
}

/// # Algorythm:
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
    let args = Cli::parse();

    match args.subcommands {
        Subcommands::Verify(v) => handle_verify(v, args.api_url, args.api_key, args.secret),
        Subcommands::Info(_) => handle_info(args.api_url),
        Subcommands::Upload(u) => handle_upload(u, args.api_url, args.api_key, args.secret),
    }
}

fn handle_upload(
    u: Upload,
    api_url: String,
    api_key: Option<String>,
    secret: Option<String>,
) -> Result<()> {
    #[derive(Serialize)]
    pub struct DbContractInfo {
        pub abi: serde_json::Value,
        pub contract_name: String,
        pub project_link: Option<String>,
        pub sources: serde_json::Value,

        pub tvc: String,
        pub code_hash: String,

        pub compiler_version: String,
        pub linker_version: String,
    }

    let (api_key, secret) = utils::get_credentials(api_key, secret);

    let json_files = walkdir::WalkDir::new(&u.build)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter_map(|e| match e.path().extension() {
            Some(a) if a.to_string_lossy() == "json" => Some(e),
            _ => None,
        })
        .filter_map(|e| {
            e.path()
                .canonicalize()
                .ok()
                .map(|p| p.to_string_lossy().to_string())
        })
        .collect::<Vec<_>>();

    let idxs = dialoguer::MultiSelect::with_theme(&dialoguer::theme::ColorfulTheme::default())
        .with_prompt("Select contracts to verify with space")
        .items(&json_files)
        .interact()
        .with_context(|| "Failed to select contracts")?;

    let include_paths = u.include_paths.unwrap_or_default();
    let sources = resolve_sources(&u.project_root, &include_paths, false)?;
    // EverFarmPool.abi.json  EverFarmPool.base64  EverFarmPool.code  EverFarmPool.tvc

    let client = default_client()?;
    for idx in idxs {
        let abi_path = json_files[idx].clone();
        let tvc_path = abi_path.replace("abi.json", "tvc");
        let contract_base = if let Some(p) =utils::file_prefix(&abi_path) {
            p.to_string_lossy().to_string()
        } else {
            println!("Failed to get contract base name for {abi_path}");
            continue;
        };

        let abi = std::fs::read_to_string(&abi_path).context("Failed to read abi")?;
        let tvc = std::fs::read(&tvc_path)
            .with_context(|| format!("Failed to read tvc with path: {}", tvc_path))?;

        let matched_sources = sources
            .iter()
            .filter_map(|s| (utils::file_prefix(&s.path)?.to_string_lossy() == contract_base).then_some(s))
            .collect::<Vec<_>>();

        let matched_sources_list = matched_sources
            .iter()
            .map(|s| s.path.to_string_lossy())
            .collect::<Vec<_>>();
        let prompt = Select::with_theme(&dialoguer::theme::ColorfulTheme::default())
            .with_prompt(format!(
                "Select source which matches {} with space",
                contract_base
            ))
            .items(&matched_sources_list)
            .interact()
            .with_context(|| "Failed to select sources")?;
        let source = matched_sources[prompt];
        let source_path = u.project_root.join(
            source
                .path
                .strip_prefix("/app/contracts/src/")
                .context("Failed to get source path")?,
        );
        let sources: Vec<_> = resolve_deps(&source_path, &include_paths)
            .into_iter()
            .map(|x| Source {
                content: std::fs::read_to_string(&x).expect("Failed to read source"),
                source_type: if x == source.path {
                    SourceType::VerifyTarget
                } else {
                    SourceType::Dependency
                },
                path: x,
            })
            .collect();
        let sources = serde_json::to_value(&sources).expect("Failed to serialize sources");

        let req = DbContractInfo {
            abi: serde_json::from_str(&abi).context("Failed to parse abi")?,
            contract_name: source.path.to_string_lossy().to_string(),
            project_link: u.project_link.clone(),
            sources,
            tvc: base64::encode(&tvc),
            code_hash: "".to_string(),
            compiler_version: u.compiler_version.clone(),
            linker_version: u.linker_version.clone(),
        };

        println!(
            "{}",
            "Check that source and artifacts are the same before submission".yellow()
        );
        println!("Contract path: {}", source.path.to_string_lossy().magenta());
        println!("Abi path: {}", abi_path.clone().magenta());
        println!("Code path: {}", format!("{}.code", contract_base).magenta());
        println!("Tvc path: {}", format!("{}.tvc", contract_base).magenta());

        let res = dialoguer::Confirm::with_theme(&dialoguer::theme::ColorfulTheme::default())
            .with_prompt("Are you sure you want to submit this contract?")
            .interact()
            .with_context(|| "Failed to confirm contract")?;

        if !res {
            println!("{}", "Skipping contract".yellow());
            continue;
        }
        let mut spinner = Spinner::with_timer(
            spinners::Spinners::TimeTravel,
            "Submitting contract".to_string(),
        );

        let body_bytes = serde_json::to_string(&req)?;
        let hash = hex::encode(hmac_sha256::Hash::hash(body_bytes.as_bytes()));
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        let concat = format!("{}{}{}", &api_key, &hash, nonce);
        let signature = hex::encode(hmac_sha256::HMAC::mac(concat.as_bytes(), secret.as_bytes()));

        let response = client
            .put(&format!("{}/authorized/upload", api_url))
            .set("X-API-KEY", &api_key)
            .set("signature", &signature)
            .set("nonce", &nonce.to_string())
            .send_json(req);
        spinner.stop_with_newline();
        let response = match response {
            Ok(r) => r,
            Err(e) => {
                match e {
                    Error::Status(_, response) => {
                        if response.status() == 409 {
                            println!(
                                "{}",
                                style(format!("Contract {} already exists", contract_base.cyan()))
                                    .yellow()
                            )
                        } else {
                            println!(
                                "{}",
                                style(format!(
                                    "Failed to upload {}: {}",
                                    contract_base,
                                    response.into_string()?
                                ))
                                .red()
                            );
                        }
                    }
                    Error::Transport(e) => {
                        eprintln!("Failed to upload {}: {}", contract_base, e);
                        std::process::exit(1);
                    }
                }
                continue;
            }
        };

        if response.status() == 201 {
            println!(
                "{}",
                style(format!(
                    "Uploaded {}. Code hash: {}",
                    contract_base,
                    response.into_string()?
                ))
                .green()
            );
        }
    }

    Ok(())
}

fn handle_info(api_url: String) -> Result<()> {
    let client = default_client()?;

    let supported_linkers: Vec<String> = client
        .get(&format!("{}/supported/linker", api_url))
        .call()
        .context("Failed to get supported linkers")?
        .into_json()
        .context("Failed to router supported linkers")?;

    let mut supported_linkers = supported_linkers
        .into_iter()
        .map(|linker| Version::parse(&linker).expect("Failed to router linker version"))
        .collect::<Vec<Version>>();
    supported_linkers.sort();

    let supported_compilers: HashMap<String, String> = client
        .get(&format!("{}/supported/solc", api_url))
        .call()
        .context("Failed to get supported compilers")?
        .into_json()
        .context("Failed to router supported compilers")?;

    println!("{}", style("Supported linkers").cyan());
    for linker in supported_linkers {
        println!("- {}", style(linker).green());
    }

    println!("{}", style("Supported compilers").cyan());
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

    for (version, commit) in supported_compilers {
        println!(
            "- {} Commit: {}",
            style(version).magenta(),
            style(commit).green()
        );
    }

    Ok(())
}

fn handle_verify(
    args: Verify,
    api_url: String,
    api_key: Option<String>,
    secret: Option<String>,
) -> Result<()> {
    let (api_key, secret) = utils::get_credentials(api_key, secret);

    let mut contracts = resolve_sources(&args.input, &args.include_paths, args.ignore_errors)?;

    args.output
        .parent()
        .as_ref()
        .and_then(|x| std::fs::create_dir_all(&x).ok());
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

    let idxs = dialoguer::MultiSelect::with_theme(&dialoguer::theme::ColorfulTheme::default())
        .with_prompt("Select contracts to verify with space")
        .items(&filtered_contracts)
        .interact()
        .with_context(|| "Failed to select contracts")?;

    if idxs.is_empty() {
        println!("{}", style("No contracts selected").yellow());
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
        sources: contracts,
        project_link: args.project_link,
        linker: LinkerInfo {
            version: args.linker_version,
        },
    };

    serde_json::to_writer_pretty(outfile, &compile_request)?;
    println!(
        "✅ {} {}. {}",
        style("Saved to").green(),
        outfile_path.canonicalize()?.display(),
        style("Check it before submission").yellow()
    );
    let submit = dialoguer::Confirm::with_theme(&dialoguer::theme::ColorfulTheme::default())
        .with_prompt("Do you want to submit this request to the verifier?")
        .interact()
        .with_context(|| "Failed to confirm")?;

    if submit {
        let client = default_client()?;

        let mut spinner = spinners::Spinner::with_timer(
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

        let resp = client
            .post(&(api_url + "/authorized/compile"))
            .set("X-API-KEY", &api_key)
            .set("signature", &signature)
            .set("nonce", &nonce.to_string())
            .send_json(&compile_request)
            .context("Failed to send request")?;

        spinner.stop_with_newline();
        if resp.status() == 200 {
            let response =
                serde_json::from_str(&resp.into_string().context("Failed to router response")?)?;
            render_markdown(response, checked)?;
        } else {
            println!(
                "❌ {} {} Response: {}",
                style("Failed to send request").red(),
                style(resp.status()).red(),
                style(resp.into_string().context("Failed to router response")?).red()
            );
        }
    }

    Ok(())
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

    println!("✨ {}", style("Starting to resolve paths").yellow());
    let (contracts, lib_root) = extract_imports(&project_root, &includes)?;
    let mut failed = false;
    let mut contracts: Vec<_> = contracts
        .into_iter()
        // rewriting imports to updated
        .filter_map(
            |mut contract| match contract.remap(&lib_root, &project_root, &includes) {
                Err(e) => {
                    eprintln!(
                        "{} {}: {:?}",
                        style("Failed remaping").red(),
                        style(contract.path.display()).cyan(),
                        style(e).red()
                    );
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
        println!(
            "{}",
            style("Run with --ignore-errors to ignore errors").yellow()
        );
        return Err(anyhow::anyhow!("Failed to remap paths"));
    }

    contracts.sort_by(|a: &Source, b| a.path.cmp(&b.path));
    Ok(contracts)
}

fn default_client() -> Result<Agent> {
    let client = ureq::builder()
        .tls_connector(Arc::new(native_tls::TlsConnector::new()?))
        .timeout_read(Duration::from_secs(30))
        .timeout(Duration::from_secs(30))
        .build();
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

        println!("{}", style("Successfully verified").green());
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
        .any(|x| checked_to_compile.contains(x.0))
    {
        println!("{}", style("Failed to compile:").yellow());

        for (path, result) in response
            .failed_to_verify
            .into_iter()
            .filter(|x| checked_to_compile.contains(&x.0))
        {
            println!("Contract path: {path}");
            println!("Compiler stdout:");
            println!("{}\n", style(result.compiler_output.stdout).yellow());
            println!("Compiler stderr:");
            println!("{}\n", style(result.compiler_output.stderr).red());

            if let Some(out) = result.linker_output {
                println!("Linker stdout:");
                println!("{}\n", style(out.stdout).yellow());
                println!("Linker stderr:");
                println!("{}\n", style(out.stderr).red());
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

        println!("{}", style("Already verified:").yellow());
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
            eprintln!(
                "{}",
                style(format!(
                    "Failed to process {}: {:?}",
                    file.path().display(),
                    e
                ))
                .red()
            );
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
    println!(
        "🤹 Processing {}",
        style(contract_path.display().to_string()).cyan()
    );
    std::thread::sleep(std::time::Duration::from_millis(10));
    let content = match std::fs::read_to_string(&contract_path) {
        Ok(content) => content,
        Err(err) => {
            eprintln!("Failed reading {}: {:?}", contract_path.display(), err);
            return Ok(());
        }
    };

    let imports = get_paths(&content);
    let contract_dir = contract_path
        .parent()
        .with_context(|| format!("Failed getting parent dir for {}", contract_path.display()))?;
    let mut resolve_paths = vec![contract_dir.to_path_buf()];
    resolve_paths.extend(includes.iter().cloned());

    let imports = get_canonical_paths(imports, &resolve_paths, true);
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
            let imports = get_canonical_paths(imports, &resolve_paths, false);

            for import in imports {
                if remaped_list.contains(&import.old_path) {
                    continue;
                }
                let import_path = import.absolute_path;
                let import_path = update_abs_path(&import_path, lib_path, project_root)
                    .context("Failed updating import")?;
                let new_path = get_relative_path(&self.path, &import_path)?;

                self.content
                    .replace_range(import.start..import.end, &new_path.to_string_lossy());

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
    initial_resolve: bool,
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
            if initial_resolve {
                println!(
                    "{}: {}. {}",
                    style("Failed to resolve").red(),
                    style(contract_import.path.display()).cyan(),
                    style("Tip: Maybe you forgot to set `--include-path`?").yellow()
                );
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
    extension == "sol"
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
    if found {
        Some(final_path)
    } else {
        None
    }
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
        ClassifiedImports, get_relative_path, ImportKind, render_markdown, update_abs_path,
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

    // #[test]
    // fn md_generate() {
    //     let md = render_markdown(test_data()).unwrap();
    //     println!("{}", md);
    //     assert_eq!(md, include_str!("../test/output.md"));
    // }

    #[test]
    fn display() {
        render_markdown(test_data(),Default::default()).unwrap();
    }
}

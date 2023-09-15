use std::{
    collections::HashMap,
    fmt::{Display, Formatter},
    path::PathBuf,
};

use anyhow::Result;
use base64::{engine::general_purpose, Engine};
use serde::{de::Error, Deserialize, Deserializer, Serialize, Serializer};
use ton_block::Deserializable;

mod compiler_error;
mod place_error;
mod versions;

pub use compiler_error::CompileError;
pub use place_error::PlaceError;
pub use versions::Versions;

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct CompileServiceResponse {
    pub result: HashMap<String, CompileResult>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CompileResult {
    pub linker_output: Option<LinkerOutput>,
    pub compiler_output: CompileOutput,
}

impl CompileResult {
    pub fn is_empty(&self) -> bool {
        self.linker_output.is_none() && self.compiler_output.is_empty()
    }

    pub fn calculate_code_hash(&mut self) -> Result<()> {
        if let Some(ref mut linker_output) = self.linker_output {
            linker_output.calculate_code_hash()?;
        }

        Ok(())
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct LinkerOutput {
    pub stdout: String,
    pub stderr: String,
    pub success: bool,
    pub tvc: Option<String>,
    pub code_hash: Option<String>,
}

impl LinkerOutput {
    pub fn calculate_code_hash(&mut self) -> Result<()> {
        if let Some(ref tvc) = self.tvc {
            let tvc = ton_block::StateInit::construct_from_base64(tvc)?;
            self.code_hash = tvc
                .code
                .map(|x| x.repr_hash())
                .map(|x| general_purpose::STANDARD.encode(x.as_slice()));
        }

        Ok(())
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CompileOutput {
    pub stdout: String,
    pub stderr: String,
    pub success: bool,
    pub abi: Option<String>,
    pub code: Option<String>,
    pub dependencies_list: Vec<PathBuf>,
}

impl CompileOutput {
    pub fn is_empty(&self) -> bool {
        self.stdout.is_empty() && self.stderr.is_empty() && !self.success
    }
}

#[derive(Deserialize, Serialize, Default, Debug, Clone)]
pub struct CompileRequest {
    pub compiler: CompilerInfo,
    pub linker: LinkerInfo,
    pub sources: Vec<Source>,
    pub license: String,
    pub audit_url: Option<String>,
    pub project_link: Option<String>,
    #[serde(default)]
    pub anonymous_sources: bool,
}

#[derive(Deserialize, Serialize, Default, Debug, Clone)]
pub struct CompilerInfo {
    pub version: String,
    // #[serde(skip)]
    // pub compiler: Option<CompilerType>,
    pub flags: Vec<String>,
}

// #[derive(Deserialize)]
// pub enum CompilerType {
//     Solidity,
//     Cpp,
// }
//
// pub enum LinkerType {
//     TVM,
// }

#[derive(Deserialize, Serialize, Default, Debug, Clone)]
pub struct LinkerInfo {
    // pub ty: LinkerType,
    pub version: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Source {
    pub path: PathBuf,
    pub content: String,
    pub source_type: SourceType,
}

#[derive(Debug, Clone, Copy)]
pub enum SourceType {
    CompileTarget,
    VerifyTarget,
    Dependency,
}

impl<'de> Deserialize<'de> for SourceType {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        match s.to_lowercase().as_str() {
            "compiletarget" => Ok(SourceType::CompileTarget),
            "verifytarget" => Ok(SourceType::VerifyTarget),
            "dependency" => Ok(SourceType::Dependency),
            _ => Err(D::Error::custom(format!("Unknown source type: {}", s))),
        }
    }
}

impl Serialize for SourceType {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let str = match self {
            SourceType::CompileTarget => "CompileTarget",
            SourceType::VerifyTarget => "VerifyTarget",
            SourceType::Dependency => "Dependency",
        };
        serializer.serialize_str(str)
    }
}

impl SourceType {
    pub fn to_compile(&self) -> bool {
        !matches!(*self, SourceType::Dependency)
    }

    pub fn is_verify_target(&self) -> bool {
        matches!(*self, SourceType::VerifyTarget)
    }
}

impl Display for Source {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.path.display())
    }
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct VerificationResponse {
    pub contract_name: String,
    pub code_hash: Option<String>,
    pub tvc: Option<String>,
    pub success: bool,
    pub dependencies_list: Vec<Source>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct CompileResponse {
    pub compiled: Vec<VerificationResponse>,
    pub already_verified: HashMap<String, String>,
    pub failed_to_verify: HashMap<String, CompileResult>,
}

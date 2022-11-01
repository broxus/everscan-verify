use crate::place_error::PlaceError;
use crate::Versions;
use axum::http::StatusCode;

#[derive(Debug, thiserror::Error)]
pub enum CompileError {
    #[error("Bad compiler version: `{0}`")]
    BadCompilerVersion(String),
    #[error("Unsupported compiler version: `{0}`")]
    UnsupportedCompilerVersion(String),
    #[error("Unsupported linker version: `{0}`")]
    UnsupportedLinkerVersion(String),
    #[error(transparent)]
    ExecuteError(#[from] anyhow::Error),
    #[error("Internal error")]
    PlaceError(PlaceError),
    #[error("Internal error")]
    IoError(#[from] std::io::Error),
    #[error("Internal error")]
    DeserializeError(#[from] serde_json::Error),
}

impl CompileError {
    pub fn validate_compiler_version(
        version: &str,
        versions: &Versions,
    ) -> Result<(), CompileError> {
        if version.len() != 40 {
            return Err(CompileError::BadCompilerVersion(version.to_string()));
        }

        if !versions.check_compiler_version(version) {
            return Err(CompileError::UnsupportedCompilerVersion(
                version.to_string(),
            ));
        }

        Ok(())
    }

    pub fn check_linker_version(version: &str, versions: &Versions) -> Result<(), CompileError> {
        if !versions.check_linker_version(version) {
            return Err(CompileError::UnsupportedLinkerVersion(version.to_string()));
        }

        Ok(())
    }

    pub fn status_code(&self) -> StatusCode {
        match self {
            CompileError::BadCompilerVersion(_) => StatusCode::BAD_REQUEST,
            CompileError::UnsupportedCompilerVersion(_) => StatusCode::BAD_REQUEST,
            CompileError::UnsupportedLinkerVersion(_) => StatusCode::BAD_REQUEST,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

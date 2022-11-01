#[derive(thiserror::Error, Debug)]
pub enum PlaceError {
    #[error("Internal error: `{0}`")]
    Io(anyhow::Error),
}

use std::{
    collections::HashSet,
    path::{Path, PathBuf},
};

use pest::Parser;
use pest_derive::Parser;
pub mod utils;

#[derive(Parser)]
#[grammar = "import.pest"]
struct ImportParser;

macro_rules! ok_or_next {
    ($expr:expr) => {
        match $expr {
            Some(pair) => pair,
            None => {
                eprintln!("Logic error: {}", stringify!($expr));
                continue;
            }
        }
    };
}

/// returns a list of paths parsed from the import statement
pub fn get_paths(input: &str) -> Vec<ContractPath> {
    let mut paths = Vec::new();
    if let Ok(mut parsed) = ImportParser::parse(Rule::imports, input) {
        let tokens = parsed.next().unwrap().into_inner();
        for import in tokens {
            if import.as_rule() == Rule::import_expr {
                for token in import.into_inner() {
                    if token.as_rule() == Rule::path {
                        let path = ok_or_next!(token.into_inner().next()); // dquoted or quoted string
                        let span = path.as_span();
                        paths.push(ContractPath {
                            path: path.as_str().into(),
                            import_start: span.start(),
                            import_end: span.end(),
                        });
                    }
                }
            }
        }
    }
    paths
}

#[derive(Debug, Clone)]
pub struct ContractPath {
    pub path: PathBuf,
    pub import_start: usize,
    pub import_end: usize,
}

pub fn resolve_deps<P: AsRef<Path>>(contract_path: P, includes: &[PathBuf]) -> Vec<PathBuf> {
    fn resolve_deps_inner(
        visited: &mut HashSet<PathBuf>,
        contract: &str,
        contract_path: &Path,
        includes: &[PathBuf],
    ) {
        if !visited.insert(contract_path.to_path_buf()) {
            return;
        }
        let contract_dir = contract_path.parent().unwrap();
        let paths = get_paths(contract).into_iter().filter_map(|x| {
            let path = contract_dir.join(&x.path);
            // resolve the path relative to the contract file as direct dependency
            if let Ok(path) = path.canonicalize() {
                return Some(path);
            }

            // resolve the path relative to the includes as indirect dependency via include
            for include in includes {
                let path = include.join(&x.path);
                if let Ok(path) = path.canonicalize() {
                    return Some(path);
                }
            }
            eprintln!("Failed to resolve dependency: {}", x.path.display());
            None
        });
        for path in paths {
            let contract_data =
                std::fs::read_to_string(&path).expect("Checked with `canonicalize`");
            resolve_deps_inner(visited, &contract_data, &path, includes);
        }
    }

    let mut visited = HashSet::new();
    let contract_data = std::fs::read_to_string(contract_path.as_ref()).unwrap_or_else(|_| {
        format!(
            "Contract does not exist. Filename: {}",
            contract_path.as_ref().display()
        )
    });
    resolve_deps_inner(
        &mut visited,
        &contract_data,
        contract_path.as_ref(),
        includes,
    );
    visited.into_iter().collect()
}

#[cfg(test)]
mod test {
    use std::path::PathBuf;

    use pest::Parser;

    use super::ImportParser;
    use crate::{get_paths, resolve_deps, Rule};

    #[test]
    fn test_ok() {
        let input =
            r#"import "../../../node_modules/@broxus/contracts/contracts/libraries/MsgFlag.sol";"#;
        ImportParser::parse(Rule::import_expr, input).unwrap();
    }

    #[test]
    fn test_dens() {
        let input = r#"import {Version} from "versionable/contracts/utils/Structs.sol";"#;
        let paths = get_paths(input);
        assert_eq!(paths.len(), 1);
        let input =
            r#"import {BaseMaster, SlaveData} from "versionable/contracts/BaseMaster.sol";"#;
        let paths = get_paths(input);
        assert_eq!(paths.len(), 1);
        let input = r#"import {BaseSlave, Version, ErrorCodes as VersionableErrorCodes} from "versionable/contracts/BaseSlave.sol";";
        let paths = get_paths(input);
        assert_eq!(paths.len(), 1);
    }

    #[test]
    fn test_single_quote() {
        let input = r#"import 'IDaoRoot.sol';"#;
        ImportParser::parse(Rule::import_expr, input).unwrap();
    }

    #[test]
    fn test_comment() {
        let input = r#"import /*loooooooooooool*/'IDaoRoot.sol';"#;
        ImportParser::parse(Rule::import_expr, input).unwrap();
    }

    #[test]
    fn test_bad() {
        let input = r#"import ""foo";"#;
        let result = ImportParser::parse(Rule::import_expr, input).is_err();
        assert!(result);
    }

    #[test]
    fn test_complex() {
        let input = r#"import {PlatformTypes as StakingPlatformTypes} from "../staking/libraries/PlatformTypes.sol";import {PlatformTypes as StakingPlatformTypes} from "../staking/libraries/PlatformTypes.sol";"#;
        assert_eq!(get_paths(input).len(), 2);
    }

    #[test]
    fn test_rename() {
        let input = r#"import { PlatformTypes as StakingPlatformTypes } from "heh";"#;
        ImportParser::parse(Rule::import_expr, input).unwrap();
    }

    #[test]
    fn test_get_paths() {
        let input = include_str!("../test/dao_root.sol");
        let paths = super::get_paths(input);
        assert_eq!(paths.len(), 144);
    }

    #[test]
    fn test_token_wallet() {
        let input = include_str!("../test/TokenWallet.sol");
        let paths = super::get_paths(input);
        assert_eq!(paths.len(), 13);
    }

    #[test]
    fn test_single_quote_rename() {
        let input = r#"import {lol as kek} from '../../../node_modules/@broxus/contracts/contracts/libraries/MsgFlag.sol';"#;
        let paths = super::get_paths(input);
        assert_eq!(paths.len(), 1);
    }

    #[test]
    fn test() {
        let data = include_str!("../test/StakingRelay.sol");
        let paths = super::get_paths(data);
        assert_eq!(paths.len(), 3);
    }

    #[test]
    fn found_all_deps() {
        let paths = vec![PathBuf::from(
            "/home/odm3n/dev/work/bridge-contracts/node_modules",
        )];
        let res = resolve_deps(
            "/home/odm3n/dev/work/bridge-contracts/everscale/contracts/bridge/Bridge.sol",
            &paths,
        );
        dbg!(res);
    }
}

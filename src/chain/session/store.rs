// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! What a provider session keeps across a restart, in the node's own storage directory, so a
//! node finds its Pro again with no app having to say anything.

use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

#[cfg(feature = "cbf")]
use crate::chain::cbf::source_sync::SavedFilterHeader;
use crate::chain::session::machine::{normalise_node_id, DroppedPro, SessionMemory};

/// The file, in the host's storage directory. One per host: every wallet of a device shares
/// the host's chain source.
pub(crate) const SESSION_FILE_NAME: &str = "chain_session.json";

const SESSION_FILE_VERSION: u16 = 1;

/// The filter headers kept across a restart, in a file of their own: written once a block.
pub(crate) const FILTER_HEADERS_FILE_NAME: &str = "chain_filter_headers.json";

const FILTER_HEADERS_FILE_VERSION: u16 = 1;

#[derive(Debug, Serialize, Deserialize)]
struct FilterHeadersFile {
	version: u16,
	rows: Vec<SavedRow>,
}

#[derive(Debug, Serialize, Deserialize)]
struct SavedRow {
	height: u32,
	hash: String,
	filter_header: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct SessionFile {
	version: u16,
	#[serde(default)]
	candidates: Vec<String>,
	#[serde(default)]
	longest_known: Vec<String>,
	#[serde(default)]
	pinned: Option<String>,
	#[serde(default)]
	last_good: Option<String>,
	#[serde(default)]
	dropped: Vec<SavedDrop>,
	#[serde(default)]
	used_for_now: Option<String>,
	#[serde(default)]
	auto_source: Option<bool>,
}

/// A dropped Pro as saved. `conflict_with` was written by builds that dropped a Pro over a conflict
/// nobody could attribute: nothing was proven of those, and they are not read back.
#[derive(Debug, Serialize, Deserialize)]
struct SavedDrop {
	#[serde(flatten)]
	dropped: DroppedPro,
	#[serde(default, skip_serializing)]
	conflict_with: Option<String>,
}

/// Why what is on disk was not used.
#[derive(Debug)]
pub(crate) enum LoadProblem {
	Unreadable(io::Error),
	Corrupt(String),
}

impl std::fmt::Display for LoadProblem {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			Self::Unreadable(e) => write!(f, "unreadable: {}", e),
			Self::Corrupt(e) => write!(f, "corrupt: {}", e),
		}
	}
}

pub(crate) struct SessionStore {
	path: PathBuf,
	filter_headers_path: PathBuf,
}

impl SessionStore {
	pub(crate) fn in_dir(storage_dir: &str) -> Self {
		let dir = Path::new(storage_dir);
		Self {
			path: dir.join(SESSION_FILE_NAME),
			filter_headers_path: dir.join(FILTER_HEADERS_FILE_NAME),
		}
	}

	/// What was last saved. No file is the empty memory of a fresh node, not a problem.
	pub(crate) fn load(&self) -> Result<SessionMemory, LoadProblem> {
		let raw = match fs::read(&self.path) {
			Ok(raw) => raw,
			Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(SessionMemory::default()),
			Err(e) => return Err(LoadProblem::Unreadable(e)),
		};
		let file: SessionFile =
			serde_json::from_slice(&raw).map_err(|e| LoadProblem::Corrupt(e.to_string()))?;
		if file.version != SESSION_FILE_VERSION {
			return Err(LoadProblem::Corrupt(format!("version {}", file.version)));
		}
		let clean = |id: String| Some(normalise_node_id(&id)).filter(|id| !id.is_empty());
		Ok(SessionMemory {
			candidates: file.candidates.into_iter().filter_map(clean).collect(),
			longest_known: file.longest_known.into_iter().filter_map(clean).collect(),
			pinned: file.pinned.and_then(clean),
			last_good: file.last_good.and_then(clean),
			dropped: file
				.dropped
				.into_iter()
				.filter(|saved| saved.conflict_with.is_none())
				.map(|saved| saved.dropped)
				.collect(),
			used_for_now: file.used_for_now.and_then(clean),
			auto_source: file.auto_source,
		})
	}

	/// The filter headers an earlier run kept. Nothing on disk, or nothing readable, is an empty list:
	/// they are one more thing to compare against and nothing depends on them, and a file from a
	/// build that kept none simply is not there.
	#[cfg(feature = "cbf")]
	pub(crate) fn load_filter_headers(&self) -> Result<Vec<SavedFilterHeader>, LoadProblem> {
		let raw = match fs::read(&self.filter_headers_path) {
			Ok(raw) => raw,
			Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
			Err(e) => return Err(LoadProblem::Unreadable(e)),
		};
		let file: FilterHeadersFile =
			serde_json::from_slice(&raw).map_err(|e| LoadProblem::Corrupt(e.to_string()))?;
		if file.version != FILTER_HEADERS_FILE_VERSION {
			return Err(LoadProblem::Corrupt(format!("version {}", file.version)));
		}
		file.rows
			.into_iter()
			.map(|row| {
				let corrupt = |e: String| LoadProblem::Corrupt(e);
				Ok(SavedFilterHeader {
					height: row.height,
					hash: row.hash.parse().map_err(|e: bitcoin::hex::HexToArrayError| corrupt(e.to_string()))?,
					filter_header: row
						.filter_header
						.parse()
						.map_err(|e: bitcoin::hex::HexToArrayError| corrupt(e.to_string()))?,
				})
			})
			.collect()
	}

	/// Keeps `rows`, whole or not at all.
	#[cfg(feature = "cbf")]
	pub(crate) fn save_filter_headers(&self, rows: &[SavedFilterHeader]) -> io::Result<()> {
		let file = FilterHeadersFile {
			version: FILTER_HEADERS_FILE_VERSION,
			rows: rows
				.iter()
				.map(|row| SavedRow {
					height: row.height,
					hash: row.hash.to_string(),
					filter_header: row.filter_header.to_string(),
				})
				.collect(),
		};
		let body = serde_json::to_vec(&file).map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
		write_whole(&self.filter_headers_path, &body)
	}

	/// Saves `memory`, whole or not at all: a temporary file renamed over the last one.
	pub(crate) fn save(&self, memory: &SessionMemory) -> io::Result<()> {
		let file = SessionFile {
			version: SESSION_FILE_VERSION,
			candidates: memory.candidates.clone(),
			longest_known: memory.longest_known.clone(),
			pinned: memory.pinned.clone(),
			last_good: memory.last_good.clone(),
			dropped: memory
				.dropped
				.iter()
				.map(|dropped| SavedDrop { dropped: dropped.clone(), conflict_with: None })
				.collect(),
			used_for_now: memory.used_for_now.clone(),
			auto_source: memory.auto_source,
		};
		let body = serde_json::to_vec_pretty(&file).map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
		write_whole(&self.path, &body)
	}
}

fn write_whole(path: &Path, body: &[u8]) -> io::Result<()> {
	if let Some(dir) = path.parent() {
		fs::create_dir_all(dir)?;
	}
	let tmp = path.with_extension("json.tmp");
	let mut out = fs::File::create(&tmp)?;
	out.write_all(body)?;
	out.sync_all()?;
	drop(out);
	fs::rename(&tmp, path)?;
	// The rename is only durable once its directory is. Power cuts are what these files are kept for.
	if let Some(dir) = path.parent() {
		fs::File::open(dir)?.sync_all()?;
	}
	Ok(())
}

#[cfg(test)]
mod tests {
	use super::*;

	fn temp_dir(name: &str) -> PathBuf {
		let dir = std::env::temp_dir().join(format!(
			"ldk-node-session-store-{}-{}",
			name,
			std::process::id()
		));
		let _ = fs::remove_dir_all(&dir);
		dir
	}

	#[test]
	fn a_file_from_before_the_later_fields_reads_as_a_proof_and_no_choice_for_now() {
		let dir = temp_dir("older-conflict");
		fs::create_dir_all(&dir).unwrap();
		fs::write(
			dir.join(SESSION_FILE_NAME),
			r#"{"version":1,"dropped":[{"node_id":"02dd","reason":"x","height":7,"until":12345}]}"#,
		)
		.unwrap();
		let memory = SessionStore::in_dir(dir.to_str().unwrap()).load().unwrap();
		assert_eq!(memory.dropped[0].node_id, "02dd");
		assert_eq!(memory.dropped[0].at, 0);
		assert_eq!(memory.used_for_now, None);
		fs::remove_dir_all(&dir).unwrap();
	}

	/// A build before 11-05 dropped a witness over a conflict. Nothing was proven of it.
	#[test]
	fn a_pro_dropped_over_a_conflict_by_an_older_build_is_not_held_against_it() {
		let dir = temp_dir("older-conflict-drop");
		fs::create_dir_all(&dir).unwrap();
		fs::write(
			dir.join(SESSION_FILE_NAME),
			r#"{"version":1,"dropped":[
				{"node_id":"02dd","reason":"filter_header_conflict","height":7,"until":12345,"conflict_with":"02aa","at":1},
				{"node_id":"02ee","reason":"bad_header","height":8,"until":12345,"conflict_with":null,"at":1}
			]}"#,
		)
		.unwrap();
		let memory = SessionStore::in_dir(dir.to_str().unwrap()).load().unwrap();
		assert_eq!(memory.dropped.len(), 1);
		assert_eq!(memory.dropped[0].node_id, "02ee");
		fs::remove_dir_all(&dir).unwrap();
	}

	#[test]
	fn what_is_saved_comes_back_and_no_file_is_a_fresh_node() {
		let dir = temp_dir("round-trip");
		let store = SessionStore::in_dir(dir.to_str().unwrap());
		assert_eq!(store.load().unwrap(), SessionMemory::default());

		let memory = SessionMemory {
			longest_known: Vec::new(),
			dropped: vec![crate::chain::session::machine::DroppedPro {
				node_id: "02dd".into(),
				reason: "filter_lacks_block_output".into(),
				height: 7,
				until: 12345,
				at: 12000,
			}],
			candidates: vec!["02aa".into(), "02bb".into()],
			pinned: Some("02cc".into()),
			last_good: Some("02bb".into()),
			used_for_now: Some("02ee".into()),
			auto_source: Some(false),
		};
		store.save(&memory).unwrap();
		assert_eq!(store.load().unwrap(), memory);

		// Overwriting leaves nothing half-written behind.
		store.save(&SessionMemory::default()).unwrap();
		assert_eq!(store.load().unwrap(), SessionMemory::default());
		assert_eq!(fs::read_dir(&dir).unwrap().count(), 1);
		fs::remove_dir_all(&dir).unwrap();
	}

	#[test]
	fn a_file_from_before_dropped_pros_reads_as_none_dropped() {
		let dir = temp_dir("older-file");
		fs::create_dir_all(&dir).unwrap();
		fs::write(dir.join(SESSION_FILE_NAME), br#"{"version":1,"candidates":["02aa"]}"#).unwrap();
		let memory = SessionStore::in_dir(dir.to_str().unwrap()).load().unwrap();
		assert_eq!(memory.candidates, vec!["02aa".to_string()]);
		assert!(memory.dropped.is_empty());
		fs::remove_dir_all(&dir).unwrap();
	}

	#[test]
	fn a_corrupt_file_or_another_version_is_a_problem_to_report_not_a_crash() {
		let dir = temp_dir("corrupt");
		fs::create_dir_all(&dir).unwrap();
		let store = SessionStore::in_dir(dir.to_str().unwrap());
		fs::write(dir.join(SESSION_FILE_NAME), b"{ not json").unwrap();
		assert!(matches!(store.load(), Err(LoadProblem::Corrupt(_))));
		fs::write(dir.join(SESSION_FILE_NAME), br#"{"version": 99}"#).unwrap();
		assert!(matches!(store.load(), Err(LoadProblem::Corrupt(_))));
		fs::write(dir.join(SESSION_FILE_NAME), br#"{"version": 1, "last_good": " 02AA "}"#)
			.unwrap();
		assert_eq!(store.load().unwrap().last_good.as_deref(), Some("02aa"));
		fs::remove_dir_all(&dir).unwrap();
	}
}

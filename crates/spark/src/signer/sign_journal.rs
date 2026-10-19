//! Durable record of the one FROST share each nonce commitment has released.
//!
//! In this signer the nonces travel encrypted inside their commitment, so a
//! caller holding a commitment could ask for a signature under it twice. Two
//! shares under one nonce for different requests reveal the signing key share.
//! The journal binds each commitment to the first request it signs: the same
//! request gets the same share back (a retry after a crash), any other is
//! refused.

use std::fs::{self, File, OpenOptions};
use std::io::{ErrorKind, Write};
use std::path::PathBuf;

use bitcoin::hashes::{Hash, sha256};
use bitcoin::secp256k1::rand::{RngCore, thread_rng};
use frost_secp256k1_tr::round1::SigningCommitments;
use frost_secp256k1_tr::round2::SignatureShare;

use crate::signer::SignerError;

fn io(context: &str, e: std::io::Error) -> SignerError {
    SignerError::Generic(format!("sign journal: {context}: {e}"))
}

/// One `<id>.signed` record per commitment that signed: the request hash and
/// the share. A record is created with a hard link, which fails when it exists,
/// so of two concurrent signers exactly one publishes; the other's share is
/// dropped unreleased. A share is returned only after the directory is synced.
/// ponytail: records are never swept; add an age-keyed sweep if the directory
/// grows.
pub struct SignJournal {
    path: PathBuf,
}

impl SignJournal {
    /// Opens the journal in `dir`, removing temporary files a crash left.
    pub fn open(dir: impl Into<PathBuf>) -> Result<Self, SignerError> {
        let path = dir.into();
        fs::create_dir_all(&path).map_err(|e| io("create directory", e))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                .map_err(|e| io("restrict directory", e))?;
        }
        let journal = Self { path };
        journal.sweep()?;
        Ok(journal)
    }

    fn sweep(&self) -> Result<(), SignerError> {
        let mut removed = false;
        for entry in fs::read_dir(&self.path).map_err(|e| io("list directory", e))? {
            let path = entry.map_err(|e| io("list directory", e))?.path();
            if path.extension().is_some_and(|ext| ext == "tmp") {
                fs::remove_file(&path).map_err(|e| io("sweep", e))?;
                removed = true;
            }
        }
        if removed {
            self.sync_dir()?;
        }
        Ok(())
    }

    fn sync_dir(&self) -> Result<(), SignerError> {
        File::open(&self.path)
            .and_then(|dir| dir.sync_all())
            .map_err(|e| io("sync directory", e))
    }

    fn record_path(
        commitments: &SigningCommitments,
        dir: &std::path::Path,
    ) -> Result<PathBuf, SignerError> {
        let bytes = commitments
            .serialize()
            .map_err(|e| SignerError::SerializationError(e.to_string()))?;
        Ok(dir.join(format!("{}.signed", sha256::Hash::hash(&bytes))))
    }

    /// Produces the share for `request_hash` under `commitments` through `sign`,
    /// once. Errors with [`SignerError::UnknownNonceCommitment`] when the
    /// commitment already signed a different request.
    pub(crate) fn sign_with(
        &self,
        commitments: &SigningCommitments,
        request_hash: [u8; 32],
        sign: impl FnOnce() -> Result<SignatureShare, SignerError>,
    ) -> Result<SignatureShare, SignerError> {
        let record = Self::record_path(commitments, &self.path)?;
        if record.exists() {
            return self.released_share(&record, request_hash);
        }
        let share = sign()?;

        let mut bytes = request_hash.to_vec();
        bytes.extend_from_slice(&share.serialize());
        let tmp = self
            .path
            .join(format!("{:016x}.tmp", thread_rng().next_u64()));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&tmp).map_err(|e| io("create record", e))?;
        file.write_all(&bytes)
            .and_then(|()| file.sync_all())
            .map_err(|e| io("write record", e))?;
        let published = fs::hard_link(&tmp, &record);
        let _ = fs::remove_file(&tmp);
        match published {
            Ok(()) => {}
            // Another signer published first: answer from its record.
            Err(e) if e.kind() == ErrorKind::AlreadyExists => {
                return self.released_share(&record, request_hash);
            }
            Err(e) => return Err(io("publish record", e)),
        }
        // The record must be on disk before the share leaves: a share released
        // without it could be followed by a second, different one.
        self.sync_dir()?;
        Ok(share)
    }

    /// The share a commitment already released, if `request_hash` is the request
    /// it signed. Synced first: the record may have just been linked by a signer
    /// that has not synced yet.
    fn released_share(
        &self,
        record: &std::path::Path,
        request_hash: [u8; 32],
    ) -> Result<SignatureShare, SignerError> {
        let bytes = fs::read(record).map_err(|e| io("read record", e))?;
        let (hash, share) = bytes
            .split_at_checked(32)
            .ok_or_else(|| SignerError::Generic("sign journal: truncated record".to_string()))?;
        if hash != request_hash {
            return Err(SignerError::UnknownNonceCommitment);
        }
        self.sync_dir()?;
        SignatureShare::deserialize(share)
            .map_err(|e| SignerError::SerializationError(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::sync::Arc;

    use bitcoin::secp256k1::SecretKey;
    use bitcoin::secp256k1::rand::thread_rng;
    use frost_core::round1::Nonce;
    use frost_secp256k1_tr::round1::{SigningCommitments, SigningNonces};
    use frost_secp256k1_tr::round2::SignatureShare;

    use super::SignJournal;
    use crate::signer::SignerError;

    fn commitments() -> SigningCommitments {
        let mut rng = thread_rng();
        *SigningNonces::from_nonces(
            Nonce::deserialize(&SecretKey::new(&mut rng).secret_bytes()).unwrap(),
            Nonce::deserialize(&SecretKey::new(&mut rng).secret_bytes()).unwrap(),
        )
        .commitments()
    }

    fn temp_dir(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "spark-sign-journal-{name}-{}",
            SecretKey::new(&mut thread_rng()).display_secret()
        ))
    }

    /// A stand-in share that differs per call, so a cached answer is visible.
    fn fresh_share() -> Result<SignatureShare, SignerError> {
        Ok(SignatureShare::deserialize(&SecretKey::new(&mut thread_rng()).secret_bytes()).unwrap())
    }

    #[test]
    fn a_commitment_signs_one_request_and_refuses_another() {
        let journal = SignJournal::open(temp_dir("one")).unwrap();
        let c = commitments();
        journal.sign_with(&c, [1; 32], fresh_share).unwrap();
        assert!(matches!(
            journal.sign_with(&c, [2; 32], fresh_share),
            Err(SignerError::UnknownNonceCommitment)
        ));
    }

    #[test]
    fn a_retry_after_a_restart_gets_the_same_share() {
        let dir = temp_dir("retry");
        let c = commitments();
        let first = SignJournal::open(&dir)
            .unwrap()
            .sign_with(&c, [1; 32], fresh_share)
            .unwrap();
        let retried = SignJournal::open(&dir)
            .unwrap()
            .sign_with(&c, [1; 32], fresh_share)
            .unwrap();
        assert_eq!(first.serialize(), retried.serialize());
    }

    #[test]
    fn a_failed_signature_leaves_the_commitment_signable() {
        let journal = SignJournal::open(temp_dir("failed")).unwrap();
        let c = commitments();
        assert!(
            journal
                .sign_with(&c, [1; 32], || Err(SignerError::Generic("crash".into())))
                .is_err()
        );
        assert!(journal.sign_with(&c, [2; 32], fresh_share).is_ok());
    }

    #[test]
    fn concurrent_signers_release_one_share() {
        let journal = Arc::new(SignJournal::open(temp_dir("race")).unwrap());
        let c = commitments();
        let released = (0..8u8)
            .map(|request| {
                let journal = Arc::clone(&journal);
                std::thread::spawn(move || {
                    journal.sign_with(&c, [request; 32], fresh_share).is_ok()
                })
            })
            .collect::<Vec<_>>()
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .filter(|ok| *ok)
            .count();
        assert_eq!(released, 1);
    }

    #[test]
    fn opening_sweeps_temporary_files() {
        let dir = temp_dir("sweep");
        drop(SignJournal::open(&dir).unwrap());
        std::fs::write(dir.join("0000000000000000.tmp"), [0u8; 64]).unwrap();
        drop(SignJournal::open(&dir).unwrap());
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 0);
    }
}

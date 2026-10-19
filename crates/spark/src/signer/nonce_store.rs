use std::collections::VecDeque;
use std::sync::Mutex;

use frost_secp256k1_tr::round1::{SigningCommitments, SigningNonces};
use frost_secp256k1_tr::round2::SignatureShare;

use crate::signer::SignerError;

/// Most unconsumed nonces held before the oldest are evicted. An entry is only
/// left pending by a flow that commits and signs in separate calls, so this
/// sits far above steady-state use. Eviction fails the stale flow closed with
/// [`SignerError::UnknownNonceCommitment`].
const MAX_PENDING_NONCES: usize = 1024;

/// Single-use store of the FROST nonces a signer has issued.
///
/// Signing twice under one nonce leaks the signing share, so a nonce may be
/// signed with at most once. Nonces are held here rather than taken from the
/// caller, so a caller cannot choose them or present one twice.
///
/// Share one store across signers when the commit and the sign happen on
/// different instances. Nonces carry no key material, so sharing is safe even
/// between signers on different masters.
#[derive(Default)]
pub struct NonceStore {
    /// Pending nonces, oldest first. Bounded and scanned linearly: one entry is
    /// removed per signature, so the scan never competes with the signing.
    pending: Mutex<VecDeque<SigningNonces>>,
    #[cfg(not(target_family = "wasm"))]
    durable: Option<durable::Dir>,
}

impl NonceStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// A store that keeps each issued nonce in its own file under `dir`, so a
    /// flow that commits before a restart can still sign after it.
    ///
    /// A nonce releases at most one signature share, for one request: the share
    /// is journaled with a hash of the request before it is returned. Repeating
    /// that request returns the same share (a retry after a crash), any other
    /// request is refused. `dir` holds secrets: keep it as private as the seed.
    #[cfg(not(target_family = "wasm"))]
    pub fn durable(dir: impl Into<std::path::PathBuf>) -> Result<Self, SignerError> {
        Ok(Self {
            pending: Mutex::default(),
            durable: Some(durable::Dir::open(dir.into())?),
        })
    }

    /// Records `nonces` as issued and unconsumed.
    pub(crate) fn insert(&self, nonces: SigningNonces) -> Result<(), SignerError> {
        #[cfg(not(target_family = "wasm"))]
        if let Some(dir) = &self.durable {
            return dir.insert(&nonces);
        }
        let mut pending = self.lock()?;
        pending.push_back(nonces);
        while pending.len() > MAX_PENDING_NONCES {
            pending.pop_front();
        }
        Ok(())
    }

    /// Produces the share for `request_hash` with the nonces behind
    /// `commitments`, through `sign`. Errors with
    /// [`SignerError::UnknownNonceCommitment`] when the commitment was not issued
    /// here, was evicted, or already signed a different request.
    pub(crate) fn sign_with(
        &self,
        commitments: &SigningCommitments,
        request_hash: [u8; 32],
        sign: impl FnOnce(&SigningNonces) -> Result<SignatureShare, SignerError>,
    ) -> Result<SignatureShare, SignerError> {
        #[cfg(not(target_family = "wasm"))]
        if let Some(dir) = &self.durable {
            return dir.sign_with(commitments, request_hash, sign);
        }
        let _ = request_hash;
        // Taken before signing, so a failed attempt cannot be retried with it.
        let nonces = self.take(commitments)?;
        sign(&nonces)
    }

    fn take(&self, commitments: &SigningCommitments) -> Result<SigningNonces, SignerError> {
        let mut pending = self.lock()?;
        let at = pending
            .iter()
            .position(|nonces| nonces.commitments() == commitments)
            .ok_or(SignerError::UnknownNonceCommitment)?;
        Ok(pending
            .remove(at)
            .expect("position returned an in-range index"))
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, VecDeque<SigningNonces>>, SignerError> {
        self.pending
            .lock()
            .map_err(|_| SignerError::Generic("nonce store lock poisoned".to_string()))
    }
}

#[cfg(not(target_family = "wasm"))]
mod durable {
    use std::fs::{self, File, OpenOptions};
    use std::io::{ErrorKind, Write};
    use std::path::{Path, PathBuf};

    use bitcoin::hashes::{Hash, sha256};
    use bitcoin::secp256k1::rand::{RngCore, thread_rng};
    use frost_secp256k1_tr::round1::{SigningCommitments, SigningNonces};
    use frost_secp256k1_tr::round2::SignatureShare;

    use crate::signer::SignerError;

    fn io(context: &str, e: std::io::Error) -> SignerError {
        SignerError::Generic(format!("durable nonce store: {context}: {e}"))
    }

    /// One `<id>.nonce` file per issued commitment and, once it signs, one
    /// `<id>.signed` record: the request hash and the share. The record is
    /// created with a hard link, which fails when it exists, so of two
    /// concurrent signers exactly one publishes; the other's share is dropped
    /// unreleased. ponytail: `.signed` and `.nonce` files are never swept; add
    /// a sweep keyed on age if the directory grows.
    pub(super) struct Dir {
        path: PathBuf,
    }

    impl Dir {
        pub(super) fn open(path: PathBuf) -> Result<Self, SignerError> {
            fs::create_dir_all(&path).map_err(|e| io("create directory", e))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                    .map_err(|e| io("restrict directory", e))?;
            }
            Ok(Self { path })
        }

        fn id(commitments: &SigningCommitments) -> Result<String, SignerError> {
            let bytes = commitments
                .serialize()
                .map_err(|e| SignerError::SerializationError(e.to_string()))?;
            Ok(sha256::Hash::hash(&bytes).to_string())
        }

        fn file(&self, id: &str, kind: &str) -> PathBuf {
            self.path.join(format!("{id}.{kind}"))
        }

        fn sync_dir(&self) -> Result<(), SignerError> {
            File::open(&self.path)
                .and_then(|dir| dir.sync_all())
                .map_err(|e| io("sync directory", e))
        }

        /// Writes `bytes` to a fresh private temporary file, synced.
        fn write_temp(&self, id: &str, bytes: &[u8]) -> Result<PathBuf, SignerError> {
            let tmp = self.file(id, &format!("{:016x}.tmp", thread_rng().next_u64()));
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let mut file = options.open(&tmp).map_err(|e| io("create file", e))?;
            file.write_all(bytes)
                .and_then(|()| file.sync_all())
                .map_err(|e| io("write file", e))?;
            Ok(tmp)
        }

        pub(super) fn insert(&self, nonces: &SigningNonces) -> Result<(), SignerError> {
            let id = Self::id(nonces.commitments())?;
            let bytes = nonces
                .serialize()
                .map_err(|e| SignerError::SerializationError(e.to_string()))?;
            let tmp = self.write_temp(&id, &bytes)?;
            fs::rename(&tmp, self.file(&id, "nonce")).map_err(|e| io("publish nonce", e))?;
            self.sync_dir()
        }

        pub(super) fn sign_with(
            &self,
            commitments: &SigningCommitments,
            request_hash: [u8; 32],
            sign: impl FnOnce(&SigningNonces) -> Result<SignatureShare, SignerError>,
        ) -> Result<SignatureShare, SignerError> {
            let id = Self::id(commitments)?;
            let signed = self.file(&id, "signed");
            if signed.exists() {
                return self.released_share(&signed, request_hash);
            }
            let nonces = match fs::read(self.file(&id, "nonce")) {
                Ok(bytes) => SigningNonces::deserialize(&bytes)
                    .map_err(|e| SignerError::SerializationError(e.to_string()))?,
                Err(e) if e.kind() == ErrorKind::NotFound => {
                    return Err(SignerError::UnknownNonceCommitment);
                }
                Err(e) => return Err(io("read nonce", e)),
            };
            if nonces.commitments() != commitments {
                return Err(SignerError::Generic(
                    "durable nonce store: nonce file does not match its commitment".to_string(),
                ));
            }
            let share = sign(&nonces)?;

            let mut record = request_hash.to_vec();
            record.extend_from_slice(&share.serialize());
            let tmp = self.write_temp(&id, &record)?;
            let published = fs::hard_link(&tmp, &signed);
            let _ = fs::remove_file(&tmp);
            match published {
                Ok(()) => {}
                // Another signer published first: answer from its record.
                Err(e) if e.kind() == ErrorKind::AlreadyExists => {
                    return self.released_share(&signed, request_hash);
                }
                Err(e) => return Err(io("journal share", e)),
            }
            // The record must be on disk before the share leaves: a share released
            // without it could be followed by a second, different one.
            self.sync_dir()?;
            let _ = fs::remove_file(self.file(&id, "nonce"));
            Ok(share)
        }

        /// The share a nonce already released, if `request_hash` is the request it
        /// signed. Any other request is refused: answering it would sign twice.
        /// The directory is synced first: the record may have just been linked by
        /// a signer that has not synced yet, and a share must never leave before
        /// its record is on disk.
        fn released_share(
            &self,
            path: &Path,
            request_hash: [u8; 32],
        ) -> Result<SignatureShare, SignerError> {
            let record = fs::read(path).map_err(|e| io("read share", e))?;
            let (hash, share) = record.split_at_checked(32).ok_or_else(|| {
                SignerError::Generic("durable nonce store: truncated share record".to_string())
            })?;
            if hash != request_hash {
                return Err(SignerError::UnknownNonceCommitment);
            }
            self.sync_dir()?;
            SignatureShare::deserialize(share)
                .map_err(|e| SignerError::SerializationError(e.to_string()))
        }
    }
}

#[cfg(all(test, not(target_family = "wasm")))]
mod tests {
    use std::path::PathBuf;
    use std::sync::Arc;

    use bitcoin::secp256k1::SecretKey;
    use bitcoin::secp256k1::rand::thread_rng;
    use frost_core::round1::Nonce;
    use frost_secp256k1_tr::round1::SigningNonces;
    use frost_secp256k1_tr::round2::SignatureShare;

    use super::NonceStore;
    use crate::signer::SignerError;

    fn nonces() -> SigningNonces {
        let mut rng = thread_rng();
        let hiding = Nonce::deserialize(&SecretKey::new(&mut rng).secret_bytes()).unwrap();
        let binding = Nonce::deserialize(&SecretKey::new(&mut rng).secret_bytes()).unwrap();
        SigningNonces::from_nonces(hiding, binding)
    }

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "spark-nonce-store-{name}-{}",
            SecretKey::new(&mut thread_rng()).display_secret()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    /// A stand-in share that differs per call, so a cached answer is visible.
    fn fresh_share(_: &SigningNonces) -> Result<SignatureShare, SignerError> {
        Ok(SignatureShare::deserialize(&SecretKey::new(&mut thread_rng()).secret_bytes()).unwrap())
    }

    fn is_unknown<T>(result: &Result<T, SignerError>) -> bool {
        matches!(result, Err(SignerError::UnknownNonceCommitment))
    }

    #[test]
    fn a_nonce_signs_one_request_and_refuses_another() {
        let store = NonceStore::durable(temp_dir("one-request")).unwrap();
        let issued = nonces();
        let commitments = *issued.commitments();
        store.insert(issued).unwrap();

        store.sign_with(&commitments, [1; 32], fresh_share).unwrap();
        assert!(is_unknown(&store.sign_with(
            &commitments,
            [2; 32],
            fresh_share
        )));
    }

    #[test]
    fn retrying_the_same_request_returns_the_same_share() {
        let dir = temp_dir("retry");
        let issued = nonces();
        let commitments = *issued.commitments();
        NonceStore::durable(&dir).unwrap().insert(issued).unwrap();

        let first = NonceStore::durable(&dir)
            .unwrap()
            .sign_with(&commitments, [1; 32], fresh_share)
            .unwrap();
        // A crash after the share was released: the retry runs on a new store.
        let retried = NonceStore::durable(&dir)
            .unwrap()
            .sign_with(&commitments, [1; 32], fresh_share)
            .unwrap();
        assert_eq!(first.serialize(), retried.serialize());
    }

    #[test]
    fn a_crash_before_the_share_is_journaled_leaves_the_nonce_signable() {
        let dir = temp_dir("crash");
        let issued = nonces();
        let commitments = *issued.commitments();
        NonceStore::durable(&dir).unwrap().insert(issued).unwrap();

        let crashed = NonceStore::durable(&dir)
            .unwrap()
            .sign_with(&commitments, [1; 32], |_| {
                Err(SignerError::Generic("crash".to_string()))
            });
        assert!(crashed.is_err());
        assert!(
            NonceStore::durable(&dir)
                .unwrap()
                .sign_with(&commitments, [2; 32], fresh_share)
                .is_ok()
        );
    }

    #[test]
    fn concurrent_signers_release_one_share() {
        let store = Arc::new(NonceStore::durable(temp_dir("race")).unwrap());
        let issued = nonces();
        let commitments = *issued.commitments();
        store.insert(issued).unwrap();

        let released = (0..8u8)
            .map(|request| {
                let store = Arc::clone(&store);
                std::thread::spawn(move || {
                    store
                        .sign_with(&commitments, [request; 32], fresh_share)
                        .is_ok()
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
    fn an_unknown_commitment_is_refused() {
        let store = NonceStore::durable(temp_dir("unknown")).unwrap();
        assert!(is_unknown(&store.sign_with(
            nonces().commitments(),
            [1; 32],
            fresh_share
        )));
    }
}

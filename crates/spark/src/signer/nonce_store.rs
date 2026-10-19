use std::collections::VecDeque;
use std::sync::Mutex;

use frost_secp256k1_tr::round1::{SigningCommitments, SigningNonces};

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
    /// flow that commits before a restart can still sign after it. Single use
    /// holds across processes: taking a nonce renames its file away and syncs
    /// the directory before the nonce is returned, so a crash after the take
    /// loses the nonce instead of offering it again. `dir` holds secrets: keep
    /// it as private as the seed.
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

    /// Consumes the nonces behind `commitments`, so a second call for the same
    /// commitment fails. Errors with [`SignerError::UnknownNonceCommitment`]
    /// when the commitment was not issued here, was already signed with, or was
    /// evicted.
    pub(crate) fn take(
        &self,
        commitments: &SigningCommitments,
    ) -> Result<SigningNonces, SignerError> {
        #[cfg(not(target_family = "wasm"))]
        if let Some(dir) = &self.durable {
            return dir.take(commitments);
        }
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
    use frost_secp256k1_tr::round1::{SigningCommitments, SigningNonces};

    use crate::signer::SignerError;

    fn io(context: &str, e: std::io::Error) -> SignerError {
        SignerError::Generic(format!("durable nonce store: {context}: {e}"))
    }

    /// Nonce files, one per issued commitment. `<id>.nonce` is pending; a take
    /// renames it to `<id>.taken` before reading it. Renames are atomic, so of
    /// two concurrent takes exactly one wins, and a `.taken` file left by a
    /// crash is never read again. ponytail: `.taken` leftovers and abandoned
    /// `.nonce` files are not swept; add a sweep if the directory grows.
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

        fn sync_dir(&self) -> Result<(), SignerError> {
            File::open(&self.path)
                .and_then(|dir| dir.sync_all())
                .map_err(|e| io("sync directory", e))
        }

        pub(super) fn insert(&self, nonces: &SigningNonces) -> Result<(), SignerError> {
            let id = Self::id(nonces.commitments())?;
            let bytes = nonces
                .serialize()
                .map_err(|e| SignerError::SerializationError(e.to_string()))?;
            // Written under a temporary name and renamed, so a reader never sees
            // a partial nonce file.
            let tmp = self.path.join(format!("{id}.tmp"));
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let mut file = options.open(&tmp).map_err(|e| io("create nonce", e))?;
            file.write_all(&bytes)
                .and_then(|()| file.sync_all())
                .map_err(|e| io("write nonce", e))?;
            fs::rename(&tmp, self.path.join(format!("{id}.nonce")))
                .map_err(|e| io("publish nonce", e))?;
            self.sync_dir()
        }

        pub(super) fn take(
            &self,
            commitments: &SigningCommitments,
        ) -> Result<SigningNonces, SignerError> {
            let id = Self::id(commitments)?;
            let pending = self.path.join(format!("{id}.nonce"));
            let taken = self.path.join(format!("{id}.taken"));
            match fs::rename(&pending, &taken) {
                Ok(()) => {}
                Err(e) if e.kind() == ErrorKind::NotFound => {
                    return Err(SignerError::UnknownNonceCommitment);
                }
                Err(e) => return Err(io("take nonce", e)),
            }
            // The take must be on disk before the nonce is used: otherwise a crash
            // after signing could bring the pending file back.
            self.sync_dir()?;
            let nonces = read_nonces(&taken)?;
            if nonces.commitments() != commitments {
                return Err(SignerError::Generic(
                    "durable nonce store: nonce file does not match its commitment".to_string(),
                ));
            }
            fs::remove_file(&taken).map_err(|e| io("remove taken nonce", e))?;
            Ok(nonces)
        }
    }

    fn read_nonces(path: &Path) -> Result<SigningNonces, SignerError> {
        let bytes = fs::read(path).map_err(|e| io("read nonce", e))?;
        SigningNonces::deserialize(&bytes)
            .map_err(|e| SignerError::SerializationError(e.to_string()))
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

    fn is_unknown(result: Result<SigningNonces, SignerError>) -> bool {
        matches!(result, Err(SignerError::UnknownNonceCommitment))
    }

    #[test]
    fn a_durable_nonce_is_taken_once() {
        let store = NonceStore::durable(temp_dir("once")).unwrap();
        let issued = nonces();
        let commitments = *issued.commitments();
        store.insert(issued).unwrap();

        assert_eq!(
            store.take(&commitments).unwrap().commitments(),
            &commitments
        );
        assert!(is_unknown(store.take(&commitments)));
    }

    #[test]
    fn a_durable_nonce_survives_a_restart_and_is_still_single_use() {
        let dir = temp_dir("restart");
        let issued = nonces();
        let commitments = *issued.commitments();
        NonceStore::durable(&dir).unwrap().insert(issued).unwrap();

        let after_restart = NonceStore::durable(&dir).unwrap();
        assert!(after_restart.take(&commitments).is_ok());
        assert!(is_unknown(
            NonceStore::durable(&dir).unwrap().take(&commitments)
        ));
    }

    #[test]
    fn a_nonce_taken_before_a_crash_is_never_offered_again() {
        let dir = temp_dir("crash");
        let store = NonceStore::durable(&dir).unwrap();
        let issued = nonces();
        let commitments = *issued.commitments();
        store.insert(issued).unwrap();
        // A crash between the rename and the read leaves only the `.taken` file.
        let pending = std::fs::read_dir(&dir)
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        std::fs::rename(&pending, pending.with_extension("taken")).unwrap();

        assert!(is_unknown(
            NonceStore::durable(&dir).unwrap().take(&commitments)
        ));
    }

    #[test]
    fn concurrent_takes_of_one_nonce_succeed_once() {
        let store = Arc::new(NonceStore::durable(temp_dir("race")).unwrap());
        let issued = nonces();
        let commitments = *issued.commitments();
        store.insert(issued).unwrap();

        let wins = (0..8)
            .map(|_| {
                let store = Arc::clone(&store);
                std::thread::spawn(move || store.take(&commitments).is_ok())
            })
            .collect::<Vec<_>>()
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .filter(|won| *won)
            .count();
        assert_eq!(wins, 1);
    }

    #[test]
    fn an_unknown_commitment_is_refused() {
        let store = NonceStore::durable(temp_dir("unknown")).unwrap();
        assert!(is_unknown(store.take(nonces().commitments())));
    }
}

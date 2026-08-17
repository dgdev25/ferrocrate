//! Domain-separated Merkle inclusion proofs for witness record hashes.
//!
//! The tree is an additive transparency primitive: leaves are already
//! canonical witness-record hashes, so this module never hashes a JSON view.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

const LEAF_DOMAIN: &[u8] = b"FERROCRATE-WITNESS-MERKLE-LEAF-V1";
const NODE_DOMAIN: &[u8] = b"FERROCRATE-WITNESS-MERKLE-NODE-V1";
pub const MAX_LEAVES: usize = 1 << 20;
pub const MAX_PROOF_DEPTH: usize = 64;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum MerkleError {
    #[error("Merkle tree requires at least one leaf")]
    Empty,
    #[error("Merkle tree exceeds {MAX_LEAVES} leaves")]
    TooManyLeaves,
    #[error("Merkle leaf index is out of range")]
    IndexOutOfRange,
    #[error("Merkle proof exceeds {MAX_PROOF_DEPTH} levels")]
    ProofTooDeep,
    #[error("Merkle proof root does not match")]
    RootMismatch,
}

/// A self-contained inclusion proof for one witness record hash.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MerkleProof {
    pub leaf: [u8; 32],
    pub index: u64,
    pub tree_size: u64,
    pub siblings: Vec<[u8; 32]>,
    pub root: [u8; 32],
}

/// A bounded append-only consistency witness.
///
/// The proof carries the opaque record-hash sequence so an external verifier
/// can independently recompute both tree roots and confirm that the old tree
/// is exactly the prefix of the new tree. It is intentionally bounded by
/// `MAX_LEAVES`; a compact frontier proof can be added without changing the
/// root or domain-separation rules.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MerkleConsistencyProof {
    pub old_size: u64,
    pub new_size: u64,
    pub leaves: Vec<[u8; 32]>,
    pub old_root: [u8; 32],
    pub new_root: [u8; 32],
}

/// A compact append-only consistency proof.
///
/// Unlike `MerkleConsistencyProof`, this carries only the old tree's binary
/// frontier and the newly appended leaves. Verification reconstructs the old
/// and new roots, so proof size is proportional to the retained frontier plus
/// the append delta rather than the entire journal prefix.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MerkleFrontierConsistencyProof {
    pub old_size: u64,
    pub new_size: u64,
    pub old_frontier: Vec<Option<[u8; 32]>>,
    pub appended_leaves: Vec<[u8; 32]>,
    pub old_root: [u8; 32],
    pub new_root: [u8; 32],
}

fn leaf_hash(leaf: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(LEAF_DOMAIN);
    hasher.update(leaf);
    hasher.finalize().into()
}

fn node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(NODE_DOMAIN);
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

fn checked_leaves(leaves: &[[u8; 32]]) -> Result<(), MerkleError> {
    if leaves.is_empty() {
        return Err(MerkleError::Empty);
    }
    if leaves.len() > MAX_LEAVES {
        return Err(MerkleError::TooManyLeaves);
    }
    Ok(())
}

fn next_level(level: &[[u8; 32]]) -> Vec<[u8; 32]> {
    level
        .chunks(2)
        .map(|pair| node_hash(&pair[0], pair.get(1).unwrap_or(&pair[0])))
        .collect()
}

fn append_frontier(
    frontier: &mut Vec<Option<[u8; 32]>>,
    leaf: &[u8; 32],
) -> Result<(), MerkleError> {
    let mut carry = leaf_hash(leaf);
    let mut level = 0usize;
    loop {
        if level >= MAX_PROOF_DEPTH {
            return Err(MerkleError::ProofTooDeep);
        }
        if frontier.len() <= level {
            frontier.resize(level + 1, None);
        }
        match frontier[level].take() {
            Some(left) => {
                carry = node_hash(&left, &carry);
                level += 1;
            }
            None => {
                frontier[level] = Some(carry);
                return Ok(());
            }
        }
    }
}

fn frontier_root(frontier: &[Option<[u8; 32]>], leaf_count: u64) -> Result<[u8; 32], MerkleError> {
    if leaf_count == 0 || leaf_count as usize > MAX_LEAVES {
        return Err(if leaf_count == 0 { MerkleError::Empty } else { MerkleError::TooManyLeaves });
    }
    let mut current = None;
    let mut current_level = 0usize;
    for level in 0..MAX_PROOF_DEPTH {
        let Some(peak) = frontier.get(level).and_then(|value| *value) else {
            continue;
        };
        if current.is_none() {
            current = Some(peak);
            current_level = level;
            continue;
        }
        let mut right = current.take().expect("frontier current exists");
        while current_level < level {
            right = node_hash(&right, &right);
            current_level += 1;
        }
        current = Some(node_hash(&peak, &right));
        current_level = level + 1;
    }
    current.ok_or(MerkleError::Empty)
}

fn frontier_from_leaves(leaves: &[[u8; 32]]) -> Result<Vec<Option<[u8; 32]>>, MerkleError> {
    checked_leaves(leaves)?;
    let mut frontier = Vec::new();
    for leaf in leaves {
        append_frontier(&mut frontier, leaf)?;
    }
    Ok(frontier)
}

/// Compute the transparency root for canonical witness record hashes.
pub fn root(leaves: &[[u8; 32]]) -> Result<[u8; 32], MerkleError> {
    checked_leaves(leaves)?;
    let mut level = leaves.iter().map(leaf_hash).collect::<Vec<_>>();
    while level.len() > 1 {
        level = next_level(&level);
    }
    Ok(level[0])
}

/// Produce an inclusion proof for `index`.
pub fn prove(leaves: &[[u8; 32]], index: usize) -> Result<MerkleProof, MerkleError> {
    checked_leaves(leaves)?;
    if index >= leaves.len() {
        return Err(MerkleError::IndexOutOfRange);
    }

    let mut level = leaves.iter().map(leaf_hash).collect::<Vec<_>>();
    let mut cursor = index;
    let mut siblings = Vec::new();
    while level.len() > 1 {
        let sibling = if cursor.is_multiple_of(2) {
            level.get(cursor + 1).copied().unwrap_or(level[cursor])
        } else {
            level[cursor - 1]
        };
        siblings.push(sibling);
        if siblings.len() > MAX_PROOF_DEPTH {
            return Err(MerkleError::ProofTooDeep);
        }
        cursor /= 2;
        level = next_level(&level);
    }

    Ok(MerkleProof {
        leaf: leaves[index],
        index: index as u64,
        tree_size: leaves.len() as u64,
        siblings,
        root: level[0],
    })
}

/// Verify an inclusion proof without access to the original tree.
pub fn verify(proof: &MerkleProof) -> Result<(), MerkleError> {
    if proof.tree_size == 0 || proof.index >= proof.tree_size {
        return Err(MerkleError::IndexOutOfRange);
    }
    if proof.siblings.len() > MAX_PROOF_DEPTH {
        return Err(MerkleError::ProofTooDeep);
    }
    let mut hash = leaf_hash(&proof.leaf);
    let mut cursor = proof.index as usize;
    for sibling in &proof.siblings {
        hash = if cursor.is_multiple_of(2) {
            node_hash(&hash, sibling)
        } else {
            node_hash(sibling, &hash)
        };
        cursor /= 2;
    }
    if hash == proof.root {
        Ok(())
    } else {
        Err(MerkleError::RootMismatch)
    }
}

/// Create a consistency proof showing that the tree at `old_size` is a
/// prefix of the supplied tree.
pub fn consistency_proof(
    leaves: &[[u8; 32]],
    old_size: usize,
) -> Result<MerkleConsistencyProof, MerkleError> {
    checked_leaves(leaves)?;
    if old_size == 0 || old_size > leaves.len() {
        return Err(MerkleError::IndexOutOfRange);
    }
    let old_root = root(&leaves[..old_size])?;
    let new_root = root(leaves)?;
    Ok(MerkleConsistencyProof {
        old_size: old_size as u64,
        new_size: leaves.len() as u64,
        leaves: leaves.to_vec(),
        old_root,
        new_root,
    })
}

/// Verify an append-only consistency proof without trusting either root.
pub fn verify_consistency(proof: &MerkleConsistencyProof) -> Result<(), MerkleError> {
    checked_leaves(&proof.leaves)?;
    if proof.old_size == 0
        || proof.new_size != proof.leaves.len() as u64
        || proof.old_size > proof.new_size
    {
        return Err(MerkleError::IndexOutOfRange);
    }
    let old_root = root(&proof.leaves[..proof.old_size as usize])?;
    let new_root = root(&proof.leaves)?;
    if old_root != proof.old_root || new_root != proof.new_root {
        return Err(MerkleError::RootMismatch);
    }
    Ok(())
}

/// Create a compact append-only consistency proof for `old_size`.
pub fn frontier_consistency_proof(
    leaves: &[[u8; 32]],
    old_size: usize,
) -> Result<MerkleFrontierConsistencyProof, MerkleError> {
    checked_leaves(leaves)?;
    if old_size == 0 || old_size > leaves.len() {
        return Err(MerkleError::IndexOutOfRange);
    }
    let old_frontier = frontier_from_leaves(&leaves[..old_size])?;
    Ok(MerkleFrontierConsistencyProof {
        old_size: old_size as u64,
        new_size: leaves.len() as u64,
        old_frontier,
        appended_leaves: leaves[old_size..].to_vec(),
        old_root: root(&leaves[..old_size])?,
        new_root: root(leaves)?,
    })
}

/// Verify a compact append-only consistency proof without the old prefix.
pub fn verify_frontier_consistency(
    proof: &MerkleFrontierConsistencyProof,
) -> Result<(), MerkleError> {
    if proof.old_size == 0
        || proof.old_size > proof.new_size
        || proof.old_size as usize > MAX_LEAVES
        || proof.new_size as usize > MAX_LEAVES
        || proof.new_size - proof.old_size != proof.appended_leaves.len() as u64
        || proof.old_frontier.len() > MAX_PROOF_DEPTH
    {
        return Err(MerkleError::IndexOutOfRange);
    }
    let old_root = frontier_root(&proof.old_frontier, proof.old_size)?;
    if old_root != proof.old_root {
        return Err(MerkleError::RootMismatch);
    }
    let mut frontier = proof.old_frontier.clone();
    for leaf in &proof.appended_leaves {
        append_frontier(&mut frontier, leaf)?;
    }
    let new_root = frontier_root(&frontier, proof.new_size)?;
    if new_root != proof.new_root {
        return Err(MerkleError::RootMismatch);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leaves(count: usize) -> Vec<[u8; 32]> {
        (0..count)
            .map(|value| {
                let mut leaf = [0u8; 32];
                leaf[..8].copy_from_slice(&(value as u64).to_be_bytes());
                leaf
            })
            .collect()
    }

    #[test]
    fn inclusion_proofs_verify_for_even_and_odd_trees() {
        for count in [1, 2, 3, 7, 8, 17] {
            let records = leaves(count);
            let tree_root = root(&records).expect("root");
            for index in 0..count {
                let proof = prove(&records, index).expect("proof");
                assert_eq!(proof.root, tree_root);
                verify(&proof).expect("verify");
            }
        }
    }

    #[test]
    fn tampered_leaf_or_sibling_is_rejected() {
        let records = leaves(5);
        let mut proof = prove(&records, 2).expect("proof");
        proof.leaf[0] ^= 1;
        assert_eq!(verify(&proof), Err(MerkleError::RootMismatch));

        let mut proof = prove(&records, 2).expect("proof");
        proof.siblings[0][0] ^= 1;
        assert_eq!(verify(&proof), Err(MerkleError::RootMismatch));
    }

    #[test]
    fn consistency_proof_binds_old_prefix_and_new_root() {
        let records = leaves(9);
        let mut proof = consistency_proof(&records, 4).expect("consistency proof");
        verify_consistency(&proof).expect("verify consistency");

        proof.leaves[0][0] ^= 1;
        assert_eq!(verify_consistency(&proof), Err(MerkleError::RootMismatch));

        let mut proof = consistency_proof(&records, 4).expect("consistency proof");
        proof.old_size = 5;
        assert_eq!(verify_consistency(&proof), Err(MerkleError::RootMismatch));
    }

    #[test]
    fn compact_frontier_consistency_proof_reconstructs_append_only_roots() {
        for count in [2, 3, 5, 7, 9, 17, 31] {
            let records = leaves(count);
            for old_size in 1..=count {
                let proof = frontier_consistency_proof(&records, old_size).expect("proof");
                verify_frontier_consistency(&proof).expect("verify");
                assert_eq!(proof.new_root, root(&records).expect("root"));
            }
        }
        let records = leaves(9);
        let mut proof = frontier_consistency_proof(&records, 4).expect("proof");
        proof.appended_leaves[0][0] ^= 1;
        assert_eq!(verify_frontier_consistency(&proof), Err(MerkleError::RootMismatch));
    }

    #[test]
    fn bounds_are_fail_closed() {
        assert_eq!(root(&[]), Err(MerkleError::Empty));
        assert_eq!(prove(&leaves(2), 2), Err(MerkleError::IndexOutOfRange));
        let mut proof = prove(&leaves(2), 0).expect("proof");
        proof.tree_size = 0;
        assert_eq!(verify(&proof), Err(MerkleError::IndexOutOfRange));
    }
}

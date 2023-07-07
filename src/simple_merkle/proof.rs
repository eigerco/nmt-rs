use super::{
    db::NoopDb,
    error::RangeProofError,
    tree::{MerkleHash, MerkleTree},
    utils::compute_num_left_siblings,
};

/// A proof of some statement about a namespaced merkle tree.
///
/// This proof may prove the presence of some set of leaves, or the
/// absence of a particular namespace
#[derive(Debug, PartialEq, Clone, Default)]
#[cfg_attr(
    feature = "borsh",
    derive(borsh::BorshSerialize, borsh::BorshDeserialize)
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Proof<M: MerkleHash> {
    pub siblings: Vec<M::Output>,
    pub start: u32,
    pub end: u32, // non inclusive
}

impl<M> Proof<M>
where
    M: MerkleHash,
{
    /// Verify a range proof
    pub fn verify_range(
        &self,
        root: &M::Output,
        leaf_hashes: &[M::Output],
    ) -> Result<(), RangeProofError> {
        let tree = MerkleTree::<NoopDb, M>::new();
        let mut siblings = self.siblings.iter().collect();

        if leaf_hashes.len() != self.range_len() {
            return Err(RangeProofError::WrongAmountOfLeavesProvided);
        }

        tree.check_range_proof(root, leaf_hashes, &mut siblings, self.start as usize)
    }

    pub fn siblings(&self) -> &Vec<M::Output> {
        &self.siblings
    }

    pub fn start_idx(&self) -> u32 {
        self.start
    }

    pub fn end_idx(&self) -> u32 {
        self.end
    }

    pub fn range_len(&self) -> usize {
        self.end.saturating_sub(self.start)
    }

    pub fn leftmost_right_sibling(&self) -> Option<&M::Output> {
        let siblings = self.siblings();
        let num_left_siblings = compute_num_left_siblings(self.start_idx() as usize);
        if siblings.len() > num_left_siblings {
            return Some(&siblings[num_left_siblings]);
        }
        None
    }

    pub fn rightmost_left_sibling(&self) -> Option<&M::Output> {
        let siblings = self.siblings();
        let num_left_siblings = compute_num_left_siblings(self.start_idx() as usize);
        if num_left_siblings != 0 && num_left_siblings <= siblings.len() {
            return Some(&siblings[num_left_siblings - 1]);
        }
        None
    }
}

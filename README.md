# Plonky3 Merkle Tree inclusion example

This proves inclusion of a leaf hash in a merkle tree using Plonky3. 

## Program & Constraints

Input: hashed_leaf, inclusion path (hash + "flip" bit), merkle root.

Verifies that hashed leaf is indeed part of the merkle tree. 

### Trace definition
Each row contains: current hash (32 bits), sibling node (32 bits), flip or not (1 bit), resulting hash (32 bits). 

### Constraints

- The 32 last bits of the last row equals merkle root
- Flip bit should always be binary
TODO
- For each row: final hash was created by hashing first 2 hashes
- Final rows are duplicated if proof_len() is less than 4

## Tutorials

Uses `Cargo.lock` from https://github.com/BrianSeong99/Plonky3_RangeCheck

Written tutorial: https://docs.polygon.technology/learn/plonky3/examples/fibonacci
# Plonky3 Merkle Tree inclusion example

## Input: hashed_leaf, inclusion path (hash + "flip" bit), merkle root

## Trace definition
Each row contains:
current hash, sibling node, flip or not, resulting hash

Step 0: hash the leaf
Then, for each node: fill out the row as described above

## Constraints

- The 4th element of the last row equals merkle root
- flip bit should always be binary

## Tutorials

Uses `Cargo.lock` from https://github.com/BrianSeong99/Plonky3_RangeCheck

Written tutorial: https://docs.polygon.technology/learn/plonky3/examples/fibonacci
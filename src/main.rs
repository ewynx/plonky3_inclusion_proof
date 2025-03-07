use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::{AbstractField, Field};
use p3_matrix::Matrix;
use p3_matrix::dense::RowMajorMatrix;
use std::marker::PhantomData;
use p3_symmetric::CryptographicHasher;
use p3_sha256::Sha256;
use p3_challenger::{HashChallenger, SerializingChallenger32};
use p3_circle::CirclePcs;
use p3_commit::ExtensionMmcs;
use p3_field::extension::BinomialExtensionField;
use p3_fri::FriConfig;
use p3_keccak::Keccak256Hash;
use p3_merkle_tree::MerkleTreeMmcs;
use p3_mersenne_31::Mersenne31;
use p3_symmetric::{CompressionFunctionFromHasher, SerializingHasher32};
use p3_uni_stark::{prove, verify, StarkConfig};
use tracing_forest::util::LevelFilter;
use tracing_forest::ForestLayer;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Registry};


pub struct MmrAir {
  pub hashed_leaf: [u8; 32],
  pub inclusion_proof: Vec<(u8, [u8; 32])>,
  pub merkle_root: [u8; 32],
}

impl<F: Field> BaseAir<F> for MmrAir {
  fn width(&self) -> usize {
     // current hash 32 spots, other node 32 spots, flip bit, resulting hash 32 spots
     // 3*32 + 1  
    97
  }
}

// - The final 32 bits of the last row equal the merkle root bits
// - flip bit should always be binary
impl<AB: AirBuilder> Air<AB> for MmrAir {
  fn eval(&self, builder: &mut AB) {
      let main = builder.main();
      let local = main.row_slice(0);

      builder.assert_bool(local[32]); // the flip bit of the inclusion path

      // when last row check the last 32 bits with the 32 bits of merkle_root
      for i in 0..32 {
        let merkle_root_hash_bit = AB::Expr::from_canonical_u8(self.merkle_root[i].into());
        builder.when_last_row().assert_eq(local[32*2+1+i], merkle_root_hash_bit);
      }
      
  }
}

pub fn generate_inclusion_trace<F: Field>(
  hashed_leaf: [u8; 32],
  inclusion_proof: Vec<(u8, [u8; 32])>,
  merkle_root: [u8; 32]
) -> RowMajorMatrix<F> {
  let mut values = Vec::with_capacity(97 * inclusion_proof.len()); // 97 per row

  let sha256 = Sha256;
  let mut left: [u8; 32] = [0; 32];
  let mut right: [u8; 32] = [0; 32];
  let mut next_hash: [u8; 32] = [0; 32];
  let mut concat = [0u8; 64];

  left = hashed_leaf;
  right = inclusion_proof[0].1;
  let mut flip: u8 = inclusion_proof[0].0;

  if flip == 0 {
      concat[..32].copy_from_slice(&left);
      concat[32..].copy_from_slice(&right);
  } else {
      concat[..32].copy_from_slice(&right);
      concat[32..].copy_from_slice(&left);
  }

  next_hash = sha256.hash_iter(concat);

  // Push the initial row values
  push_hash_as_bits(&mut values, left);
  push_hash_as_bits(&mut values, right);
  values.push(flip);
  push_hash_as_bits(&mut values, next_hash);

  // Process the inclusion proof
  for i in 1..inclusion_proof.len() {
      left = next_hash;
      right = inclusion_proof[i].1;
      flip = inclusion_proof[i].0;

      if flip == 0 {
          concat[..32].copy_from_slice(&left);
          concat[32..].copy_from_slice(&right);
      } else {
          concat[..32].copy_from_slice(&right);
          concat[32..].copy_from_slice(&left);
      }

      next_hash = sha256.hash_iter(concat);
      push_hash_as_bits(&mut values, left);
      push_hash_as_bits(&mut values, right);
      values.push(flip);
      push_hash_as_bits(&mut values, next_hash);
  }

  // Convert the collected u8 values into field elements
  let values_f: Vec<F> = values.iter().map(|&x| F::from_canonical_u8(x)).collect();

  RowMajorMatrix::new(values_f, 97)
}

/// Helper function to push a 32-byte hash as separate bits into the values vector
fn push_hash_as_bits(values: &mut Vec<u8>, hash: [u8; 32]) {
  for byte in hash.iter() {
      for bit in (0..8).rev() {
          values.push((byte >> bit) & 1); // Extract bit and push it
      }
  }
}

pub fn prove_and_verify<F: Field>(  hashed_leaf: [u8; 32],
  inclusion_proof: Vec<(u8, [u8; 32])>,
  merkle_root: [u8; 32]) {
  let env_filter = EnvFilter::builder()
      .with_default_directive(LevelFilter::INFO.into())
      .from_env_lossy();

  Registry::default()
      .with(env_filter)
      .with(ForestLayer::default())
      .init();

  type Val = Mersenne31;
  type Challenge = BinomialExtensionField<Val, 3>;

  type ByteHash = Sha256;
  type FieldHash = SerializingHasher32<ByteHash>;
  let byte_hash = ByteHash {};
  let field_hash = FieldHash::new(Sha256 {});

  type MyCompress = CompressionFunctionFromHasher<ByteHash, 2, 32>;
  let compress = MyCompress::new(byte_hash);

  type ValMmcs = MerkleTreeMmcs<Val, u8, FieldHash, MyCompress, 32>;
  let val_mmcs = ValMmcs::new(field_hash, compress);

  type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;
  let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());

  type Challenger = SerializingChallenger32<Val, HashChallenger<u8, ByteHash, 32>>;

  let fri_config = FriConfig {
      log_blowup: 1,
      num_queries: 100,
      proof_of_work_bits: 16,
      mmcs: challenge_mmcs,
  };

  type Pcs = CirclePcs<Val, ValMmcs, ChallengeMmcs>;
  let pcs = Pcs {
      mmcs: val_mmcs,
      fri_config,
      _phantom: PhantomData,
  };

  type MyConfig = StarkConfig<Pcs, Challenge, Challenger>;
  let config = MyConfig::new(pcs);

  let air = MmrAir { hashed_leaf, inclusion_proof: inclusion_proof.clone(), merkle_root };
  let trace = generate_inclusion_trace::<Val>( hashed_leaf, inclusion_proof, merkle_root);

  let mut challenger = Challenger::from_hasher(vec![], byte_hash);
  let proof = prove(&config, &air, &mut challenger, trace, &vec![]);

  let mut challenger = Challenger::from_hasher(vec![], byte_hash);
  let _ = verify(&config, &air, &mut challenger, &proof, &vec![]).expect("verification failed");
}

fn main() {
  let sha256 = Sha256;
  let leaf: u8 = 26;
  let hashed_leaf = sha256.hash_iter([leaf].to_vec());

  let right_leaf: u8 = 8;
  let hashed_right_leaf: [u8;32] = sha256.hash_iter([right_leaf].to_vec());

  let mut inclusion_path: Vec<(u8, [u8; 32])> = Vec::new();
  inclusion_path.push((0, hashed_right_leaf));

  let mut concat: [u8;64] = [0;64];  
  concat[..32].copy_from_slice(&hashed_leaf);
  concat[32..].copy_from_slice(&hashed_right_leaf);
  let merkle_root = sha256.hash_iter(concat.to_vec());

  prove_and_verify::<Mersenne31>(hashed_leaf, inclusion_path, merkle_root);
}
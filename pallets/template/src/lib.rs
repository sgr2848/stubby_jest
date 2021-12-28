#![cfg_attr(not(feature = "std"), no_std)]
pub use pallet::*;
//
// #################################

#[frame_support::pallet] // frame_support will allow the pallet to be used in construct_runtime
pub mod pallet {
	use super::*;
	use frame_support::{fail, pallet_prelude::*, Blake2_128Concat};
	use frame_system::pallet_prelude::*;
	#[cfg(feature = "std")]
	use sp_std::convert::TryInto;
	use sp_std::vec::Vec;

	////Check if error or ok,
	/// return error
	macro_rules! ok_or_err {
		($x:expr,$y:expr) => {
			if ($x.is_err()) {
				return fail!($y);
			}
			// $x.unwrap()
		};
	}
	pub fn get_fixed_arr<T>(v: Vec<T>) -> [T; 32] {
		v.try_into().unwrap_or_else(|_v: Vec<T>| panic!())
	}
	#[pallet::config] //Used for defining pallet generics
	pub trait Config: frame_system::Config {
		type Event: From<Event<Self>> + IsType<<Self as frame_system::Config>::Event>;
		#[pallet::constant]
		type SigLength: Get<u8>;
		#[pallet::constant]
		type PKLength: Get<u8>;
		#[pallet::constant]
		type MsgLength: Get<u8>;
	}
	#[pallet::event] // Same as error, but gives more information
	#[pallet::generate_deposit(pub(super) fn deposit_event)]
	pub enum Event<T: Config> {
		ClaimCreated(T::AccountId, Vec<u8>),
		ClaimRevoked(T::AccountId, Vec<u8>),
		SignatureValidated(T::AccountId),
		// ValidUser(T::AccountId, Vec<u8>),
	}
	#[pallet::error] //Puts error variants documentation into metadata.
	pub enum Error<T> {
		ProofAlreadyClaimed,
		NoSuchProof,
		NotProofOwner,
		InvalidSignature,
		KeysDoNotMatch,
		SignatureLengthDoesNotMatch,
		PublicKeyLengthDoesNotMatch,
		MessageLengthDoesNotMatch,
	}
	#[pallet::pallet] //required to declare the pallet struct
	#[pallet::generate_store(pub(super) trait Store)]
	pub struct Pallet<T>(_);
	#[pallet::storage]
	pub(super) type Proofs<T: Config> =
		StorageMap<_, Blake2_128Concat, Vec<u8>, (T::AccountId, T::BlockNumber), ValueQuery>;
	#[pallet::hooks]
	impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {}
	#[pallet::call]
	impl<T: Config> Pallet<T> {
		#[pallet::weight(1_000)]
		pub fn create_claim(origin: OriginFor<T>, proof: Vec<u8>) -> DispatchResult {
			let sender = ensure_signed(origin)?;
			ensure!(!Proofs::<T>::contains_key(&proof), Error::<T>::ProofAlreadyClaimed);
			let current_block = <frame_system::Pallet<T>>::block_number();
			Proofs::<T>::insert(&proof, (&sender, current_block));
			Self::deposit_event(Event::ClaimCreated(sender, proof));
			Ok(())
		}
		#[pallet::weight(1_000)]
		pub fn authenticate_signature(
			origin: OriginFor<T>,
			signature: Vec<u8>,
			raw_msg: Vec<u8>,
			public_key: Vec<u8>,
		) -> DispatchResult {
			let sender = ensure_signed(origin)?;
			///Checks For Length
			ensure!(
				signature.len() == T::SigLength::get() as usize,
				Error::<T>::SignatureLengthDoesNotMatch
			);
			ensure!(
				raw_msg.len() == T::MsgLength::get() as usize,
				Error::<T>::MessageLengthDoesNotMatch
			);
			ensure!(
				public_key.len() == T::PKLength::get() as usize,
				Error::<T>::PublicKeyLengthDoesNotMatch
			);
			let msg = libsecp256k1::Message::parse(&get_fixed_arr(raw_msg));
			let signature_k = libsecp256k1::Signature::parse_standard_slice(&signature[..64]);
			let recovery_k = libsecp256k1::RecoveryId::parse(signature[64]);
			ok_or_err!(signature_k, Error::<T>::ProofAlreadyClaimed);
			ok_or_err!(recovery_k, Error::<T>::ProofAlreadyClaimed);
			let i_key = libsecp256k1::recover(&msg, &signature_k.unwrap(), &recovery_k.unwrap());
			ok_or_err!(i_key, Error::<T>::ProofAlreadyClaimed);
			ensure!(
				i_key.unwrap().serialize_compressed()[..] == public_key[..],
				Error::<T>::KeysDoNotMatch
			);
			Self::deposit_event(Event::SignatureValidated(sender));
			Ok(())
		}
		#[pallet::weight(1_000)]
		pub fn revoke_claim(origin: OriginFor<T>, proof: Vec<u8>) -> DispatchResult {
			let sender = ensure_signed(origin)?; //getting sender
			ensure!(Proofs::<T>::contains_key(&proof), Error::<T>::NoSuchProof); //checking if proof exists
			let (owner, _) = Proofs::<T>::get(&proof); //get owner for the said proof
			ensure!(sender == owner, Error::<T>::NotProofOwner); //Error if proof is not saved by the sender
			Proofs::<T>::remove(&proof);
			Self::deposit_event(Event::ClaimRevoked(sender, proof));
			Ok(())
		}
	}
}

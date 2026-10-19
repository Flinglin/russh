use cbc::cipher::{InnerIvInit, Iv, IvSizeUser};
use cbc::{Decryptor, Encryptor};
use cipher::common::InnerUser;
use cipher::{
    Block, BlockCipherDecrypt, BlockCipherEncrypt, BlockModeDecrypt, BlockModeEncrypt, IvState,
};

use super::block::{BlockStreamCipher, PacketLengthProbe};

/// CBC wrapper that stores the decryption cipher and IV separately rather than
/// a `cbc::Decryptor`, because `Decryptor` is no longer `Clone` in cbc 0.2.
/// This allows stateless peeking at the packet length block without cloning.
pub struct CbcWrapper<C>
where
    C: BlockCipherEncrypt + BlockCipherDecrypt,
{
    encryptor: Encryptor<C>,
    /// Raw cipher used for decryption. `BlockCipherDecrypt::decrypt_block` takes
    /// `&self`, so this can be used without mutation for packet-length probing.
    dec_cipher: C,
    /// Current CBC decryption IV (i.e. the last ciphertext block consumed).
    dec_iv: Block<C>,
}

impl<C> CbcWrapper<C>
where
    C: BlockCipherEncrypt + BlockCipherDecrypt + Clone,
{
    #[must_use]
    fn decrypt_inner(&self, data: &mut [u8]) -> Iv<Self> {
        let mut dec = Decryptor::<&C>::inner_iv_init(&self.dec_cipher, &self.dec_iv);

        for chunk in data.chunks_exact_mut(C::block_size()) {
            #[allow(clippy::expect_used)]
            let block = <&mut Block<C>>::try_from(chunk).expect("chunk length matches block size");

            dec.decrypt_block(block);
        }

        dec.iv_state()
    }
}

impl<C: BlockCipherEncrypt + BlockCipherDecrypt> InnerUser for CbcWrapper<C> {
    type Inner = C;
}

impl<C: BlockCipherEncrypt + BlockCipherDecrypt> IvSizeUser for CbcWrapper<C> {
    type IvSize = C::BlockSize;
}

impl<C: BlockCipherEncrypt + BlockCipherDecrypt + Clone> BlockStreamCipher for CbcWrapper<C> {
    fn encrypt_data(&mut self, data: &mut [u8]) {
        for chunk in data.chunks_exact_mut(C::block_size()) {
            #[allow(clippy::expect_used)]
            let block = <&mut Block<C>>::try_from(chunk).expect("chunk length matches block size");
            self.encryptor.encrypt_block(block);
        }
    }

    fn decrypt_data(&mut self, data: &mut [u8]) {
        self.dec_iv = self.decrypt_inner(data)
    }
}

impl<C: BlockCipherEncrypt + BlockCipherDecrypt + Clone> PacketLengthProbe for CbcWrapper<C> {
    fn decrypt_packet_length_block(&self, first_block: &mut [u8; 16]) {
        let _ = self.decrypt_inner(first_block);
    }
}

impl<C: BlockCipherEncrypt + BlockCipherDecrypt + Clone> InnerIvInit for CbcWrapper<C> {
    #[inline]
    fn inner_iv_init(cipher: C, iv: &Iv<Self>) -> Self {
        Self {
            encryptor: Encryptor::inner_iv_init(cipher.clone(), iv),
            dec_cipher: cipher,
            dec_iv: iv.clone(),
        }
    }
}
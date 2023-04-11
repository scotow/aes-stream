use std::{
    mem,
    pin::Pin,
    task::{Context, Poll},
};

use aes::Aes128;
use bytes::{Buf, Bytes, BytesMut};
use cbc::{
    cipher::{block_padding::Pkcs7, BlockEncryptMut, KeyIvInit},
    Encryptor,
};
use futures_core::Stream;

const BLOCK_SIZE: usize = 16;

pub struct AesSteam<S> {
    inner: S,
    max_len: usize,
    read: usize,
    remaining: Bytes,
    encryptor: Encryptor<Aes128>,
}

impl<S> AesSteam<S> {
    pub fn new(stream: S, max_len: usize, key: &[u8; 16], iv: &[u8; 16]) -> Self {
        Self {
            inner: stream,
            max_len,
            read: 0,
            remaining: Bytes::new(),
            encryptor: Encryptor::new(key.into(), iv.into()),
        }
    }
}

impl<S, E> Stream for AesSteam<S>
where
    S: Stream<Item = Result<Bytes, E>> + Unpin,
{
    type Item = Result<Bytes, E>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match Pin::new(&mut self.inner).poll_next(cx) {
            Poll::Ready(Some(Ok(chunk))) => {
                let mut block = [0; BLOCK_SIZE];
                let remaining = mem::take(&mut self.remaining);
                let mut chain = remaining.chain(chunk);
                let mut encoded = BytesMut::new();

                loop {
                    let remaining_len = chain.remaining();
                    if remaining_len >= BLOCK_SIZE {
                        self.read += BLOCK_SIZE;
                        chain.copy_to_slice(&mut block);
                        self.encryptor.encrypt_block_mut((&mut block).into());
                        encoded.extend_from_slice(&block);
                    } else if self.read + remaining_len >= self.max_len {
                        chain.copy_to_slice(&mut block[..self.max_len - self.read]);
                        let encryptor = mem::replace(
                            &mut self.encryptor,
                            Encryptor::<Aes128>::new(&[0; 16].into(), &[0; 16].into()),
                        );
                        encryptor
                            .encrypt_padded_mut::<Pkcs7>(&mut block, self.max_len - self.read)
                            .unwrap();
                        encoded.extend_from_slice(&block);
                        break;
                    } else if remaining_len > 0 {
                        self.remaining = chain.copy_to_bytes(remaining_len);
                        break;
                    } else {
                        break;
                    }
                }

                Poll::Ready(Some(Ok(encoded.freeze())))
            }
            other => other,
        }
    }
}

#[cfg(test)]
mod tests {
    use futures::{StreamExt, TryStreamExt};
    use hex_literal::hex;
    use sha2::{Digest, Sha256};
    use tokio::fs::File;
    use tokio_util::io::ReaderStream;

    use crate::AesSteam;

    #[tokio::test]
    async fn encrypt() {
        let file = File::open("testfile.bin").await.unwrap();
        let size = file.metadata().await.unwrap().len();
        let data = ReaderStream::new(file)
            .chain(ReaderStream::new(File::open("testfile.bin").await.unwrap()));

        let crypted = AesSteam::new(data, 2 * size as usize, &[0x42; 16], &[0x00; 16])
            .map(|c| c.map(|b| b.to_vec()))
            .try_concat()
            .await
            .unwrap();

        // cat testfile.bin testfile.bin | openssl enc -aes-128-cbc -e -K 42424242424242424242424242424242 -iv 0 -nosalt | shasum -a 256
        // (MacOS)
        let expected = hex!("cb8993d0144b1ecaad953e4144b1b0204dbc7848237fde5076e2e386953ab471");
        assert_eq!(Sha256::digest(&crypted).as_slice(), expected);
    }
}

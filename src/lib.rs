use std::{
    mem,
    pin::Pin,
    task::{Context, Poll},
};

use aes::Aes128;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use cbc::{
    cipher::{block_padding::Pkcs7, BlockEncryptMut, KeyIvInit},
    Encryptor,
};
use futures::Stream;
use pin_project::pin_project;

const BLOCK_SIZE: usize = 16;

#[pin_project]
pub struct AesSteam<S> {
    #[pin]
    inner: S,
    ended: bool,
    remaining: BytesMut,
    encryptor: Encryptor<Aes128>,
}

impl<S: Stream<Item = Result<Bytes, E>>, E> AesSteam<S> {
    pub fn new(stream: S, key: &[u8; 16], iv: &[u8; 16]) -> Self {
        Self {
            inner: stream,
            ended: false,
            remaining: BytesMut::new(),
            encryptor: Encryptor::new(key.into(), iv.into()),
        }
    }
}

impl<S: Stream<Item = Result<Bytes, E>>, E> Stream for AesSteam<S> {
    type Item = Result<Bytes, E>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if self.ended {
            return Poll::Ready(None);
        }

        let mut this = self.project();

        let mut bytes = mem::take(this.remaining);
        let chunk = loop {
            match this.inner.as_mut().poll_next(cx) {
                Poll::Ready(chunk) => match chunk.transpose() {
                    Ok(Some(chunk)) if bytes.len() + chunk.len() >= BLOCK_SIZE => break chunk,
                    Ok(Some(chunk)) => bytes.put(chunk),
                    Ok(None) => {
                        *this.ended = true;
                        break Bytes::new();
                    }
                    Err(err) => return Poll::Ready(Some(Err(err))),
                },
                Poll::Pending => {
                    *this.remaining = bytes;
                    return Poll::Pending;
                }
            }
        };

        let mut block = [0; BLOCK_SIZE];
        let mut chain = bytes.freeze().chain(chunk);
        let mut encoded = BytesMut::new();

        loop {
            let remaining_len = chain.remaining();
            if remaining_len >= BLOCK_SIZE {
                chain.copy_to_slice(&mut block);
                this.encryptor.encrypt_block_mut((&mut block).into());
                encoded.extend_from_slice(&block);
            } else if *this.ended {
                chain.copy_to_slice(&mut block[..remaining_len]);
                let encryptor = mem::replace(
                    this.encryptor,
                    Encryptor::<Aes128>::new(&[0; 16].into(), &[0; 16].into()),
                );
                encryptor
                    .encrypt_padded_mut::<Pkcs7>(&mut block, remaining_len)
                    .unwrap();
                encoded.extend_from_slice(&block);
                break;
            } else {
                *this.remaining = BytesMut::from_iter(chain);
                break;
            }
        }

        Poll::Ready(Some(Ok(encoded.freeze())))
    }
}

#[cfg(test)]
mod tests {
    use std::convert::Infallible;

    use bytes::Bytes;
    use futures::{stream, Stream, StreamExt};
    use hex_literal::hex;
    use sha2::{Digest, Sha256};
    use tokio::fs::File;
    use tokio_util::io::ReaderStream;

    use super::AesSteam;

    async fn encrypt_and_hash<S: Stream<Item = B> + Unpin, B: Into<Bytes>>(stream: S) -> [u8; 32] {
        let mut digest = Sha256::new();
        let mut encryptor = AesSteam::new(
            stream.map(|b| Ok::<_, Infallible>(b.into())),
            &[0x42; 16],
            &[0x00; 16],
        );
        while let Some(Ok(bytes)) = encryptor.next().await {
            digest.update(&bytes);
        }
        digest.finalize().into()
    }

    #[tokio::test]
    async fn empty() {
        assert_eq!(
            encrypt_and_hash(stream::empty::<Bytes>()).await,
            hex!("9aef0dbd6133cb2d3976d0f09fab0d4e7e9a020ceaab96bf35cd22f9369b1b9d")
        )
    }

    #[tokio::test]
    async fn less_than_one_block() {
        let expected = hex!("69331974fa39104bd6581e8093ad1d09c5f60330b8f6ed41a401b7584b27e7c6");
        assert_eq!(encrypt_and_hash(stream::iter(["hello"])).await, expected);
        assert_eq!(
            encrypt_and_hash(stream::iter(b"hello".map(|c| vec![c]))).await,
            expected
        );
    }

    #[tokio::test]
    async fn exactly_one_block() {
        let expected = hex!("207f95b2f792dbaa56438f35937bff8ec7670c2736654cd7c0764baa5732b2d1");
        assert_eq!(
            encrypt_and_hash(stream::iter([[0x42u8; 16].as_slice()])).await,
            expected
        );
        assert_eq!(
            encrypt_and_hash(stream::iter([[0x42u8; 1].as_slice(); 16])).await,
            expected
        );
    }

    #[tokio::test]
    async fn more_than_one_block() {
        let expected = hex!("fe22d4ee0ea759adee8bf18239366f8872b59a72b2c7c47aa18f2e3d4ac97fe1");
        assert_eq!(
            encrypt_and_hash(stream::iter([[0x42u8; 23].as_slice()])).await,
            expected
        );
        assert_eq!(
            encrypt_and_hash(stream::iter([[0x42u8; 1].as_slice(); 23])).await,
            expected
        );
    }

    #[tokio::test]
    async fn exactly_two_blocks() {
        let expected = hex!("6f1db9b84f3f8a1397883e3209668a0d3687b973b384150a0891c3f35b2758d1");
        assert_eq!(
            encrypt_and_hash(stream::iter([[0x42u8; 32].as_slice()])).await,
            expected
        );
        assert_eq!(
            encrypt_and_hash(stream::iter([[0x42u8; 1].as_slice(); 32])).await,
            expected
        );
    }

    #[tokio::test]
    async fn file() {
        // cat testfile.bin | openssl enc -aes-128-cbc -e -K 42424242424242424242424242424242 -iv 0 -nosalt | shasum -a 256 # MacOS
        let expected = hex!("f42b9fc803c7f9ea6aca251e5a06897a96a32361693df11631927bb669170d01");
        assert_eq!(
            encrypt_and_hash(
                ReaderStream::new(File::open("testfile.bin").await.unwrap()).map(|b| b.unwrap())
            )
            .await,
            expected
        );
        assert_eq!(
            encrypt_and_hash(
                ReaderStream::new(File::open("testfile.bin").await.unwrap())
                    .flat_map(|b| stream::iter(b.unwrap()))
                    .map(|b| vec![b])
            )
            .await,
            expected
        );

        // cat testfile.bin testfile.bin | openssl enc -aes-128-cbc -e -K 42424242424242424242424242424242 -iv 0 -nosalt | shasum -a 256 # MacOS
        assert_eq!(
            encrypt_and_hash(
                ReaderStream::new(File::open("testfile.bin").await.unwrap())
                    .chain(ReaderStream::new(File::open("testfile.bin").await.unwrap()))
                    .map(|b| b.unwrap())
            )
            .await,
            hex!("6d32ed31e3012f9088f76a88cb63c9ffaa3a018e9844b0b5c1e3cafed8b283c2")
        );
    }
}

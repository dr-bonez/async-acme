use std::{io::ErrorKind, path::Path};

use async_trait::async_trait;

#[cfg(feature = "use_async_std")]
use async_std::fs::{create_dir_all as cdall, read, write};
#[cfg(feature = "use_tokio")]
use tokio::fs::{create_dir_all, read, write};

use crate::crypto::sha256_hasher;

#[async_trait]
pub trait AcmeCache {
    type Error: CacheError;

    async fn read_account(&self, contacts: &[&str]) -> Result<Option<Vec<u8>>, Self::Error>;

    async fn write_account(&self, contacts: &[&str], contents: &[u8]) -> Result<(), Self::Error>;

    async fn write_certificate(
        &self,
        domains: &[String],
        directory_url: &str,
        key_pem: &str,
        certificate_pem: &str,
    ) -> Result<(), Self::Error>;
}

#[async_trait]
impl<P> AcmeCache for P
where
    P: AsRef<Path> + Send + Sync,
{
    type Error = std::io::Error;

    async fn read_account(&self, contacts: &[&str]) -> Result<Option<Vec<u8>>, Self::Error> {
        let file = cached_key_file_name(contacts);
        let mut path = self.as_ref().to_path_buf();
        path.push(file);
        match read(path).await {
            Ok(content) => Ok(Some(content)),
            Err(err) => match err.kind() {
                ErrorKind::NotFound => Ok(None),
                _ => Err(err),
            },
        }
    }

    async fn write_account(&self, contacts: &[&str], contents: &[u8]) -> Result<(), Self::Error> {
        let mut path = self.as_ref().to_path_buf();
        create_dir_all(&path).await?;
        path.push(cached_key_file_name(contacts));
        Ok(write(path, contents).await?)
    }

    async fn write_certificate(
        &self,
        domains: &[String],
        directory_url: &str,
        key_pem: &str,
        certificate_pem: &str,
    ) -> Result<(), Self::Error> {
        let hash = {
            let mut ctx = sha256_hasher();
            for domain in domains {
                ctx.update(domain.as_ref());
                ctx.update(&[0])
            }
            // cache is specific to a particular ACME API URL
            ctx.update(directory_url.as_bytes());
            base64::encode_config(ctx.finish(), base64::URL_SAFE_NO_PAD)
        };
        let file = AsRef::<Path>::as_ref(self).join(&format!("cached_cert_{}", hash));
        let content = format!("{}\n{}", key_pem, certificate_pem);
        write(&file, &content).await?;
        Ok(())
    }
}

pub trait CacheError: std::error::Error + Send + Sync + 'static {}

impl<T> CacheError for T where T: std::error::Error + Send + Sync + 'static {}

#[cfg(feature = "use_async_std")]
pub async fn create_dir_all(a: impl AsRef<Path>) -> Result<(), Error> {
    let p = a.as_ref();
    let p = <&async_std::path::Path>::from(p);
    cdall(p).await
}

#[cfg(not(any(feature = "use_tokio", feature = "use_async_std")))]
pub async fn create_dir_all(_a: impl AsRef<Path>) -> Result<(), Error> {
    Err(Error::new(ErrorKind::NotFound, "no async backend selected"))
}
#[cfg(not(any(feature = "use_tokio", feature = "use_async_std")))]
pub async fn read(_a: impl AsRef<Path>) -> Result<Vec<u8>, Error> {
    Err(Error::new(ErrorKind::NotFound, "no async backend selected"))
}
#[cfg(not(any(feature = "use_tokio", feature = "use_async_std")))]
pub async fn write(_a: impl AsRef<Path>, _c: impl AsRef<[u8]>) -> Result<(), Error> {
    Err(Error::new(ErrorKind::NotFound, "no async backend selected"))
}

fn cached_key_file_name(contact: &[&str]) -> String {
    let mut ctx = sha256_hasher();
    for el in contact {
        ctx.update(el.as_ref());
        ctx.update(&[0])
    }
    let hash = base64::encode_config(ctx.finish(), base64::URL_SAFE_NO_PAD);
    format!("cached_account_{}", hash)
}

/*! Ways to cache account data and certificates.

A default implementation for `AsRef<Path>` (`Sting`, `OsString`, `PathBuf`, ...)
allows the use of a local directory as cache.
Note that the files contain private keys.
*/

use std::{
    io::{Error as IoError, ErrorKind},
    net::IpAddr,
    path::Path,
};

use crate::{acme::Identifier, B64_URL_SAFE_NO_PAD};
use async_trait::async_trait;
use base64::Engine;

#[cfg(feature = "use_async_std")]
use async_std::{
    fs::{create_dir_all as cdall, read, OpenOptions},
    io::WriteExt,
    os::unix::fs::OpenOptionsExt,
};
#[cfg(feature = "use_tokio")]
use tokio::{
    fs::{create_dir_all, read, OpenOptions},
    io::AsyncWriteExt,
};

use crate::crypto::sha256_hasher;

/// Trait to define a custom location/mechanism to cache account data and certificates.
#[async_trait]
pub trait AcmeCache {
    /// The error type returned from the functions on this trait.
    type Error: CacheError;

    /// Returns the previously written data for `contacts`, if any. This
    /// function should return `None` instead of erroring if data was not
    /// previously written for `contacts`.
    async fn read_account(&self, contacts: &[&str]) -> Result<Option<Vec<u8>>, Self::Error>;

    /// Writes `data` for `contacts`. The data being written is unique for the
    /// combined list of `contacts`.
    ///
    /// # Errors
    ///
    /// Returns an error when `data` was unable to be written successfully.
    async fn write_account(&self, contacts: &[&str], data: &[u8]) -> Result<(), Self::Error>;

    async fn read_certificate(
        &self,
        identifiers: &[Identifier],
        directory_url: &str,
    ) -> Result<Option<(String, String)>, Self::Error>;

    /// Writes a certificate retrieved from `Acme`. The parameters are:
    ///
    /// ## Parameters
    ///
    /// * `identifiers`: the list of identifiers included in the certificate.
    /// * `directory_url`: the Url of the `Acme` directory that this certificate
    ///   was issued form.
    /// * `key_pem`: the private key, encoded in PEM format.
    /// * `certificate_pem`: the certificate chain, encoded in PEM format.
    ///
    /// ## Errors
    ///
    /// Returns an error when the certificate was unable to be written
    /// sucessfully.
    async fn write_certificate(
        &self,
        identifiers: &[Identifier],
        directory_url: &str,
        key_pem: &str,
        certificate_pem: &str,
    ) -> Result<(), Self::Error>;
}

fn hash_idents(identifiers: &[Identifier], directory_url: &str) -> String {
    let mut ctx = sha256_hasher();
    for identifier in identifiers {
        match identifier {
            Identifier::Dns(d) => {
                ctx.update(b"dns\0");
                ctx.update(d.as_ref());
            }
            Identifier::Ip(ip) => {
                ctx.update(b"ip\0");
                match ip {
                    IpAddr::V4(ip) => ctx.update(&ip.octets()),
                    IpAddr::V6(ip) => ctx.update(&ip.octets()),
                }
            }
        }
        ctx.update(&[0])
    }
    // cache is specific to a particular ACME API URL
    ctx.update(directory_url.as_bytes());
    B64_URL_SAFE_NO_PAD.encode(ctx.finish())
}

#[async_trait]
impl<P> AcmeCache for P
where
    P: AsRef<Path> + Send + Sync,
{
    type Error = IoError;

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

    async fn read_certificate(
        &self,
        identifiers: &[Identifier],
        directory_url: &str,
    ) -> Result<Option<(String, String)>, Self::Error> {
        let hash = hash_idents(identifiers, directory_url);
        let file = AsRef::<Path>::as_ref(self).join(&format!("cached_cert_{}", hash));
        match read(file).await {
            Ok(content) => {
                let mut key_pem = String::new();
                let mut cert_pem = String::new();
                for pem in pem::parse_many(content)
                    .map_err(|e| IoError::new(std::io::ErrorKind::InvalidData, e))?
                {
                    if pem.tag().ends_with("PRIVATE KEY") {
                        key_pem.push_str(&pem::encode(&pem));
                    } else if pem.tag() == "CERTIFICATE" {
                        cert_pem.push_str(&pem::encode(&pem));
                    }
                }

                if key_pem.is_empty() || cert_pem.is_empty() {
                    Ok(None)
                } else {
                    Ok(Some((key_pem, cert_pem)))
                }
            }
            Err(err) => match err.kind() {
                ErrorKind::NotFound => Ok(None),
                _ => Err(err),
            },
        }
    }

    async fn write_certificate(
        &self,
        identifiers: &[Identifier],
        directory_url: &str,
        key_pem: &str,
        certificate_pem: &str,
    ) -> Result<(), Self::Error> {
        let hash = hash_idents(identifiers, directory_url);
        let file = AsRef::<Path>::as_ref(self).join(&format!("cached_cert_{}", hash));
        let content = format!("{}\n{}", key_pem, certificate_pem);
        write(&file, &content).await?;
        Ok(())
    }
}

/// An error that can be returned from an [`AcmeCache`].
pub trait CacheError: std::error::Error + Send + Sync + 'static {}

impl<T> CacheError for T where T: std::error::Error + Send + Sync + 'static {}

#[cfg(feature = "use_async_std")]
async fn create_dir_all(a: impl AsRef<Path>) -> Result<(), IoError> {
    let p = a.as_ref();
    let p = <&async_std::path::Path>::from(p);
    cdall(p).await
}

#[cfg(not(any(feature = "use_tokio", feature = "use_async_std")))]
async fn create_dir_all(_a: impl AsRef<Path>) -> Result<(), IoError> {
    Err(IoError::new(
        ErrorKind::NotFound,
        "no async backend selected",
    ))
}
#[cfg(not(any(feature = "use_tokio", feature = "use_async_std")))]
async fn read(_a: impl AsRef<Path>) -> Result<Vec<u8>, IoError> {
    Err(IoError::new(
        ErrorKind::NotFound,
        "no async backend selected",
    ))
}
#[cfg(not(any(feature = "use_tokio", feature = "use_async_std")))]
async fn write(_a: impl AsRef<Path>, _c: impl AsRef<[u8]>) -> Result<(), IoError> {
    Err(IoError::new(
        ErrorKind::NotFound,
        "no async backend selected",
    ))
}
#[cfg(any(feature = "use_tokio", feature = "use_async_std"))]
async fn write(file_path: impl AsRef<Path>, content: impl AsRef<[u8]>) -> Result<(), IoError> {
    let mut file = OpenOptions::new();
    file.write(true).create(true).truncate(true);
    #[cfg(unix)]
    file.mode(0o600); //user: R+W
    let mut buffer = file.open(file_path.as_ref()).await?;
    buffer.write_all(content.as_ref()).await?;
    Ok(())
}

fn cached_key_file_name(contact: &[&str]) -> String {
    let mut ctx = sha256_hasher();
    for el in contact {
        ctx.update(el.as_ref());
        ctx.update(&[0])
    }
    let hash = B64_URL_SAFE_NO_PAD.encode(ctx.finish());
    format!("cached_account_{}", hash)
}

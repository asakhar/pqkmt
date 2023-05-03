use qprov::{keys::{CertificateRequest, CertificateChain, CertificateContents}, Certificate};
use serde::Serialize;

#[derive(Serialize)]
pub struct CertificateRequestDisplay {
  owner: String,
  contract: String,
}

impl From<CertificateRequest> for CertificateRequestDisplay {
  fn from(value: CertificateRequest) -> Self {
    let CertificateRequest{owner, contract, ..} = value;
    Self { owner, contract }
  }
}

#[derive(Serialize)]
pub struct CertificateDisplay {
  issuer: String,
  owner: String,
  contract: String,
}

impl From<Certificate> for CertificateDisplay {
  fn from(value: Certificate) -> Self {
    let CertificateContents{issuer, owner, contract, ..} = value.contents;
    Self { issuer, owner, contract }
  }
}

#[derive(Serialize)]
pub struct CertificateChainDisplay {
  chain: Vec<CertificateDisplay>
}

impl From<CertificateChain> for CertificateChainDisplay {
  fn from(value: CertificateChain) -> Self {
    let CertificateChain{chain} = value;
    let chain = chain.into_iter().map(CertificateDisplay::from).collect();
    Self { chain }
  }
}


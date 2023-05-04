use std::path::PathBuf;

use clap::Parser;
use qprov::{
  generate_key_pairs, Certificate, CertificateChain, CertificateRequest, FileSerialize, PubKeyPair,
  SecKeyPair,
};

use crate::display::{CertificateChainDisplay, CertificateDisplay, CertificateRequestDisplay};

pub mod display;

const REQ_EXT: &str = "req";
const CRT_EXT: &str = "crt";
const SEC_EXT: &str = "key";
const PUB_EXT: &str = "pub";
const CHN_EXT: &str = "chn";

fn main() {
  let cli = Cli::parse();
  cli.run();
}

#[derive(Debug, clap::Parser)]
struct Cli {
  #[command(subcommand)]
  command: Commands,
}

#[derive(Debug, clap::Subcommand)]
enum Commands {
  Generate {
    #[arg()]
    key_path: PathBuf,
    #[arg()]
    pub_path: Option<PathBuf>,
  },
  Request {
    #[arg()]
    pub_path: PathBuf,
    #[arg()]
    req_path: Option<PathBuf>,
  },
  Sign {
    #[arg()]
    req_path: PathBuf,
    #[arg()]
    issuer_priv: PathBuf,
    #[arg()]
    cert_path: Option<PathBuf>,
    #[arg()]
    issuer_chain: Option<PathBuf>,
  },
  Chain {
    #[arg()]
    cert_path: PathBuf,
    #[arg()]
    input_chain: Option<PathBuf>,
    #[arg()]
    output_chain: Option<PathBuf>,
  },
  Verify {
    #[arg()]
    cert_path: PathBuf,
    #[arg()]
    issuer_pub: PathBuf,
  },
  Show {
    #[arg()]
    file_path: PathBuf,
  },
}

impl Cli {
  pub fn run(self) {
    match self.command {
      Commands::Generate { key_path, pub_path } => generate_keys(key_path, pub_path),
      Commands::Sign {
        req_path,
        cert_path,
        issuer_chain,
        issuer_priv,
      } => sign_certificate(req_path, issuer_chain, issuer_priv, cert_path),
      Commands::Request { pub_path, req_path } => request_singing(pub_path, req_path),
      Commands::Chain {
        cert_path,
        input_chain,
        output_chain,
      } => chain(cert_path, input_chain, output_chain),
      Commands::Verify {
        cert_path,
        issuer_pub,
      } => verify_certificate(cert_path, issuer_pub),
      Commands::Show { file_path } => show(file_path),
    }
  }
}

fn file_meaning_by_ext(ext: &str) -> &'static str {
  match ext {
    REQ_EXT => "certificate request",
    CRT_EXT => "certificate",
    SEC_EXT => "secret key",
    PUB_EXT => "public key",
    CHN_EXT => "certificate chain",
    _ => "unknown",
  }
}

fn assume_ext_inner(path: &mut PathBuf, target_ext: &str, print: bool) -> bool {
  if let Some(ext) = path.extension() {
    if ext != target_ext {
      if print {
        eprintln!(
          "Invalid extention for {} file: {}",
          file_meaning_by_ext(target_ext),
          ext.to_string_lossy()
        );
      }
      return false;
    }
  } else {
    path.set_extension(target_ext);
  }
  true
}

fn assume_ext_no_print(path: &mut PathBuf, target_ext: &str) -> bool {
  assume_ext_inner(path, target_ext, false)
}

fn assume_ext(path: &mut PathBuf, target_ext: &str) -> bool {
  assume_ext_inner(path, target_ext, true)
}

fn name_as(target: Option<PathBuf>, reference: &PathBuf, target_ext: &str) -> Option<PathBuf> {
  target
    .map(|mut target| {
      if assume_ext(&mut target, target_ext) {
        Some(target)
      } else {
        None
      }
    })
    .unwrap_or_else(|| {
      let mut cloned = reference.clone();
      cloned.set_extension(target_ext);
      Some(cloned)
    })
}

fn generate_keys(mut key_path: PathBuf, pub_path: Option<PathBuf>) {
  if !assume_ext(&mut key_path, SEC_EXT) {
    return;
  }
  let Some(pub_path ) = name_as(pub_path, &key_path, PUB_EXT) else {return;};

  let (pub_k, sec_k) = generate_key_pairs();
  sec_k
    .to_file(key_path)
    .expect("Failed to write private keys to file");
  pub_k
    .to_file(pub_path)
    .expect("Failed to write public keys to file");
  println!("Success!");
}

fn sign_certificate(
  mut req_path: PathBuf,
  mut issuer_chain: Option<PathBuf>,
  mut issuer_priv: PathBuf,
  cert_path: Option<PathBuf>,
) {
  if !assume_ext(&mut req_path, REQ_EXT) {
    return;
  }
  let Some(cert_path) = name_as(cert_path, &req_path, CRT_EXT) else {return;};

  if let Some(issuer_chain) = issuer_chain.as_mut() {
    if !assume_ext(issuer_chain, CHN_EXT) {
      return;
    }
  }
  if !assume_ext(&mut issuer_priv, SEC_EXT) {
    return;
  }

  println!("Choosen issuer chain file: {issuer_chain:?}");

  let issuer_chain = issuer_chain.map(|file| {
    CertificateChain::from_file(file).expect("Failed to read CA certificate chain from file")
  });
  let issuer_priv_key =
    SecKeyPair::from_file(issuer_priv).expect("Failed to read CA private key from file");
  let cert_req = CertificateRequest::from_file(req_path)
    .expect("Failed to read certificate signing request from file");
  let issuer = match issuer_chain {
    Some(chain) => chain.get_target().contents.owner.clone(),
    None => {
      println!("Enter certificate issuer name: ");
      let mut line = String::new();
      std::io::stdin().read_line(&mut line).unwrap();
      let Some(issuer) = line.lines().next().map(str::to_owned) else {
          println!("Exitting!");
          return;
        };
      issuer
    }
  };
  let cert = cert_req.sign(issuer, issuer_priv_key.sig_key);
  cert
    .to_file(cert_path)
    .expect("Failed to write certificate to file");
  println!("Success!");
}

fn request_singing(mut pub_path: PathBuf, req_path: Option<PathBuf>) {
  if !assume_ext(&mut pub_path, PUB_EXT) {
    return;
  }
  let Some(req_path) = name_as(req_path, &pub_path, REQ_EXT) else {return;};

  let pub_keys = PubKeyPair::from_file(pub_path).expect("Failed to read public key from file");

  let mut line = String::new();
  println!("Enter certificate owner name: ");
  std::io::stdin().read_line(&mut line).unwrap();
  let Some(owner) = line.lines().next().map(str::to_owned) else {
    println!("Exitting!");
    return;
  };
  line.clear();
  println!("Enter contract: ");
  std::io::stdin().read_line(&mut line).unwrap();
  let Some(contract) = line.lines().next().map(str::to_owned) else {
    println!("Exitting!");
    return;
  };
  let request = CertificateRequest::new(pub_keys, owner, contract);
  request
    .to_file(req_path)
    .expect("Failed to write certificate request to file");
  println!("Success!");
}

fn chain(mut cert_path: PathBuf, mut input_chain: Option<PathBuf>, output_chain: Option<PathBuf>) {
  if !assume_ext(&mut cert_path, CRT_EXT) {
    return;
  }

  if let Some(input_chain) = input_chain.as_mut() {
    if !assume_ext(input_chain, CHN_EXT) {
      return;
    }
  }
  let Some(output_chain) = name_as(output_chain, &cert_path, CHN_EXT) else {return;};

  let cert = Certificate::from_file(cert_path).expect("Failed to read certificate from file");
  let input_chain = input_chain.map(|file| {
    CertificateChain::from_file(file).expect("Failed to read parent certificate chain from file")
  });

  let chain = match input_chain {
    Some(mut chain) => {
      if !chain.append(cert) {
        eprintln!("Failed to append certificate to chain, invalid signature");
        return;
      }
      chain
    }
    None => {
      let Some(chain) = CertificateChain::root(cert) else {
        eprintln!("Failed to start chain. Certificate is not self-signed");
        return;
      };
      chain
    }
  };
  chain
    .to_file(output_chain)
    .expect("Failed to write certificate chain to file");
  println!("Success!");
}

fn verify_certificate(mut cert_path: PathBuf, mut issuer_pub: PathBuf) {
  if !assume_ext(&mut cert_path, CRT_EXT) {
    return;
  }
  if !assume_ext_no_print(&mut issuer_pub, PUB_EXT)
    && !assume_ext_no_print(&mut issuer_pub, CRT_EXT)
    && !assume_ext(&mut issuer_pub, CHN_EXT)
  {
    return;
  }

  let cert = Certificate::from_file(cert_path).expect("Failed to read certificate from file");
  let pub_key = match issuer_pub.extension().unwrap().to_string_lossy().as_ref() {
    PUB_EXT => PubKeyPair::from_file(issuer_pub).expect("Failed to read CA public key from file"),
    CRT_EXT => {
      Certificate::from_file(issuer_pub)
        .expect("Failed to read CA certificate from file")
        .contents
        .pub_keys
    }
    CHN_EXT => {
      CertificateChain::from_file(issuer_pub)
        .expect("Failed to read CA certificate chain from file")
        .get_target()
        .clone()
        .contents
        .pub_keys
    }
    _ => unreachable!(),
  };
  let message = if cert.verify(&pub_key.sig_key) {
    "Certificate is valid"
  } else {
    "Invalid certificate"
  };
  println!("{}", message);
}

fn show(file_path: PathBuf) {
  let Some(ext) = file_path.extension() else {
    panic!("File extension not found: {file_path:?}");
  };
  std::fs::File::open(&file_path).expect("File not found");
  match ext.to_string_lossy().as_ref() {
    REQ_EXT => {
      let request =
        CertificateRequest::from_file(file_path).expect("Failed to parse certificate request file");
      println!("Certificate request file:");
      let display: CertificateRequestDisplay = request.into();
      serde_json::to_writer_pretty(std::io::stdout(), &display)
        .expect("Failed to serialize certificate request");
    }
    CRT_EXT => {
      let cert = Certificate::from_file(file_path).expect("Failed to parse certificate file");
      println!("Certificate file:");
      let display: CertificateDisplay = cert.into();
      serde_json::to_writer_pretty(std::io::stdout(), &display)
        .expect("Failed to serialize certificate");
    }
    CHN_EXT => {
      let chain =
        CertificateChain::from_file(file_path).expect("Failed to parse certificate chain file");
      println!("Certificate chain file:");
      let display: CertificateChainDisplay = chain.into();
      serde_json::to_writer_pretty(std::io::stdout(), &display)
        .expect("Failed to serialize certificate chain");
    }
    _ => {
      unimplemented!()
    }
  }
}

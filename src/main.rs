use std::{fs::File, path::PathBuf};

use clap::Parser;

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
      Commands::Chain { cert_path, input_chain, output_chain } => chain(cert_path, input_chain, output_chain),
      Commands::Verify {
        cert_path,
        issuer_pub,
      } => verify_certificate(cert_path, issuer_pub),
    }
  }
}

fn generate_keys(mut key_path: PathBuf, mut pub_path: Option<PathBuf>) {
  if let Some(ext) = key_path.extension() {
    if ext != SEC_EXT {
      eprintln!(
        "Invalid extention for private key file: {}",
        ext.to_string_lossy()
      );
      return;
    }
  } else {
    key_path.set_extension(SEC_EXT);
  }
  let pub_path = pub_path.get_or_insert_with(|| {
    let mut cloned = key_path.clone();
    cloned.set_extension(PUB_EXT);
    cloned
  });
  if let Some(ext) = pub_path.extension() {
    if ext != PUB_EXT {
      eprintln!(
        "Invalid extention for public key file: {}",
        ext.to_string_lossy()
      );
      return;
    }
  } else {
    pub_path.set_extension(PUB_EXT);
  }

  let (pub_k, sec_k) = qprov::generate_key_pairs();
  let key_file = File::create(key_path).expect("Failed to create private key file");
  bincode::serialize_into(key_file, &sec_k).expect("Failed to write private keys to file");
  let  pub_file = File::create(pub_path).expect("Failed to create public key file");
  bincode::serialize_into(pub_file, &pub_k).expect("Failed to write public keys to file");
  println!("Success!");
}

fn sign_certificate(
  mut req_path: PathBuf,
  mut issuer_chain: Option<PathBuf>,
  mut issuer_priv: PathBuf,
  mut cert_path: Option<PathBuf>,
) {
  if let Some(ext) = req_path.extension() {
    if ext != REQ_EXT {
      eprintln!(
        "Invalid extention for certificate signing request file: {}",
        ext.to_string_lossy()
      );
      return;
    }
  } else {
    req_path.set_extension(REQ_EXT);
  }
  let cert_path = cert_path.get_or_insert_with(|| {
    let mut cloned = req_path.clone();
    cloned.set_extension(CRT_EXT);
    cloned
  });
  if let Some(ext) = cert_path.extension() {
    if ext != CRT_EXT {
      eprintln!(
        "Invalid extention for certificate file: {}",
        ext.to_string_lossy()
      );
      return;
    }
  } else {
    cert_path.set_extension(CRT_EXT);
  }
  if let Some(issuer_chain) = issuer_chain.as_mut() {
    if let Some(ext) = issuer_chain.extension() {
      if ext != CHN_EXT {
        eprintln!(
          "Invalid extention for certificate chain file: {}",
          ext.to_string_lossy()
        );
        return;
      }
    } else {
      issuer_chain.set_extension(CHN_EXT);
    }
  }
  if let Some(ext) = issuer_priv.extension() {
    if ext != SEC_EXT {
      eprintln!(
        "Invalid extention for private key file: {}",
        ext.to_string_lossy()
      );
      return;
    }
  } else {
    issuer_priv.set_extension(SEC_EXT);
  }
  let req_file = File::open(req_path).expect("Failed to open cerificate signing request file");
  let  issuer_chain_file = issuer_chain.map(|path|File::open(path).expect("Failed to open CA certificate chain file"));
  let  issuer_priv_file = File::open(issuer_priv).expect("Failed to open CA private key file");
  let  output_file = File::create(cert_path).expect("Failed to create certificate file");
  let issuer_chain: Option<qprov::keys::CertificateChain> = issuer_chain_file.map(|file|bincode::deserialize_from(file).expect("Failed to read CA certificate chain from file"));
  let issuer_priv_key =
    bincode::deserialize_from(issuer_priv_file).expect("Failed to read CA private key from file");
  let cert_req: qprov::keys::CertificateRequest = bincode::deserialize_from(req_file)
    .expect("Failed to read certificate signing request from file");
  let issuer = match issuer_chain {
    Some(chain) => {
      chain.get_target().contents.owner.clone()
    },
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
  let cert = cert_req.sign(issuer, issuer_priv_key);

  bincode::serialize_into(output_file, &cert).expect("Failed to write certificate to file");
}

fn request_singing(mut pub_path: PathBuf, mut req_path: Option<PathBuf>) {
  if let Some(ext) = pub_path.extension() {
    if ext != PUB_EXT {
      eprintln!(
        "Invalid extention for public key file: {}",
        ext.to_string_lossy()
      );
      return;
    }
  } else {
    pub_path.set_extension(PUB_EXT);
  }
  let req_path = req_path.get_or_insert_with(|| {
    let mut cloned = pub_path.clone();
    cloned.set_extension(REQ_EXT);
    cloned
  });
  if let Some(ext) = req_path.extension() {
    if ext != REQ_EXT {
      eprintln!(
        "Invalid extention for certificate signing request file: {}",
        ext.to_string_lossy()
      );
      return;
    }
  } else {
    req_path.set_extension(REQ_EXT);
  }
  let pub_file = File::open(pub_path).expect("Failed to open public key file");
  let pub_keys = bincode::deserialize_from(pub_file).expect("Failed to read public key from file");
  let  req_file = File::create(req_path).expect("Failed to create cerificate signing request file");

  let mut line = String::new();
  println!("Enter certificate owner name: ");
  std::io::stdin().read_line(&mut line).unwrap();
  let Some(owner) = line.lines().next().map(str::to_owned) else {
    println!("Exitting!");
    return;
  };
  println!("Enter owner's alt names (comma separated): ");
  std::io::stdin().read_line(&mut line).unwrap();
  let Some(alt_names) = line.lines().next().map(str::to_owned) else {
    println!("Exitting!");
    return;
  };
  let request = qprov::keys::CertificateRequest::new(pub_keys, owner, alt_names);
  bincode::serialize_into(req_file, &request).expect("Failed to write certificate request to file");
}

fn chain(mut cert_path: PathBuf, mut input_chain: Option<PathBuf>, mut output_chain: Option<PathBuf>) {
  if let Some(ext) = cert_path.extension() {
    if ext != CRT_EXT {
      eprintln!(
        "Invalid extention for certificate file: {}",
        ext.to_string_lossy()
      );
      return;
    }
  } else {
    cert_path.set_extension(CRT_EXT);
  }
  if let Some(input_chain) = input_chain.as_mut() {
    if let Some(ext) = input_chain.extension() {
      if ext != CHN_EXT {
        eprintln!(
          "Invalid extention for certificate chain file: {}",
          ext.to_string_lossy()
        );
        return;
      }
    } else {
      input_chain.set_extension(CHN_EXT);
    }
  }
  let output_chain = output_chain.get_or_insert_with(|| {
    let mut cloned = cert_path.clone();
    cloned.set_extension(CHN_EXT);
    cloned
  });
  if let Some(ext) = output_chain.extension() {
    if ext != CHN_EXT {
      eprintln!(
        "Invalid extention for certificate chain file: {}",
        ext.to_string_lossy()
      );
      return;
    }
  } else {
    output_chain.set_extension(CHN_EXT);
  }
  let  cert_file = File::open(cert_path).expect("Failed to open certificate file");
  let  input_chain_file = input_chain.map(|path|File::open(path).expect("Failed to open parent certificate chain file"));
  let cert: qprov::Certificate = bincode::deserialize_from(cert_file).expect("Failed to read certificate from file");
  let input_chain: Option<qprov::keys::CertificateChain> = input_chain_file.map(|file|bincode::deserialize_from(file).expect("Failed to read parent certificate chain from file"));
  let output_file = File::create(output_chain).expect("Failed to create certificate chain file");
  let chain = match input_chain {
    Some(mut chain) => {
      if !chain.append(cert) {
        eprintln!("Failed to append certificate to chain, invalid signature");
        return;
      }
      chain
    }
    None => {
      let Some(chain) = qprov::keys::CertificateChain::root(cert) else {
        eprintln!("Failed to create chain. Certificate is not self-signed");
        return;
      };
      chain
    }
  };
  bincode::serialize_into(output_file, &chain).expect("Failed to write certificate chain to file");
  println!("Success!");
}

fn verify_certificate(mut cert_path: PathBuf, mut issuer_pub: PathBuf) {
  if let Some(ext) = cert_path.extension() {
    if ext != "cert" {
      eprintln!(
        "Invalid extention for certificate file: {}",
        ext.to_string_lossy()
      );
      return;
    }
  } else {
    cert_path.set_extension("cert");
  }
  if let Some(ext) = issuer_pub.extension() {
    if ext != "pub" {
      eprintln!(
        "Invalid extention for public key file: {}",
        ext.to_string_lossy()
      );
      return;
    }
  } else {
    issuer_pub.set_extension("pub");
  }
  let cert_file = File::open(cert_path).expect("Failed to open certificate file");
  let  issuer_pub_file = File::open(issuer_pub).expect("Failed to open CA public key file");
  let cert: qprov::Certificate =
    bincode::deserialize_from(cert_file).expect("Failed to read certificate from file");
  let pub_key: qprov::PubKeyPair =
    bincode::deserialize_from(issuer_pub_file).expect("Failed to read CA public key from file");
  let message = if cert.verify(&pub_key.sig_key) {
    "Certificate is valid"
  } else {
    "Invalid certificate"
  };
  println!("{}", message);
}

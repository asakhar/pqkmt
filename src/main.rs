use std::{fs::File, path::PathBuf};

use clap::Parser;
use qprov::serialization::{Deserializable, Serializable};

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
  Sign {
    #[arg()]
    pub_path: PathBuf,
    #[arg()]
    issuer_priv: PathBuf,
    #[arg()]
    cert_path: Option<PathBuf>,
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
        pub_path,
        cert_path,
        issuer_priv,
      } => sign_certificate(pub_path, cert_path, issuer_priv),
      Commands::Verify {
        cert_path,
        issuer_pub,
      } => verify_certificate(cert_path, issuer_pub),
    }
  }
}

fn generate_keys(mut key_path: PathBuf, mut pub_path: Option<PathBuf>) {
  if let Some(ext) = key_path.extension() {
    if ext != "key" {
      eprintln!(
        "Invalid extention for private key file: {}",
        ext.to_string_lossy()
      );
      return;
    }
  } else {
    key_path.set_extension("key");
  }
  let pub_path = pub_path.get_or_insert_with(|| {
    let mut cloned = key_path.clone();
    cloned.set_extension("pub");
    cloned
  });
  if let Some(ext) = pub_path.extension() {
    if ext != "pub" {
      eprintln!(
        "Invalid extention for public key file: {}",
        ext.to_string_lossy()
      );
      return;
    }
  } else {
    pub_path.set_extension("pub");
  }

  let (pub_k, sec_k) = qprov::generate_key_pairs();
  let mut key_file = File::create(key_path).expect("Failed to create private key file");
  sec_k
    .serialize(&mut key_file)
    .expect("Failed to write private keys to file");
  let mut pub_file = File::create(pub_path).expect("Failed to create public key file");
  pub_k
    .serialize(&mut pub_file)
    .expect("Failed to write public keys to file");
  println!("Success!");
}

fn sign_certificate(
  mut pub_path: PathBuf,
  mut cert_path: Option<PathBuf>,
  mut issuer_priv: PathBuf,
) {
  if let Some(ext) = pub_path.extension() {
    if ext != "pub" {
      eprintln!(
        "Invalid extention for public key file: {}",
        ext.to_string_lossy()
      );
      return;
    }
  } else {
    pub_path.set_extension("pub");
  }
  let cert_path = cert_path.get_or_insert_with(|| {
    let mut cloned = pub_path.clone();
    cloned.set_extension("cert");
    cloned
  });
  if let Some(ext) = cert_path.extension() {
    if ext != "cert" {
      eprintln!(
        "Invalid extention for public key file: {}",
        ext.to_string_lossy()
      );
      return;
    }
  } else {
    cert_path.set_extension("cert");
  }
  if let Some(ext) = issuer_priv.extension() {
    if ext != "key" {
      eprintln!(
        "Invalid extention for certificate authority's private key file: {}",
        ext.to_string_lossy()
      );
      return;
    }
  } else {
    issuer_priv.set_extension("key");
  }
  let mut pub_file = File::open(pub_path).expect("Failed to open public key file");
  let mut issuer_priv_file = File::open(issuer_priv).expect("Failed to open CA private key file");
  let mut output_file = File::create(cert_path).expect("Failed to create certificate file");
  let issuer_priv_key = qprov::SecKeyPair::deserialize(&mut issuer_priv_file)
    .expect("Failed to read CA private key from file");
  let pub_key =
    qprov::PubKeyPair::deserialize(&mut pub_file).expect("Failed to read public key from file");
  let mut line = String::new();
  println!("Enter certificate owner name: ");
  std::io::stdin().read_line(&mut line).unwrap();
  let Some(owner) = line.lines().next().map(str::to_owned) else {
    println!("Exitting!");
    return;
  };
  println!("Enter certificate issuer name: ");
  std::io::stdin().read_line(&mut line).unwrap();
  let Some(issuer) = line.lines().next().map(str::to_owned) else {
    println!("Exitting!");
    return;
  };
  println!("Enter owner's alt names (comma separated): ");
  std::io::stdin().read_line(&mut line).unwrap();
  let Some(alt_names) = line.lines().next().map(str::to_owned) else {
    println!("Exitting!");
    return;
  };
  let alt_names = alt_names.split(',').map(str::to_owned).collect();
  let cert = qprov::Certificate::create(pub_key, issuer, owner, alt_names, issuer_priv_key);
  cert
    .serialize(&mut output_file)
    .expect("Failed to write certificate to file");
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
  let mut cert_file = File::open(cert_path).expect("Failed to open certificate file");
  let mut issuer_pub_file = File::open(issuer_pub).expect("Failed to open CA public key file");
  let cert =
    qprov::Certificate::deserialize(&mut cert_file).expect("Failed to read certificate from file");
  let pub_key = qprov::PubKeyPair::deserialize(&mut issuer_pub_file)
    .expect("Failed to read CA public key from file");
  let message = if cert.verify(&pub_key) {
    "Certificate is valid"
  } else {
    "Invalid certificate"
  };
  println!("{}", message);
}

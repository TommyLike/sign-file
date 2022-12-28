use anyhow::Result;
use bincode::{config, Decode, Encode};
use clap::{Args, Parser, Subcommand};
use openssl::cms::{CMSOptions, CmsContentInfo};
use openssl::error::ErrorStack;
use openssl::pkey::PKey;
use openssl::x509::X509;
use std::fs;
use std::io::prelude::*;
use std::os::raw::{c_uchar, c_uint};

const PKEY_ID_PKCS7: c_uchar = 2;
const MAGIC_NUMBER: &str = "~Module signature appended~\n";

// Reference https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/tree/scripts/sign-file.c
#[derive(Encode, Decode, PartialEq, Debug)]
struct ModuleSignature {
    algo: c_uchar,       /* Public-key crypto algorithm [0] */
    hash: c_uchar,       /* Digest algorithm [0] */
    id_type: c_uchar,    /* Key identifier type [PKEY_ID_PKCS7] */
    signer_len: c_uchar, /* Length of signer's name [0] */
    key_id_len: c_uchar, /* Length of key identifier [0] */
    _pad: [c_uchar; 3],
    sig_len: c_uint, /* Length of signature data */
}

impl ModuleSignature {
    fn new(length: c_uint) -> ModuleSignature {
        ModuleSignature {
            algo: 0,
            hash: 0,
            id_type: PKEY_ID_PKCS7,
            signer_len: 0,
            key_id_len: 0,
            _pad: [0, 0, 0],
            sig_len: length,
        }
    }
}

#[derive(Parser)]
#[command(name = "sign-file")]
#[command(author = "TommyLike <tommylikehu@gmail.com>")]
#[command(version = "1.0")]
#[command(about = "Command to sign kernel module file with x509 certificate", long_about = None)]
struct SignCommand {
    #[arg(long)]
    debug: bool,
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    #[command(about = "Sign ko file as well as generate detached signature file (*.p7s)", long_about = None)]
    Produce(CommandProduce),
    #[command(about = "Sign ko file with only generate detached signature file (*.p7s)", long_about = None)]
    Detach(CommandDetach),
    #[command(about = "Append raw signature to ko file", long_about = None)]
    Raw(CommandRaw),
}

#[derive(Args)]
struct CommandProduce {
    #[arg(help = "x509 key file")]
    key: String,
    #[arg(help = "x509 certificate file")]
    cert: String,
    #[arg(help = "kernel module file to be signed")]
    module: String,
    #[arg(help = "password for private key", env = "KBUILD_SIGN_PIN")]
    password: Option<String>,
}

#[derive(Args)]
struct CommandDetach {
    #[arg(help = "x509 key file")]
    key: String,
    #[arg(help = "x509 certificate file")]
    cert: String,
    #[arg(help = "kernel module file to be signed")]
    module: String,
    #[arg(help = "password for private key", env = "KBUILD_SIGN_PIN")]
    password: Option<String>,
}

#[derive(Args)]
struct CommandRaw {
    #[arg(help = "raw signature file")]
    raw: String,
    #[arg(help = "kernel module file to be signed")]
    module: String,
}

fn sign(
    private_key: &[u8],
    certificate: &[u8],
    content: &[u8],
) -> Result<CmsContentInfo, ErrorStack> {
    let private_key = PKey::private_key_from_pem(private_key)?;
    let certificate = X509::from_der(certificate)?;
    //cms option reference: https://man.openbsd.org/CMS_sign.3
    let cms_signature = CmsContentInfo::sign(
        Some(&certificate),
        Some(&private_key),
        None,
        Some(content),
        CMSOptions::DETACHED
            | CMSOptions::CMS_NOCERTS
            | CMSOptions::BINARY
            | CMSOptions::NOSMIMECAP,
    )?;
    Ok(cms_signature)
}

fn generate_detached_signature(module: &str, signature: &[u8]) -> Result<()> {
    let mut buffer = fs::File::create(format!("{}.p7s", module))?;
    buffer.write_all(signature)?;
    Ok(())
}

fn create_inline_signature(module: &str, signature: &[u8]) -> Result<()> {
    let mut signed = fs::File::create(format!("{}.~signed~", module))?;
    signed.write_all(&fs::read(module)?)?;
    signed.write_all(signature)?;
    let sig_struct = ModuleSignature::new(signature.len() as c_uint);
    signed.write_all(&bincode::encode_to_vec(
        &sig_struct,
        config::standard()
            .skip_fixed_array_length()
            .with_fixed_int_encoding()
            .with_big_endian(),
    )?)?;
    signed.write_all(MAGIC_NUMBER.as_bytes())?;
    fs::rename(format!("{}.~signed~", module), module)?;
    Ok(())
}

fn main() -> Result<()> {
    match SignCommand::parse().command {
        Some(Commands::Produce(produce_command)) => {
            let private_key = fs::read(produce_command.key)?;
            let cert = fs::read(produce_command.cert)?;
            let module = fs::read(&produce_command.module)?;
            let cms = sign(&private_key, &cert, &module)?.to_der()?;
            generate_detached_signature(produce_command.module.as_str(), &cms)?;
            create_inline_signature(produce_command.module.as_str(), &cms)?;
        }
        Some(Commands::Detach(detach_command)) => {
            let private_key = fs::read(detach_command.key)?;
            let cert = fs::read(detach_command.cert)?;
            let module = fs::read(&detach_command.module)?;
            let cms = sign(&private_key, &cert, &module)?.to_der()?;
            generate_detached_signature(detach_command.module.as_str(), &cms)?;
        }
        Some(Commands::Raw(raw_command)) => {
            let raw_sig = fs::read(&raw_command.raw)?;
            create_inline_signature(raw_command.module.as_str(), &raw_sig)?;
        }
        None => {
            eprintln!("invalid command, use --help for detail")
        }
    }
    Ok(())
}

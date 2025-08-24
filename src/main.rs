//! WalletGen: Generate BTC/ETH wallets (mainnet/testnet), optionally encrypt keys,
//! export to JSON, render QR codes, and decrypt later.
//! 
//! Highlights:
//! - Keys generated locally with secp256k1 (same curve BTC/ETH use).
//! - BTC P2PKH (Base58Check) address + WIF (compressed).
//! - ETH address per EIP-55 checksum from Keccak(pubkey[1..]) last 20 bytes.
//! - Optional AES-256-GCM encryption with PBKDF2-SHA256 (salt + iterations).
//! - Minimal dependencies, terminal QR rendering for quick transfer/printing.

use clap::{Parser, Subcommand};
use rand::rngs::OsRng;
use rand::RngCore;
use secp256k1::{PublicKey, Secp256k1, SecretKey};

use sha2::{Digest as Sha2Digest, Sha256};
use ripemd::Ripemd160;
use tiny_keccak::{Hasher, Keccak};

use aes_gcm::{aead::{Aead, KeyInit}, Aes256Gcm, Nonce};
use pbkdf2::pbkdf2_hmac;
use base64::{engine::general_purpose, Engine as _};

use std::fs::File;
use std::io::BufReader;
use std::path::PathBuf;

use serde::{Serialize, Deserialize};

use qrcode::{QrCode, render::unicode};

/// CLI entry: `walletgen gen ...` or `walletgen decrypt ...`
#[derive(Parser, Debug)]
#[command(name="walletgen", about="Generate and manage BTC/ETH wallets", version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

/// Subcommands: generate new wallets or decrypt a saved JSON.
#[derive(Subcommand, Debug)]
enum Commands {
    /// Generate new wallets (BTC/ETH), with optional encryption/QR/JSON.
    Gen(GenArgs),
    /// Decrypt encrypted fields from a JSON produced by `gen --encrypt --out`.
    Decrypt(DecryptArgs),
}

/// Options for wallet generation.
#[derive(Parser, Debug)]
struct GenArgs {
    /// Which coin to generate (btc | eth).
    #[arg(long, default_value = "btc")]
    coin: String,

    /// How many wallets to produce in a single run.
    #[arg(long, short = 'c', default_value_t = 1)]
    count: usize,

    /// Use Bitcoin testnet prefixes for address and WIF (ETH has same address format across networks).
    #[arg(long)]
    testnet: bool,

    /// Encrypt private material (BTC WIF or ETH priv hex) with AES-256-GCM (PBKDF2-SHA256).
    #[arg(long)]
    encrypt: bool,

    /// Save output to a JSON file (pretty-printed).
    #[arg(long)]
    out: Option<PathBuf>,

    /// Print terminal QR codes (address + secret) for quick scan/backup.
    #[arg(long)]
    qr: bool,
}

/// Options for decrypting a previously saved JSON file.
#[derive(Parser, Debug)]
struct DecryptArgs {
    /// File produced by `gen --out`.
    #[arg(long)]
    input: PathBuf,

    /// Also show QR codes for decrypted values.
    #[arg(long)]
    qr: bool,
}

/// One wallet entry in JSON output.
#[derive(Serialize, Deserialize, Clone)]
struct WalletOut {
    coin: String,          // "btc" | "eth"
    network: String,       // "mainnet" | "testnet"
    address: String,       // BTC Base58 P2PKH or ETH 0x-checksummed address

    // Plaintext secrets (present only when --encrypt is NOT used):
    #[serde(skip_serializing_if = "Option::is_none")]
    wif: Option<String>,       // BTC secret (WIF, compressed)
    #[serde(skip_serializing_if = "Option::is_none")]
    priv_hex: Option<String>,  // ETH secret (0x-less hex)

    // Encrypted secrets (present only when --encrypt IS used):
    #[serde(skip_serializing_if = "Option::is_none")]
    wif_encrypted: Option<Encrypted>,
    #[serde(skip_serializing_if = "Option::is_none")]
    priv_hex_encrypted: Option<Encrypted>,
}

/// Symmetric encryption envelope for a single secret.
/// Stored with parameters needed for PBKDF2/AES-GCM decryption.
#[derive(Serialize, Deserialize, Clone)]
struct Encrypted {
    alg: String,       // "AES-256-GCM"
    kdf: String,       // "PBKDF2-SHA256"
    iterations: u32,   // PBKDF2 iterations
    salt_b64: String,  // 16-byte random salt (base64)
    nonce_b64: String, // 12-byte random GCM nonce (base64)
    ciphertext_b64: String, // AEAD ciphertext+tag (base64)
}

fn main() {
    let cli = Cli::parse();
    match cli.command {
        Commands::Gen(args) => run_gen(args),
        Commands::Decrypt(args) => run_decrypt(args),
    }
}

/* ===========================
   gen (generate) subcommand
   =========================== */

fn run_gen(args: GenArgs) {
    let coin = args.coin.to_lowercase();
    let count = args.count.max(1);

    // If requested, capture a passphrase once; used for all secrets in this run.
    let passphrase = if args.encrypt {
        let p1 = rpassword::prompt_password("Enter passphrase: ").expect("read passphrase");
        let p2 = rpassword::prompt_password("Confirm passphrase: ").expect("read passphrase");
        if p1 != p2 {
            eprintln!("Passphrases do not match.");
            std::process::exit(1);
        }
        Some(p1)
    } else {
        None
    };

    let mut results: Vec<WalletOut> = Vec::with_capacity(count);

    // One Secp256k1 context + OS RNG reused; generate per-wallet keypairs.
    let secp = Secp256k1::new();
    let mut rng = OsRng;

    for _ in 0..count {
        let (sk, pk) = secp.generate_keypair(&mut rng);

        match coin.as_str() {
            "btc" | "bitcoin" => {
                // Legacy P2PKH address per Base58Check: version || HASH160(pubkey) || checksum.
                let address = btc_address(&pk, args.testnet);
                let wif = btc_wif(&sk, args.testnet);

                println!("BTC {}  {}", net_name(args.testnet), address);
                if args.qr { print_qr("Address", &address); }

                if let Some(pass) = &passphrase {
                    // Store encrypted only; avoid plaintext leakage in JSON.
                    let enc = encrypt_bytes(pass, wif.as_bytes());
                    println!("  (WIF encrypted: AES-256-GCM, PBKDF2)");
                    results.push(WalletOut {
                        coin: "btc".into(),
                        network: net_name(args.testnet).into(),
                        address,
                        wif: None,
                        priv_hex: None,
                        wif_encrypted: Some(enc),
                        priv_hex_encrypted: None,
                    });
                } else {
                    println!("  WIF: {}", wif);
                    if args.qr { print_qr("WIF", &wif); }
                    results.push(WalletOut {
                        coin: "btc".into(),
                        network: net_name(args.testnet).into(),
                        address,
                        wif: Some(wif),
                        priv_hex: None,
                        wif_encrypted: None,
                        priv_hex_encrypted: None,
                    });
                }
            }

            "eth" | "ethereum" => {
                // ETH address is last 20 bytes of Keccak256(uncompressed_pubkey[1..]),
                // then EIP-55 checksum-cased (no network prefix here).
                let (addr, priv_hex) = eth_address_and_priv_hex(&pk, &sk);
                println!("ETH mainnet  {}", addr);
                if args.qr { print_qr("Address", &addr); }

                if let Some(pass) = &passphrase {
                    let enc = encrypt_bytes(pass, priv_hex.as_bytes());
                    println!("  (priv key encrypted: AES-256-GCM, PBKDF2)");
                    results.push(WalletOut {
                        coin: "eth".into(),
                        network: "mainnet".into(),
                        address: addr,
                        wif: None,
                        priv_hex: None,
                        wif_encrypted: None,
                        priv_hex_encrypted: Some(enc),
                    });
                } else {
                    println!("  priv(hex): 0x{}", priv_hex);
                    if args.qr { print_qr("Priv (hex)", &format!("0x{}", priv_hex)); }
                    results.push(WalletOut {
                        coin: "eth".into(),
                        network: "mainnet".into(),
                        address: addr,
                        wif: None,
                        priv_hex: Some(priv_hex),
                        wif_encrypted: None,
                        priv_hex_encrypted: None,
                    });
                }
            }

            _ => {
                eprintln!("Unknown coin: {} (use --coin btc|eth)", coin);
                std::process::exit(1);
            }
        }
    }

    // Optional pretty JSON output for backups/automation.
    if let Some(path) = args.out {
        let file = File::create(&path).expect("create output file");
        serde_json::to_writer_pretty(file, &results).expect("write json");
        println!("Saved {}", path.display());
    }
}

/* ===========================
   decrypt subcommand
   =========================== */

fn run_decrypt(args: DecryptArgs) {
    // Load JSON exported by `gen --out`.
    let file = File::open(&args.input).expect("open input JSON");
    let reader = BufReader::new(file);
    let wallets: Vec<WalletOut> = serde_json::from_reader(reader).expect("parse JSON");

    // One passphrase used to try all encrypted entries (common workflow).
    let pass = rpassword::prompt_password("Enter passphrase to decrypt: ").expect("read passphrase");

    for (i, w) in wallets.iter().enumerate() {
        println!("--- [{}] {} {} ---", i + 1, w.coin.to_uppercase(), w.network);
        println!("Address: {}", w.address);

        match w.coin.as_str() {
            "btc" => {
                if let Some(enc) = &w.wif_encrypted {
                    // AEAD verify + decrypt; wrong passphrase triggers error.
                    let wif = decrypt_bytes(&pass, enc).expect("decrypt WIF");
                    println!("WIF: {}", wif);
                    if args.qr { print_qr("Address", &w.address); print_qr("WIF", &wif); }
                } else if let Some(wif) = &w.wif {
                    println!("WIF: {}", wif);
                    if args.qr { print_qr("Address", &w.address); print_qr("WIF", wif); }
                } else {
                    println!("(no WIF present)");
                }
            }
            "eth" => {
                if let Some(enc) = &w.priv_hex_encrypted {
                    let priv_hex = decrypt_bytes(&pass, enc).expect("decrypt priv hex");
                    println!("Priv (hex): {}", priv_hex);
                    if args.qr { print_qr("Address", &w.address); print_qr("Priv (hex)", &priv_hex); }
                } else if let Some(priv_hex) = &w.priv_hex {
                    println!("Priv (hex): {}", priv_hex);
                    if args.qr { print_qr("Address", &w.address); print_qr("Priv (hex)", priv_hex); }
                } else {
                    println!("(no priv hex present)");
                }
            }
            _ => println!("(unknown coin {})", w.coin),
        }
    }
}

/* ===========================
   BTC helpers
   =========================== */

/// Human-readable network name.
fn net_name(testnet: bool) -> &'static str {
    if testnet { "testnet" } else { "mainnet" }
}

/// Build a legacy P2PKH Base58Check address:
/// version (00 mainnet / 6f testnet) || RIPEMD160(SHA256(pubkey_compressed)) || checksum(4).
fn btc_address(pk: &PublicKey, testnet: bool) -> String {
    let compressed = pk.serialize(); // 33 bytes
    let sha = Sha256::digest(&compressed);
    let ripe = Ripemd160::digest(&sha);

    let version = if testnet { 0x6f } else { 0x00 };
    let mut payload = Vec::with_capacity(1 + 20);
    payload.push(version);
    payload.extend_from_slice(&ripe);

    let checksum = double_sha256_first4(&payload);
    let mut full = payload;
    full.extend_from_slice(&checksum);
    bs58::encode(full).into_string()
}

/// Export private key as WIF (Base58Check):
/// prefix (0x80 mainnet / 0xEF testnet) || 32-byte priv || 0x01 (compressed) || checksum(4).
fn btc_wif(sk: &SecretKey, testnet: bool) -> String {
    let prefix = if testnet { 0xEF } else { 0x80 };
    let mut payload = Vec::with_capacity(1 + 32 + 1);
    payload.push(prefix);
    payload.extend_from_slice(&sk.secret_bytes());
    payload.push(0x01); // indicates compressed pubkey
    let checksum = double_sha256_first4(&payload);
    let mut full = payload;
    full.extend_from_slice(&checksum);
    bs58::encode(full).into_string()
}

/// First 4 bytes of double-SHA256, as used by Base58Check.
fn double_sha256_first4(data: &[u8]) -> [u8; 4] {
    let first = Sha256::digest(data);
    let second = Sha256::digest(&first);
    [second[0], second[1], second[2], second[3]]
}

/* ===========================
   ETH helpers
   =========================== */

/// Return (EIP-55 address, private_hex_without_0x).
/// ETH address = last 20 bytes of Keccak256(uncompressed_pubkey[1..]) with EIP-55 checksum casing.
fn eth_address_and_priv_hex(pk: &PublicKey, sk: &SecretKey) -> (String, String) {
    let uncompressed = pk.serialize_uncompressed(); // 65 bytes: 0x04 || X(32) || Y(32)

    // Hash the 64 bytes (skip 0x04)
    let hash = keccak256(&uncompressed[1..]);

    // Address: rightmost 20 bytes of 32-byte Keccak digest; then EIP-55 checksum-case.
    let addr_bytes = &hash[12..];
    let lower = hex::encode(addr_bytes);
    let checksummed = to_eip55_checksum(&lower);

    let priv_hex = hex::encode(sk.secret_bytes());
    (format!("0x{}", checksummed), priv_hex)
}

/// EIP-55 checksum casing: uppercase letters determined by Keccak(address_lower_hex).
fn to_eip55_checksum(lower_no_prefix: &str) -> String {
    let hash = keccak256(lower_no_prefix.as_bytes());
    let mut out = String::with_capacity(40);
    for (i, c) in lower_no_prefix.chars().enumerate() {
        if c.is_ascii_hexdigit() && c.is_ascii_alphabetic() {
            let byte = hash[i / 2];
            let nibble = if i % 2 == 0 { byte >> 4 } else { byte & 0x0f };
            out.push(if nibble >= 8 { c.to_ascii_uppercase() } else { c });
        } else {
            out.push(c);
        }
    }
    out
}

/* ===========================
   Keccak helper
   =========================== */

/// Minimal Keccak-256 helper (tiny-keccak) returning a 32-byte array.
fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak::v256();
    let mut out = [0u8; 32];
    hasher.update(data);
    hasher.finalize(&mut out);
    out
}

/* ===========================
   Encryption helpers
   =========================== */

/// Encrypt `plaintext` with AES-256-GCM. Key is derived from the passphrase using PBKDF2-SHA256.
/// We store all parameters needed for decryption alongside the ciphertext.
fn encrypt_bytes(passphrase: &str, plaintext: &[u8]) -> Encrypted {
    // Random salt (PBKDF2) and nonce (GCM) per secret.
    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);
    let iterations: u32 = 200_000; // increase for higher security; trade-off with speed.

    // Derive 32-byte key from passphrase.
    let mut key = [0u8; 32];
    pbkdf2_hmac::<Sha256>(passphrase.as_bytes(), &salt, iterations, &mut key);

    // Encrypt with AES-256-GCM (12-byte nonce).
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let cipher = Aes256Gcm::new_from_slice(&key).expect("cipher");
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher.encrypt(nonce, plaintext).expect("encryption failure");

    Encrypted {
        alg: "AES-256-GCM".to_string(),
        kdf: "PBKDF2-SHA256".to_string(),
        iterations,
        salt_b64: general_purpose::STANDARD.encode(salt),
        nonce_b64: general_purpose::STANDARD.encode(nonce_bytes),
        ciphertext_b64: general_purpose::STANDARD.encode(ciphertext),
    }
}

/// Decrypt using stored parameters. Returns UTF-8 string (WIF or hex).
fn decrypt_bytes(passphrase: &str, enc: &Encrypted) -> Result<String, String> {
    if enc.alg != "AES-256-GCM" || enc.kdf != "PBKDF2-SHA256" {
        return Err("Unsupported alg/kdf".into());
    }

    let salt = general_purpose::STANDARD
        .decode(&enc.salt_b64)
        .map_err(|_| "bad salt b64")?;
    let nonce = general_purpose::STANDARD
        .decode(&enc.nonce_b64)
        .map_err(|_| "bad nonce b64")?;
    let ciphertext = general_purpose::STANDARD
        .decode(&enc.ciphertext_b64)
        .map_err(|_| "bad ciphertext b64")?;

    let mut key = [0u8; 32];
    pbkdf2_hmac::<Sha256>(passphrase.as_bytes(), &salt, enc.iterations, &mut key);

    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|_| "cipher init")?;
    let nonce = Nonce::from_slice(&nonce);
    let plaintext = cipher
        .decrypt(nonce, ciphertext.as_ref())
        .map_err(|_| "decrypt failure (wrong passphrase?)")?;

    String::from_utf8(plaintext).map_err(|_| "plaintext not utf-8".into())
}

/* ===========================
   QR helper (unicode render)
   =========================== */

/// Render a compact Unicode QR in the terminal for fast scanning with a wallet app.
/// This is purely for convenience; avoid displaying secrets on shared screens.
fn print_qr(label: &str, data: &str) {
    let code = match QrCode::new(data.as_bytes()) {
        Ok(c) => c,
        Err(_) => { eprintln!("(QR) failed to encode data for {}", label); return; }
    };
    let string = code
        .render::<unicode::Dense1x2>()
        .quiet_zone(true)
        .build();
    println!("--- QR: {} ---", label);
    println!("{}", string);
}
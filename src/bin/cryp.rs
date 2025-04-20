use std::env;
use std::fs;
use std::process;
use openssl::symm::{Cipher, Crypter, Mode};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use openssl::rand::rand_bytes;

type HmacSha256 = Hmac<Sha256>;

fn encrypt_data(cipher: Cipher, key: &[u8], iv: &[u8], data: &[u8]) -> Result<Vec<u8>, openssl::error::ErrorStack> {
    let mut crypter = Crypter::new(cipher, Mode::Encrypt, key, Some(iv))?;
    let mut out = vec![0; data.len() + cipher.block_size()];
    let count = crypter.update(data, &mut out)?;
    let rest = crypter.finalize(&mut out[count..])?;
    out.truncate(count + rest);
    Ok(out)
}

fn decrypt_data(cipher: Cipher, key: &[u8], iv: &[u8], data: &[u8]) -> Result<Vec<u8>, openssl::error::ErrorStack> {
    let mut crypter = Crypter::new(cipher, Mode::Decrypt, key, Some(iv))?;
    let mut out = vec![0; data.len() + cipher.block_size()];
    let count = crypter.update(data, &mut out)?;
    let rest = crypter.finalize(&mut out[count..])?;
    out.truncate(count + rest);
    Ok(out)
}

fn main() {
    let args: Vec<String> = env::args().collect();
    
    if args.len() != 9 {
        println!("ERROR");
        process::exit(2);
    }

    let mode = &args[1];
    let mut key_file = "";
    let mut input_file = "";
    let mut output_file = "";
    let mut tag_file = "";

    // Parse arguments
    let mut i = 2;
    while i < args.len() {
        match args[i].as_str() {
            "-key" => key_file = &args[i + 1],
            "-in" => input_file = &args[i + 1],
            "-out" => output_file = &args[i + 1],
            "-tag" => tag_file = &args[i + 1],
            _ => {
                println!("ERROR");
                process::exit(2);
            }
        }
        i += 2;
    }

    // Read key
    let key = match fs::read_to_string(key_file) {
        Ok(k) => k.trim().as_bytes().to_vec(),
        Err(_) => {
            println!("ERROR");
            process::exit(2);
        }
    };

    // Key must be exactly 32 bytes for AES-256
    let mut real_key = [0u8; 32];
    let key_bytes = key.as_slice();
    let len = std::cmp::min(key_bytes.len(), 32);
    real_key[..len].copy_from_slice(&key_bytes[..len]);

    // Read input file
    let input_data = match fs::read(input_file) {
        Ok(data) => data,
        Err(_) => {
            println!("ERROR");
            process::exit(2);
        }
    };

    match mode.as_str() {
        "enc" => {
            // Generate random IV
            let mut iv = vec![0u8; 16];
            if let Err(_) = rand_bytes(&mut iv) {
                println!("ERROR");
                process::exit(2);
            }

            // Encrypt data
            let cipher = Cipher::aes_256_cbc();
            let encrypted = match encrypt_data(cipher, &real_key, &iv, &input_data) {
                Ok(data) => data,
                Err(_) => {
                    println!("ERROR");
                    process::exit(2);
                }
            };

            // Combine IV and encrypted data
            let mut final_data = iv.clone();
            final_data.extend(&encrypted);

            // Create HMAC
            let mut mac = HmacSha256::new_from_slice(&real_key)
                .expect("HMAC can take key of any size");
            mac.update(&final_data);
            let result = mac.finalize();
            let tag = result.into_bytes();

            // Write encrypted data and tag
            if let Err(_) = fs::write(output_file, final_data) {
                println!("ERROR");
                process::exit(2);
            }
            if let Err(_) = fs::write(tag_file, tag) {
                println!("ERROR");
                process::exit(2);
            }
        }
        "dec" => {
            // Read tag file
            let tag_data = match fs::read(tag_file) {
                Ok(data) => data,
                Err(_) => {
                    println!("ERROR");
                    process::exit(2);
                }
            };

            if input_data.len() < 16 {
                println!("ERROR");
                process::exit(2);
            }

            // Split IV and ciphertext
            let (iv, encrypted) = input_data.split_at(16);

            // Verify HMAC
            let mut mac = HmacSha256::new_from_slice(&real_key)
                .expect("HMAC can take key of any size");
            mac.update(&input_data);
            if let Err(_) = mac.verify_slice(&tag_data) {
                println!("VERIFICATION FAILURE");
                process::exit(1);
            }

            // Decrypt data
            let cipher = Cipher::aes_256_cbc();
            let decrypted = match decrypt_data(cipher, &real_key, iv, encrypted) {
                Ok(data) => data,
                Err(_) => {
                    println!("ERROR");
                    process::exit(2);
                }
            };

            // Write decrypted data
            if let Err(_) = fs::write(output_file, decrypted) {
                println!("ERROR");
                process::exit(2);
            }
        }
        _ => {
            println!("ERROR");
            process::exit(2);
        }
    }
} 
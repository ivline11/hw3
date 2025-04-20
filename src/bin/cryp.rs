// src/bin/cryp.rs

use openssl::symm::{Cipher, Crypter, Mode};
use openssl::base64::{encode_block, decode_block};
use sha2::{Digest, Sha256};
use hmac::{Hmac, Mac};
use std::{env, fs, str};

type HmacSha256 = Hmac<Sha256>;

fn encrypt(data: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>, String> {
    let cipher = Cipher::aes_256_cbc();
    let mut c = Crypter::new(cipher, Mode::Encrypt, key, Some(iv))
        .map_err(|e| e.to_string())?;
    let mut out = vec![0; data.len() + cipher.block_size()];
    let cnt = c.update(data, &mut out).map_err(|e| e.to_string())?;
    let rest = c.finalize(&mut out[cnt..]).map_err(|e| e.to_string())?;
    out.truncate(cnt + rest);
    Ok(out)
}

fn decrypt(data: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>, String> {
    let cipher = Cipher::aes_256_cbc();
    let mut c = Crypter::new(cipher, Mode::Decrypt, key, Some(iv))
        .map_err(|e| e.to_string())?;
    let mut out = vec![0; data.len() + cipher.block_size()];
    let cnt = c.update(data, &mut out).map_err(|e| e.to_string())?;
    let rest = c.finalize(&mut out[cnt..]).map_err(|e| e.to_string())?;
    out.truncate(cnt + rest);
    Ok(out)
}

fn hmac_tag(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC key error");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

fn verify_tag(key: &[u8], data: &[u8], tag: &[u8]) -> bool {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC key error");
    mac.update(data);
    mac.verify_slice(tag).is_ok()
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 9 {
        eprintln!("ERROR");
        std::process::exit(2);
    }
    let mode = args[1].as_str(); // "enc" or "dec"

    // flag 기반 파싱
    let mut key_path = None;
    let mut in_path  = None;
    let mut out_path = None;
    let mut tag_path = None;
    let mut i = 2;
    while i + 1 < args.len() {
        match args[i].as_str() {
            "-key" => { key_path = Some(args[i+1].as_str()); }
            "-in"  => { in_path  = Some(args[i+1].as_str()); }
            "-out" => { out_path = Some(args[i+1].as_str()); }
            "-tag" => { tag_path = Some(args[i+1].as_str()); }
            _ => {
                eprintln!("ERROR");
                std::process::exit(2);
            }
        }
        i += 2;
    }
    let key_path = key_path.unwrap_or_else(|| { eprintln!("ERROR"); std::process::exit(2) });
    let in_path  = in_path .unwrap_or_else(|| { eprintln!("ERROR"); std::process::exit(2) });
    let out_path = out_path.unwrap_or_else(|| { eprintln!("ERROR"); std::process::exit(2) });
    let tag_path = tag_path.unwrap_or_else(|| { eprintln!("ERROR"); std::process::exit(2) });

    // shared.key 파일 → SHA256 해시 → AES 키(32B), IV(16B), HMAC 키(32B)
    let key_file = fs::read(key_path).unwrap_or_else(|_| { eprintln!("ERROR"); std::process::exit(2) });
    let key_hash = Sha256::digest(&key_file);
    let aes_key = &key_hash[..];      // 32 bytes
    let iv      = &key_hash[..16];    // first 16 bytes

    match mode {
        "enc" => {
            // 평문은 바이너리 그대로 읽기
            let plain = fs::read(in_path).unwrap_or_else(|_| { eprintln!("ERROR"); std::process::exit(2) });
            let cipher = encrypt(&plain, aes_key, iv)
                .unwrap_or_else(|_| { eprintln!("ERROR"); std::process::exit(2) });
            let tag = hmac_tag(&key_hash, &cipher);

            // base64 인코딩 후 파일에 저장
            let c_b64 = encode_block(&cipher);
            let t_b64 = encode_block(&tag);
            fs::write(out_path, c_b64).unwrap_or_else(|_| { eprintln!("ERROR"); std::process::exit(2) });
            fs::write(tag_path, t_b64).unwrap_or_else(|_| { eprintln!("ERROR"); std::process::exit(2) });

            std::process::exit(0);
        }

        "dec" => {
            // 암호문과 태그는 base64 텍스트이므로 문자열로 읽고 trim()
            let c_b64 = fs::read_to_string(in_path).unwrap_or_else(|_| { eprintln!("ERROR"); std::process::exit(2) });
            let cipher = decode_block(c_b64.trim())
                .map_err(|_| ()).unwrap_or_else(|_| { eprintln!("ERROR"); std::process::exit(2) });

            let t_b64 = fs::read_to_string(tag_path).unwrap_or_else(|_| { eprintln!("ERROR"); std::process::exit(2) });
            let tag = decode_block(t_b64.trim())
                .map_err(|_| ()).unwrap_or_else(|_| { eprintln!("ERROR"); std::process::exit(2) });

            // 인증
            if !verify_tag(&key_hash, &cipher, &tag) {
                println!("VERIFICATION FAILURE");
                std::process::exit(1);
            }

            // 복호화
            let plain = decrypt(&cipher, aes_key, iv)
                .unwrap_or_else(|_| { eprintln!("ERROR"); std::process::exit(2) });
            fs::write(out_path, plain).unwrap_or_else(|_| { eprintln!("ERROR"); std::process::exit(2) });

            std::process::exit(0);
        }

        _ => {
            eprintln!("ERROR");
            std::process::exit(2);
        }
    }
}

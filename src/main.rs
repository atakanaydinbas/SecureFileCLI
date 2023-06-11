
use std::{env, fs};
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;
use anyhow::anyhow;
use chacha20poly1305::KeyInit;
use chacha20poly1305::{
    aead::{stream},
    XChaCha20Poly1305,
};
use rand::{rngs::OsRng, RngCore};

use zeroize::Zeroize;


static encrypt_sign: &[u8] = "atakan_aydinbas".as_bytes();

const salt: [u8; 32] = [0u8; 32];
const nonce: [u8; 19] = [0u8; 19];

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 5 {
        println!("Usage: SecureFile <command> <file_path> <password> <algorithm>");
        println!("Commands: encrypt, decrypt");
        println!("Algorithms: xor, aead ");

        return;
    }
    let command = &args[1];
    let file_path = Path::new(&args[2]);
    let file_aead = &args[2];
    let password = &args[3];
    let algorithm = &args[4];
    // Dosya yolu komut satırından alınır
    let b = file_path.exists();
    if !b {
        println!("File not found");
        return;
    }
    match algorithm.as_str(){
        "xor" => {  
             // Dosya okunur
            let mut file = match File::open(&file_path) {
                Err(why) => panic!("Cannot opened file {}: {}", file_path.display(), why),
                Ok(file) => file,
            };

            // Dosya verileri okunur
            let mut data = Vec::new();
            match file.read_to_end(&mut data) {
                Err(why) => panic!("Cannot opened file {}: {}", file_path.display(), why),
                Ok(_) => println!("{} File read", file_path.display()),
            }
            match command.as_str() {
                "encrypt" => {
                    for i in 0..15 {
                        if data[data.len()-1-i] == encrypt_sign[14-i] {
                            println!("File is already encrypted");
                            return;
                        }
                    }
                    let encrypted_data = encrypt_data(&data, &password.trim());

                    // Şifreli veriler dosyaya yazılır
                    let mut encrypted_file = match File::create(&file_path) {
                        Err(why) => panic!("Cannot created encrypted file {}: {}", file_path.display(), why),
                        Ok(file) => file,
                    };
                    match encrypted_file.write_all(&encrypted_data) {
                        Err(why) => panic!("Data cannot written {}: {}", file_path.display(), why),
                        Ok(_) => println!("{} file encrypted", file_path.display()),
                    }
                }
                "decrypt" => {
                    let decrypted_data = decrypt_data(&data, &password.trim());
                    let mut decrypted_file = match File::create(&file_path) {
                        Err(why) => panic!("Cannot created encrypted file {}: {}", file_path.display(), why),
                        Ok(file) => file,
                    };
                    match decrypted_file.write_all(&decrypted_data) {
                        Err(why) => panic!("Data cannot written {}: {}", file_path.display(), why),
                        Ok(_) => println!("{} file decrypted", file_path.display()),
                    }
                }
                _ => {
                    println!("Invalid command. Usage: file-encrypt <command> <file_path> <password>");
                    println!("Commands: encrypt, decrypt");
                }
            }
    
        }
        "aead" =>{
            match command.as_str(){
                "encrypt" => {
                    let dist = file_aead.clone() + ".encrypted";
                    encrypt_file_aead(&file_aead, &dist, &password);
                    println!("File successfully encrypted")
                }
                "decrypt" => {
                    let dist = file_aead.strip_suffix(".encrypted").unwrap().to_string();
                    decrypt_file_aead(&file_aead, &dist, &password);
                    println!("File successfully decrypted")

                }
                _ => {
                    println!("Invalid command. Usage: file-encrypt <command> <file_path> <password>");
                    println!("Commands: encrypt, decrypt");
                }
            }

        }
         _ => {
        println!("Invalid algorithm. Usage: file-encrypt <command> <file_path> <password>");
        println!("Algorithms: xor, aead");

    }
        }

}

fn encrypt_data(data: &[u8], password: &str) -> Vec<u8> {
    // Şifreleme algoritması olarak XOR kullanılır
    //if last byte is 0x45, it is already encrypted file

    let mut encrypted_data = Vec::with_capacity(data.len());
    let password_bytes = password.bytes().cycle();
    for (byte, password_byte) in data.iter().zip(password_bytes) {
        encrypted_data.push(byte ^ password_byte);
    }
    for i in encrypt_sign.iter() {
        encrypted_data.push(*i);
    }

    encrypted_data
}

fn decrypt_data(mut data: &[u8], password: &str) -> Vec<u8> {
    // Şifreleme algoritması olarak XOR kullanılır
    let mut decrypted_data = Vec::with_capacity(data.len());
    //check if last 15 byte of data
    for i in 0..15 {
        if data[data.len()-1-i] != encrypt_sign[14-i] {
            println!("File is already not encrypted");
            return data.to_vec();
        }
    }
    
    data = &data[..data.len()-15];


    let password_bytes = password.bytes().cycle();
    for (byte, password_byte) in data.iter().zip(password_bytes) {
        decrypted_data.push(byte ^ password_byte);
    }
    decrypted_data
}

fn conf<'a>() -> argon2::Config<'a> {
    return argon2::Config {
        variant: argon2::Variant::Argon2id,
        hash_length: 32,
        lanes: 8,
        mem_cost: 16 * 1024,
        time_cost: 8,
        ..Default::default()
    };
}

fn encrypt_file_aead(source_file_path: &str, dist_file_path: &str, password: &str,) -> Result<(), anyhow::Error> {
    let conf = conf();

    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut nonce);

    let mut key = argon2::hash_raw(password.as_bytes(), &salt, &conf)?;

    let aead = XChaCha20Poly1305::new(key[..32].as_ref().into());
    let mut stream_encryptor = stream::EncryptorBE32::from_aead(aead, nonce.as_ref().into());

    const BUFFER_LEN: usize = 500;
    let mut buffer = [0u8; BUFFER_LEN];

    let mut source_file = File::open(source_file_path)?;
    let mut dist_file = File::create(dist_file_path)?;

    dist_file.write(&salt)?;
    dist_file.write(&nonce)?;

    loop {
        let read_file = source_file.read(&mut buffer)?;

        if read_file == BUFFER_LEN {
            let ciphertext = stream_encryptor
                .encrypt_next(buffer.as_slice())
                .map_err(|err| anyhow!("Encrypting large file: {}", err))?;
            dist_file.write(&ciphertext)?;
        } else {
            let ciphertext = stream_encryptor
                .encrypt_last(&buffer[..read_file])
                .map_err(|err| anyhow!("Encrypting large file: {}", err))?;
            dist_file.write(&ciphertext)?;
            break;
        }
    }
    
    fs::remove_file(source_file_path)?;
    
    Ok(())
}

fn decrypt_file_aead(encrypted_fp: &str, dist: &str, password: &str,) -> 
    Result<(), anyhow::Error> {

    let mut encrypted_file = File::open(encrypted_fp)?;
    let mut dist_file = File::create(dist)?;

    let mut read_file = encrypted_file.read(&mut salt)?;
    if read_file != salt.len() {
        return Err(anyhow!("Error reading salt."));
    }

    read_file = encrypted_file.read(&mut nonce)?;
    if read_file != nonce.len() {
        return Err(anyhow!("Error reading nonce."));
    }

    let conf = conf();

    let mut key = argon2::hash_raw(password.as_bytes(), &salt, &conf)?;

    let aead = XChaCha20Poly1305::new(key[..32].as_ref().into());
    let mut stream_decryptor = stream::DecryptorBE32::from_aead(aead, nonce.as_ref().into());

    const BUFFER_LEN: usize = 500 + 16;
    let mut buffer = [0u8; BUFFER_LEN];

    loop {
        let read_file = encrypted_file.read(&mut buffer)?;

        if read_file == BUFFER_LEN {
            let plaintext = stream_decryptor
                .decrypt_next(buffer.as_slice())
                .map_err(|err| anyhow!("Decrypting large file: {}", err))?;
            dist_file.write(&plaintext)?;
        } else if read_file == 0 {
            break;
        } else {
            let plaintext = stream_decryptor
                .decrypt_last(&buffer[..read_file])
                .map_err(|err| anyhow!("Decrypting large file: {}", err))?;
            dist_file.write(&plaintext)?;
            break;
        }
    }

    fs::remove_file(encrypted_fp)?;
    Ok(())
}
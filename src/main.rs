
use std::env;
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;

static encrypt_sign: &[u8] = "atakan_aydinbas".as_bytes();

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 4 {
        println!("Usage: encrypt-file <command> <file_path> <password>");
        println!("Commands: encrypt, decrypt");
        return;
    }

    let command = &args[1];
    let file_path = Path::new(&args[2]);
    let password = &args[3];
    // Dosya yolu komut satırından alınır
        
    

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

fn encrypt_data(data: &[u8], password: &str) -> Vec<u8> {
    // Şifreleme algoritması olarak XOR kullanılır
    //if last byte is 0x45, it is already encrypted file
    for i in 0..15 {
        if data[data.len()-1-i] == encrypt_sign[14-i] {
            println!("File is already encrypted");
            return data.to_vec();
        }
    }
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


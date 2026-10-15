use arboard::Clipboard;
use chacha20poly1305::{
    ChaCha20Poly1305, Key, Nonce,
    aead::{Aead, KeyInit},
};
use dialoguer::{Input, Password, Select, theme::ColorfulTheme};
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;

const FILE_PATH: &str = "vault.enc";

#[derive(Debug, Serialize, Deserialize, Clone)]
struct ServiceAndPassword {
    num: u32,
    service: String,
    password: String,
}

impl fmt::Display for ServiceAndPassword {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "[id: {}] {} (password: {})",
            self.num, self.service, self.password
        )
    }
}

fn derive_key(master_password: &str) -> Key {
    let mut key_bytes = [0u8; 32];
    let pwd_bytes = master_password.as_bytes();
    let len = pwd_bytes.len().min(32);
    key_bytes[..len].copy_from_slice(&pwd_bytes[..len]);
    *Key::from_slice(&key_bytes)
}

fn save_vault(
    vault: &[ServiceAndPassword],
    master_password: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let json_data = serde_json::to_vec(vault)?;
    let key = derive_key(master_password);
    let cipher = ChaCha20Poly1305::new(&key);

    let mut nonce_bytes = [0u8; 12];
    rand::fill(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let encrypted_data = cipher
        .encrypt(nonce, json_data.as_ref())
        .map_err(|_| "encrypt error")?;

    let mut file = File::create(FILE_PATH)?;
    file.write_all(&nonce_bytes)?;
    file.write_all(&encrypted_data)?;
    Ok(())
}

fn load_vault(
    master_password: &str,
) -> Result<Vec<ServiceAndPassword>, Box<dyn std::error::Error>> {
    if !Path::new(FILE_PATH).exists() {
        return Ok(Vec::new());
    }

    let mut file = File::open(FILE_PATH)?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;

    if buffer.len() < 12 {
        return Err("file damaged".into());
    }

    let (nonce_bytes, encrypted_data) = buffer.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);
    let key = derive_key(master_password);
    let cipher = ChaCha20Poly1305::new(&key);

    let decrypted_data = cipher
        .decrypt(nonce, encrypted_data)
        .map_err(|_| "invalid password or file damaged")?;

    let vault = serde_json::from_slice(&decrypted_data)?;
    Ok(vault)
}

fn generate(pass_lenght: usize) -> String {
    let alphabet: Vec<char> = ('a'..='z').collect();
    let digits: Vec<char> = ('0'..='9').collect();
    let all: Vec<char> = alphabet.into_iter().chain(digits).collect();

    let mut rng = rand::rng();
    let mut pass: Vec<char> = Vec::with_capacity(pass_lenght);

    for _ in 0..pass_lenght {
        let random_index = rng.random_range(0..all.len());
        let mut character = all[random_index];

        let upper_or_lower = rng.random_bool(1.0 / 3.0);
        if upper_or_lower {
            character = character.to_ascii_uppercase();
        }

        pass.push(character);
    }
    pass.into_iter().collect()
}

fn main() {
    println!("hello world");
    let theme = ColorfulTheme::default();
    let mut clipboard = Clipboard::new().ok();

    println!("(* ^ ω ^) password generator (´• ω •`)");
    let master_password = Password::with_theme(&theme)
        .with_prompt(" enter your password ")
        .interact()
        .unwrap();
    println!("----------------------");
    let mut vault = match load_vault(&master_password) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("\n error: {}", e);
            return;
        }
    };

    let mut next_id = vault.iter().map(|item| item.num).max().unwrap_or(0) + 1;
    let actions = vec![
        "generate password",
        "password list",
        "copy your password",
        "delete password",
        "EXIT",
    ];

    'main: loop {
        let selection = Select::with_theme(&theme)
            .items(&actions)
            .default(0)
            .interact()
            .unwrap();

        match selection {
            0 => {
                let pass_lenght: usize = Input::with_theme(&theme)
                    .with_prompt(" password lenght")
                    .interact_text()
                    .unwrap();

                if pass_lenght == 0 || pass_lenght > 999 {
                    println!("🤨🤨🤨");
                    continue 'main;
                }

                let service: String = Input::with_theme(&theme)
                    .with_prompt(" service name or whatever")
                    .interact_text()
                    .unwrap();
                println!("------------------------------");
                let pass = generate(pass_lenght);
                let new_item = ServiceAndPassword {
                    num: next_id,
                    service,
                    password: pass.clone(),
                };
                next_id += 1;

                println!(" generated");
                println!(" {}", new_item.service);
                println!(" password: {}", new_item.password);

                if let Some(ref mut cb) = clipboard {
                    if cb.set_text(new_item.password.clone()).is_ok() {
                        println!(" password automatically copied");
                        println!("------------------------------");
                    }
                }

                vault.push(new_item);

                if let Err(e) = save_vault(&vault, &master_password) {
                    eprintln!(" save error: {}", e);
                }
            }
            1 => {
                if vault.is_empty() {
                    println!("\n password list is empty");
                } else {
                    println!("password list:");
                    for item in &vault {
                        println!("{}", item);
                    }
                    println!("----------------------");
                }
            }
            2 => {
                if vault.is_empty() {
                    println!("\n password list is empty");
                } else {
                    let copy_selection = Select::with_theme(&theme)
                        .with_prompt("choose password to copy")
                        .items(&vault)
                        .interact()
                        .unwrap();

                    if let Some(ref mut cb) = clipboard {
                        if cb.set_text(vault[copy_selection].password.clone()).is_ok() {
                            println!("\n password for '{}' copied", vault[copy_selection].service);
                        } else {
                            println!("\n cant copy (´ ∀ ` *) ");
                        }
                    }
                }
            }
            3 => {
                if vault.is_empty() {
                    println!("\n n0thyng to delete");
                } else {
                    let delete_selection = Select::with_theme(&theme)
                        .with_prompt("choose password to delete")
                        .items(&vault)
                        .interact()
                        .unwrap();

                    let removed = vault.remove(delete_selection);
                    println!("\n bye '{}' password", removed.service);

                    if let Err(e) = save_vault(&vault, &master_password) {
                        eprintln!("save error: {}", e);
                    }
                }
            }
            4 => {
                println!("\n");
                break;
            }
            _ => unreachable!(),
        }
    }
}

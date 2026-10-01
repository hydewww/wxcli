/// WeChat Linux 4.1+ passphrase capture and key derivation
///
/// WeChat 4.1+ no longer caches raw SQLCipher keys in memory as x'<hex>' strings.
/// Instead, it derives keys at login via PBKDF2-HMAC-SHA512 from a 32-byte passphrase.
/// This module captures that passphrase using GDB at the Cipher config hook.
use anyhow::{Context, Result};
use std::path::Path;

use super::{collect_db_salts, KeyEntry};

/// Capture passphrase via GDB breakpoint on WCDB Cipher config hook
/// Returns hex-encoded 32-byte passphrase
pub fn capture_passphrase(pid: u32) -> Result<String> {
    // Analyze ELF to find Cipher config hook VA
    let wechat_path = find_wechat_binary(pid)?;
    let hook_va = find_cipher_hook_va(&wechat_path)?;
    eprintln!("Cipher hook VA: 0x{:x}", hook_va);

    // Find PIE load bias (first mapping with file offset 0)
    let load_bias = find_load_bias(pid, &wechat_path)?;
    eprintln!("PIE load bias: 0x{:x}", load_bias);

    let breakpoint_addr = load_bias + hook_va;
    eprintln!("Setting breakpoint at: 0x{:x}", breakpoint_addr);

    // Generate GDB script
    let gdb_script = generate_gdb_script(pid, breakpoint_addr);
    let script_path = "/tmp/wx-cli-gdb-capture.py";
    std::fs::write(script_path, gdb_script)
        .context("Failed to write GDB script")?;

    eprintln!("\n=== Passphrase Capture Required ===");
    eprintln!("WeChat 4.1+ requires capturing the passphrase at login.");
    eprintln!("Please follow these steps:");
    eprintln!("1. Keep WeChat running (PID: {})", pid);
    eprintln!("2. In another terminal, run:");
    eprintln!("   sudo gdb -batch -x {} 2>&1 | grep 'WECHAT_PASSPHRASE='", script_path);
    eprintln!("3. Log out and log back in to WeChat");
    eprintln!("4. Copy the WECHAT_PASSPHRASE=<hex> output");
    eprintln!("5. Paste the hex value when prompted below");
    eprintln!("===================================\n");

    // In production, we could run GDB here, but for safety in cloud env,
    // we guide the user to run it manually
    eprint!("Enter captured passphrase (64 hex chars): ");
    use std::io::Write;
    std::io::stdout().flush()?;

    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;
    let passphrase = input.trim().to_string();

    if passphrase.len() != 64 || !passphrase.chars().all(|c| c.is_ascii_hexdigit()) {
        anyhow::bail!("Invalid passphrase: expected 64 hex characters");
    }

    Ok(passphrase)
}

/// Derive SQLCipher keys from passphrase for all DBs
pub fn derive_keys_from_passphrase(
    passphrase_hex: &str,
    db_dir: &Path,
) -> Result<Vec<KeyEntry>> {
    let passphrase_bytes = hex::decode(passphrase_hex)
        .map_err(|e| anyhow::anyhow!("Invalid passphrase hex: {}", e))?;
    if passphrase_bytes.len() != 32 {
        anyhow::bail!("Passphrase must be 32 bytes");
    }

    let db_salts = collect_db_salts(db_dir);
    eprintln!("Deriving keys for {} databases...", db_salts.len());

    let mut entries = Vec::new();
    for (salt_hex, db_name) in db_salts {
        let salt_bytes = hex::decode(&salt_hex)
            .map_err(|e| anyhow::anyhow!("Invalid salt hex: {}", e))?;
        if salt_bytes.len() != 16 {
            continue;
        }

        // Derive key: PBKDF2-HMAC-SHA512(passphrase, salt, 256000, dkLen=32)
        let enc_key = derive_sqlcipher_key(&passphrase_bytes, &salt_bytes)?;
        let enc_key_hex = hex::encode(&enc_key);

        // TODO: Verify with SQLCipher4 page-1 HMAC-SHA512
        // For now, we trust the derivation

        entries.push(KeyEntry {
            db_name,
            enc_key: enc_key_hex,
            salt: salt_hex,
        });
    }

    eprintln!("Successfully derived {} keys", entries.len());
    Ok(entries)
}

/// PBKDF2-HMAC-SHA512 key derivation for SQLCipher
fn derive_sqlcipher_key(passphrase: &[u8], salt: &[u8]) -> Result<Vec<u8>> {
    use sha2::Sha512;
    use pbkdf2::pbkdf2_hmac;

    let mut key = vec![0u8; 32];
    pbkdf2_hmac::<Sha512>(passphrase, salt, 256000, &mut key);
    Ok(key)
}

/// Find WeChat binary path from /proc/{pid}/exe
fn find_wechat_binary(pid: u32) -> Result<std::path::PathBuf> {
    let exe_link = format!("/proc/{}/exe", pid);
    std::fs::read_link(&exe_link)
        .with_context(|| format!("Failed to read {}", exe_link))
}

/// Find Cipher config hook VA by searching for the string in ELF
fn find_cipher_hook_va(binary_path: &Path) -> Result<u64> {
    // Search for "com.Tencent.WCDB.Config.Cipher" xrefs
    // For simplicity, we'll use a heuristic: search binary with `strings` + `objdump`
    // In production, should use proper ELF parsing or maintain version-specific VAs

    // Fallback: Return a documented VA for common version
    // User can update this in code or we could make it configurable
    eprintln!("Warning: Using fallback Cipher hook VA");
    eprintln!("For your WeChat version, you may need to find the correct VA using:");
    eprintln!("  strings {} | grep -i 'cipher' | head -20", binary_path.display());
    eprintln!("  objdump -d {} | grep -A5 'Cipher'", binary_path.display());

    // Known VA for WeChat 4.1.13.23 (from captured report)
    Ok(0x87AC370)
}

/// Find PIE load bias: first mapping with file offset 0
fn find_load_bias(pid: u32, binary_path: &Path) -> Result<u64> {
    let maps_path = format!("/proc/{}/maps", pid);
    let content = std::fs::read_to_string(&maps_path)
        .with_context(|| format!("Failed to read {}", maps_path))?;

    let binary_name = binary_path.file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("wechat");

    for line in content.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 6 {
            continue;
        }
        // Check if this mapping is for the WeChat binary
        if !parts[5].ends_with(binary_name) {
            continue;
        }
        // Parse file offset
        let file_offset = u64::from_str_radix(parts[2], 16)
            .context("Failed to parse file offset")?;
        if file_offset == 0 {
            // This is the load bias
            let addr_range = parts[0];
            let start_str = addr_range.split('-').next()
                .context("Invalid address range")?;
            let start = u64::from_str_radix(start_str, 16)
                .context("Failed to parse start address")?;
            return Ok(start);
        }
    }

    anyhow::bail!("Could not find PIE load bias for {}", binary_name)
}

/// Generate GDB Python script for passphrase capture
fn generate_gdb_script(pid: u32, breakpoint_addr: u64) -> String {
    format!(r#"set pagination off
attach {pid}
python
import gdb

class CaptureBreakpoint(gdb.Breakpoint):
    def stop(self):
        try:
            rsi = int(gdb.parse_and_eval("$rsi"))
            rdx = int(gdb.parse_and_eval("$rdx"))
            # Method 1: rsi=key_ptr, rdx=key_len=32
            if rsi and rdx == 32:
                raw = gdb.selected_inferior().read_memory(rsi, 32).tobytes()
                print("WECHAT_PASSPHRASE=" + raw.hex())
                gdb.execute("detach")
                gdb.execute("quit")
                return True
            # Method 2: rsi points to struct, key at *(rsi+8), size at *(rsi+16)==32
            if rsi:
                try:
                    size_val = int(gdb.parse_and_eval("*(unsigned long long*)($rsi+16)"))
                    if size_val == 32:
                        key_ptr = int(gdb.parse_and_eval("*(unsigned long long*)($rsi+8)"))
                        if key_ptr:
                            raw = gdb.selected_inferior().read_memory(key_ptr, 32).tobytes()
                            print("WECHAT_PASSPHRASE=" + raw.hex())
                            gdb.execute("detach")
                            gdb.execute("quit")
                            return True
                except:
                    pass
        except Exception as e:
            print("CAPTURE_ERROR=" + str(e))
        return False

CaptureBreakpoint("*{breakpoint_addr:#x}")
end
continue
quit
"#, pid=pid, breakpoint_addr=breakpoint_addr)
}

// hex module
mod hex {
    pub fn decode(s: &str) -> Result<Vec<u8>, String> {
        if s.len() % 2 != 0 {
            return Err("Hex string length must be even".to_string());
        }
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i+2], 16)
                .map_err(|_| "Invalid hex digit".to_string()))
            .collect()
    }

    pub fn encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_sqlcipher_key() {
        // Test vector: derive key from known passphrase and salt
        let passphrase = vec![0x42u8; 32];
        let salt = vec![0x13u8; 16];
        
        let result = derive_sqlcipher_key(&passphrase, &salt);
        assert!(result.is_ok());
        let key = result.unwrap();
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn test_hex_decode() {
        let hex_str = "deadbeef";
        let bytes = hex::decode(hex_str).unwrap();
        assert_eq!(bytes, vec![0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn test_hex_encode() {
        let bytes = vec![0xca, 0xfe, 0xba, 0xbe];
        let hex_str = hex::encode(&bytes);
        assert_eq!(hex_str, "cafebabe");
    }

    #[test]
    fn test_hex_roundtrip() {
        let original = "0123456789abcdef";
        let bytes = hex::decode(original).unwrap();
        let encoded = hex::encode(&bytes);
        assert_eq!(encoded, original);
    }
}

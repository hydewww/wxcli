use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::Path;

#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "windows")]
mod windows;

#[cfg(target_os = "linux")]
pub mod passphrase_capture;

/// 扫描到的一条密钥记录
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyEntry {
    /// 相对路径，如 "message/message_0.db"
    pub db_name: String,
    /// 32字节 AES 密钥（hex）
    pub enc_key: String,
    /// 16字节 salt（hex，来自数据库文件头）
    pub salt: String,
}

/// 从进程内存中扫描所有 SQLCipher 密钥
///
/// 需要以 root/Administrator 权限运行
pub fn scan_keys(db_dir: &Path) -> Result<Vec<KeyEntry>> {
    #[cfg(target_os = "macos")]
    return macos::scan_keys(db_dir);
    #[cfg(target_os = "linux")]
    return linux::scan_keys(db_dir);
    #[cfg(target_os = "windows")]
    return windows::scan_keys(db_dir);
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        anyhow::bail!("当前平台不支持自动密钥扫描")
    }
}

/// 读取 DB 文件前 16 字节作为 salt（hex），如果是明文 SQLite 则返回 None
pub fn read_db_salt(path: &Path) -> Option<String> {
    let mut buf = [0u8; 16];
    let mut f = std::fs::File::open(path).ok()?;
    use std::io::Read;
    f.read_exact(&mut buf).ok()?;
    // 明文 SQLite：头部是 "SQLite format 3"
    if &buf[..15] == b"SQLite format 3" {
        return None;
    }
    Some(hex::encode(&buf))
}

/// 遍历 db_dir，收集所有 .db 文件的 salt -> 相对路径 映射
pub fn collect_db_salts(db_dir: &Path) -> Vec<(String, String)> {
    let mut result = Vec::new();
    collect_recursive(db_dir, db_dir, &mut result);
    result
}

fn collect_recursive(base: &Path, dir: &Path, out: &mut Vec<(String, String)>) {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_recursive(base, &path, out);
        } else if path.extension().map(|e| e == "db").unwrap_or(false) {
            if let Some(salt) = read_db_salt(&path) {
                if let Ok(rel) = path.strip_prefix(base) {
                    let rel_str = rel.to_string_lossy().replace('\\', "/");
                    out.push((salt, rel_str));
                }
            }
        }
    }
}

// hex encoding helper (avoid adding hex crate by implementing inline)
mod hex {
    pub fn encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    /// 创建一个进程唯一的临时目录（测试用），返回路径；测试结束后调用方负责删除
    fn make_temp_dir(label: &str) -> std::path::PathBuf {
        let mut p = std::env::temp_dir();
        // 用 label + thread id 保证同进程内并发测试不冲突
        p.push(format!("wx-cli-test-{}-{:?}", label, std::thread::current().id()));
        fs::create_dir_all(&p).unwrap();
        p
    }

    // ── read_db_salt ──────────────────────────────────────────────────────────

    #[test]
    fn test_read_db_salt_plaintext_sqlite() {
        let dir = make_temp_dir("salt-plain");
        let path = dir.join("plain.db");
        // 明文 SQLite 头：前 15 字节是 "SQLite format 3"
        let mut content = b"SQLite format 3\x00".to_vec();
        content.extend_from_slice(&[0u8; 100]);
        fs::write(&path, &content).unwrap();

        assert!(read_db_salt(&path).is_none(), "明文 SQLite 应返回 None");
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_read_db_salt_encrypted() {
        let dir = make_temp_dir("salt-enc");
        let path = dir.join("enc.db");
        // 非 SQLite 头 → 视为加密数据库，取前 16 字节作为 salt
        let header: [u8; 16] = [
            0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04,
            0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
        ];
        fs::write(&path, &header).unwrap();

        let salt = read_db_salt(&path).expect("加密 DB 应返回 Some");
        assert_eq!(salt, "deadbeef0102030405060708090a0b0c");
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_read_db_salt_too_short() {
        let dir = make_temp_dir("salt-short");
        let path = dir.join("short.db");
        fs::write(&path, b"tooshort").unwrap(); // < 16 bytes

        assert!(read_db_salt(&path).is_none(), "文件太短应返回 None");
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_read_db_salt_nonexistent() {
        assert!(read_db_salt(Path::new("/nonexistent/surely/not/here.db")).is_none());
    }

    #[test]
    fn test_read_db_salt_exactly_16_bytes() {
        let dir = make_temp_dir("salt-16");
        let path = dir.join("exact.db");
        let header = [0xabu8; 16];
        fs::write(&path, &header).unwrap();

        let salt = read_db_salt(&path).unwrap();
        // 0xab × 16 → "ab" × 16 = 32 chars
        assert_eq!(salt, "ab".repeat(16));
        fs::remove_dir_all(&dir).ok();
    }

    // ── collect_db_salts ──────────────────────────────────────────────────────

    #[test]
    fn test_collect_db_salts_empty_dir() {
        let dir = make_temp_dir("collect-empty");
        let salts = collect_db_salts(&dir);
        assert!(salts.is_empty());
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_collect_db_salts_skips_plaintext_sqlite() {
        let dir = make_temp_dir("collect-plain");
        let mut content = b"SQLite format 3\x00".to_vec();
        content.extend_from_slice(&[0u8; 100]);
        fs::write(dir.join("plain.db"), &content).unwrap();

        assert!(collect_db_salts(&dir).is_empty(), "明文 SQLite 应被跳过");
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_collect_db_salts_finds_encrypted() {
        let dir = make_temp_dir("collect-enc");
        let header = [0x11u8; 16];
        fs::write(dir.join("msg.db"), &header).unwrap();

        let salts = collect_db_salts(&dir);
        assert_eq!(salts.len(), 1);
        assert_eq!(salts[0].0, "11".repeat(16)); // 0x11 × 16 → "11" × 16
        assert_eq!(salts[0].1, "msg.db");
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_collect_db_salts_recursive() {
        let dir = make_temp_dir("collect-rec");
        let subdir = dir.join("sub");
        fs::create_dir_all(&subdir).unwrap();

        let header = [0xaau8; 16];
        fs::write(dir.join("root.db"), &header).unwrap();
        fs::write(subdir.join("nested.db"), &header).unwrap();
        fs::write(dir.join("ignored.txt"), b"text file").unwrap();

        let salts = collect_db_salts(&dir);
        assert_eq!(salts.len(), 2, "应递归找到 2 个加密 .db");

        let names: Vec<&str> = salts.iter().map(|(_, n)| n.as_str()).collect();
        assert!(names.contains(&"root.db"));
        assert!(names.contains(&"sub/nested.db"));
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_collect_db_salts_ignores_non_db_extensions() {
        let dir = make_temp_dir("collect-ext");
        let header = [0xbbu8; 16];
        fs::write(dir.join("data.txt"),  &header).unwrap();
        fs::write(dir.join("data.json"), &header).unwrap();
        fs::write(dir.join("data.sqlite"), &header).unwrap();

        assert!(collect_db_salts(&dir).is_empty(), "非 .db 文件应被忽略");
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_collect_db_salts_multiple_files_unique_salts() {
        let dir = make_temp_dir("collect-multi");
        fs::write(dir.join("a.db"), &[0x11u8; 16]).unwrap();
        fs::write(dir.join("b.db"), &[0x22u8; 16]).unwrap();
        fs::write(dir.join("c.db"), &[0x33u8; 16]).unwrap();

        let salts = collect_db_salts(&dir);
        assert_eq!(salts.len(), 3);

        let salt_vals: std::collections::HashSet<&str> =
            salts.iter().map(|(s, _)| s.as_str()).collect();
        assert!(salt_vals.contains("11".repeat(16).as_str()));
        assert!(salt_vals.contains("22".repeat(16).as_str()));
        assert!(salt_vals.contains("33".repeat(16).as_str()));
        fs::remove_dir_all(&dir).ok();
    }
}

# WeChat Linux 4.1+ Passphrase-Based Initialization Guide

## Background

**Problem**: Starting with WeChat Linux 4.1+, the traditional memory-scan approach (`wx init`) finds **zero** encryption keys, even when running as root with full memory access.

**Root cause**: WeChat 4.1+ no longer caches SQLCipher raw keys (in `x'<64hex_key><32hex_salt>'` format) in process memory. Instead, it derives keys at login time via **PBKDF2-HMAC-SHA512** from a 32-byte passphrase.

**Solution**: Capture the passphrase when WeChat logs in, then derive per-database keys using PBKDF2.

---

## Prerequisites

- **WeChat Linux 4.1+** running
- **Root access** (for GDB attach and `/proc/<pid>/mem`)
- **GDB** installed: `sudo apt install gdb` or `sudo yum install gdb`
- Willingness to **logout and login again** to WeChat (passphrase is only derived at login)

---

## Step-by-Step Procedure

### 1. Find WeChat PID

```bash
ps aux | grep wechat
# or
pgrep -f wechat
```

Note the PID (example: `12345`).

### 2. Analyze WeChat Binary for Cipher Hook

The passphrase is passed to WCDB's `com.Tencent.WCDB.Config.Cipher` hook. You need to find the virtual address (VA) of this function in your WeChat binary:

```bash
# Find the WeChat binary path
ls -l /proc/<PID>/exe
# Example output: /opt/wechat/wechat

# Search for Cipher-related strings
strings /opt/wechat/wechat | grep -i cipher | head -20

# Disassemble to find the hook function VA (advanced)
# For WeChat 4.1.13.23, the known VA is 0x87AC370
# Your version may differ
```

For simplicity, `wx-cli` defaults to `0x87AC370` (verified for 4.1.13.23). If capture fails, you may need to update the VA in `src/scanner/passphrase_capture.rs`.

### 3. Generate GDB Capture Script

Run `wx init` as root. When it detects WeChat 4.1+ (zero memory-scan results), it will output instructions like:

```
=== Passphrase Capture Required ===
WeChat 4.1+ requires capturing the passphrase at login.
Please follow these steps:
1. Keep WeChat running (PID: 12345)
2. In another terminal, run:
   sudo gdb -batch -x /tmp/wx-cli-gdb-capture.py 2>&1 | grep 'WECHAT_PASSPHRASE='
3. Log out and log back in to WeChat
4. Copy the WECHAT_PASSPHRASE=<hex> output
5. Paste the hex value when prompted below
===================================
```

The script `/tmp/wx-cli-gdb-capture.py` is automatically generated. Alternatively, you can use external tools like [TANGandXUE/wcdb-key-tool](https://github.com/TANGandXUE/wcdb-key-tool).

### 4. Capture Passphrase at Login

In a **second terminal** (keep the first `wx init` session waiting):

```bash
# Attach GDB with the capture script
sudo gdb -batch -x /tmp/wx-cli-gdb-capture.py 2>&1 | grep 'WECHAT_PASSPHRASE='

# GDB is now waiting. Go to WeChat UI and logout, then login again.
# When you login, GDB will hit the breakpoint and print:
WECHAT_PASSPHRASE=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef

# Copy the 64-character hex string (this is your passphrase)
```

**Important**: 
- The passphrase is **account-specific** and **sensitive**. Treat it like a password.
- Do **not** commit this value to git or share publicly.

### 5. Derive Keys from Passphrase

Back in the first terminal where `wx init` is waiting, paste the 64-hex passphrase when prompted.

Alternatively, set it as an environment variable and re-run init:

```bash
export WX_PASSPHRASE=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
sudo -E wx init
```

wx-cli will:
1. Read the 16-byte salt from each encrypted database file header
2. Derive the encryption key: `PBKDF2-HMAC-SHA512(passphrase, salt, 256000, dkLen=32)`
3. Write keys to `~/.wx-cli/all_keys.json`

### 6. Verify

```bash
wx sessions
```

If you see recent conversations, initialization succeeded.

---

## Key Derivation Formula

For each database `db_name` with salt `salt_16` (read from file header):

```
enc_key = PBKDF2-HMAC-SHA512(
    passphrase=<32 bytes from capture>,
    salt=<16 bytes from DB header>,
    iterations=256000,
    dkLen=32
)
```

This matches SQLCipher 4 defaults used by WCDB.

---

## Troubleshooting

### "Memory scan found no keys"

**Expected** on WeChat 4.1+. Follow the passphrase capture procedure above.

### "Refusing to overwrite existing keys with empty scan result"

You already have keys in `~/.wx-cli/all_keys.json`. If you want to re-initialize:

```bash
# Backup first
cp ~/.wx-cli/all_keys.json ~/.wx-cli/all_keys.json.backup

# Then force overwrite
sudo -E wx init --force
```

### GDB breakpoint never hits

**Possible causes**:
- Wrong Cipher hook VA for your WeChat version. Update `find_cipher_hook_va()` in `src/scanner/passphrase_capture.rs`.
- WeChat already logged in (passphrase only derived at login). Logout and login again while GDB is attached.

### Incorrect PIE load bias

The default `find_load_bias()` logic finds the first mapping with file offset 0. If this fails, check `/proc/<PID>/maps` manually:

```bash
cat /proc/<PID>/maps | grep wechat | head -5
```

The load bias is the **start address** of the first mapping with offset `00000000` (rightmost column).

---

## Security Notes

1. **Passphrase sensitivity**: The captured passphrase can decrypt all your WeChat databases. Store it securely.
2. **Do not commit**: Never commit real passphrases, keys, or `all_keys.json` to version control.
3. **Permissions**: `all_keys.json` should be readable only by you (mode `0600`). wx-cli sets this automatically.

---

## Windows / macOS

**Out of scope** for this guide. Windows 4.1+ may still allow memory scan (unverified). macOS capture requires LLDB and different hooks. Contributions welcome.

---

## References

- [TANGandXUE/wcdb-key-tool](https://github.com/TANGandXUE/wcdb-key-tool) - Python implementation of GDB capture + PBKDF2
- [ylytdeng/wechat-decrypt#96](https://github.com/ylytdeng/wechat-decrypt/issues/96) - Community discussion on 4.1+ changes
- [SQLCipher docs](https://www.zetetic.net/sqlcipher/sqlcipher-api/) - PBKDF2 parameters

---

## Attribution

Passphrase capture approach inspired by TANGandXUE/wcdb-key-tool (MIT License). PIE load-bias fix integrated from community findings.

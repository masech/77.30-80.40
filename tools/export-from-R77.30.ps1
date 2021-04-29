
$sms_ip = Read-Host 'Input SMS IP-address'
$policy = Read-Host 'Input policy name'
$userName = Read-Host 'Input username'
$userPass_sec = Read-Host 'Input password' -AsSecureString
$nowShortDate = (Get-Date).ToShortDateString()
$dir = ".\objects-and-rules"

if (-not (Test-Path $dir)) {
    New-Item -Path $dir -ItemType Directory
}

Clear-Host
Write-Output ''
Write-Output "$userName@$sms_ip"
Write-Output '-------------------------------------------------------------------------------'
Write-Output 'Exporting format = Advanced (xml)'
Write-Output "Output directory = $dir"
Write-Output '-------------------------------------------------------------------------------'
Write-Output ''
Write-Output "Export $policy policy:"
Write-Output ''

$BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($userPass_sec)
$userPass = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)

C:\Software\cpdb2web\cpdb2web.exe -s $sms_ip -u $userName -p $userPass -o $dir -l $policy

$exported_files_number = (Get-ChildItem $dir).Count

Write-Output ''

if ($exported_files_number -eq 7) {
    Write-Output '*******************************************************************************'
    Write-Output 'Objects and rules exported successfully.'
    Write-Output '*******************************************************************************'
    
} else {
    Write-Output '*******************************************************************************'
    Write-Output 'Something was wrong.'
    Write-Output '*******************************************************************************'
}
Write-Output 'Press ENTER to exit.'
Read-Host

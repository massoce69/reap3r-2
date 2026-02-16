
param(
    [string]$password
)

Add-Type -AssemblyName System.Windows.Forms
Start-Sleep -Seconds 2
[System.Windows.Forms.SendKeys]::SendWait($password)
[System.Windows.Forms.SendKeys]::SendWait("{ENTER}")

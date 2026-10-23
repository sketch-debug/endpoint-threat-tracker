# Set-FirewallRule.ps1 — allow the tracker's local dashboard port through the
# Windows Firewall (localhost only by default). Run elevated.
#
# This tool never blocks or filters traffic; it only opens ONE inbound rule
# for the dashboard port on the PRIVATE profile, and only when you pass
# -AllowRemote (loopback access needs no rule at all).
[CmdletBinding(SupportsShouldProcess)]
param(
    [int]$Port = 8043,
    [switch]$AllowRemote,
    [switch]$Remove
)
$ErrorActionPreference = 'Stop'
$ruleName = "Endpoint Threat Tracker (TCP $Port)"

if ($Remove) {
    if ($PSCmdlet.ShouldProcess($ruleName, 'Remove firewall rule')) {
        Remove-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
        Write-Host "Removed rule '$ruleName' (if it existed)."
    }
    exit 0
}

if (-not $AllowRemote) {
    Write-Host "Loopback access (http://127.0.0.1:$Port) needs no firewall rule."
    Write-Host "Pass -AllowRemote only if other machines must reach the dashboard;"
    Write-Host "prefer binding to 127.0.0.1 in config/app_config.yaml instead."
    exit 0
}

if ($PSCmdlet.ShouldProcess($ruleName, 'Create firewall rule')) {
    New-NetFirewallRule -DisplayName $ruleName `
        -Direction Inbound -Protocol TCP -LocalPort $Port `
        -Profile Private -Action Allow -Enabled True `
        -Description 'Dashboard for the Endpoint Threat Detection & Incident Tracker (metadata only)'
    Write-Host "Created inbound rule for TCP $Port (Private profile only)."
}

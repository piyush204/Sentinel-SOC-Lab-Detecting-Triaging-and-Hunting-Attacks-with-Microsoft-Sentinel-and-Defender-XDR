# Sentinel SOC Lab: attack simulation helpers.
# RUN INSIDE THE LAB VM AS ADMINISTRATOR. Use only on a test machine you own and control.
#
# Usage:
#   .\attack-sim.ps1 -Technique BruteForce
#   .\attack-sim.ps1 -Technique LocalAdmin
#   .\attack-sim.ps1 -Technique LocalAdmin -Cleanup

param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("BruteForce", "LocalAdmin")]
    [string]$Technique,
    [switch]$Cleanup
)

switch ($Technique) {

    "BruteForce" {
        # MITRE T1110: eight failed network logons for an account that does not exist.
        # Each failure is logged by Windows as event 4625.
        1..8 | ForEach-Object { net use \\localhost\IPC$ /user:labfake "WrongPass$_" }
        Write-Host "Done. Wait 5-10 minutes, then check Incidents."
        Write-Host "If an earlier brute-force incident is still open, close it first so a new one is created."
    }

    "LocalAdmin" {
        # MITRE T1136.001: create a local account and add it to Administrators.
        # Windows logs event 4720 (account created) and 4732 (member added to a local group).
        if ($Cleanup) {
            net user labtemp /delete
            net user
        }
        else {
            $pw = Read-Host "Enter a throwaway test password for the labtemp account"
            net user labtemp $pw /add
            net localgroup administrators labtemp /add
            Write-Host "Done. Run again with -Cleanup after you have taken your screenshots."
        }
    }
}

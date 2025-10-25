# PowerShell Script for RBAC Audit on Critical OT Systems
# ======================================================
#
# This script audits role-based access controls on critical OT systems
# and reports privilege escalation risks in maritime environments.
#
# Author: USC-CPTC
# Version: 1.0
# Requires: PowerShell 5.1+ and appropriate permissions

param(
    [string]$TargetDomain = "localhost",
    [string]$OutputFile = "",
    [string]$Username = "",
    [string]$Password = "",
    [switch]$Verbose,
    [switch]$Help
)

# Help function
function Show-Help {
    Write-Host @"
RBAC Audit Tool for OT Systems
===============================

This script audits role-based access controls on critical OT systems and reports 
privilege escalation risks in maritime environments.

USAGE:
    .\rbac.ps1 [OPTIONS]

OPTIONS:
    -TargetDomain    Domain or computer to audit (default: localhost)
    -OutputFile      Output file for results (default: auto-generated)
    -Username        Username for authentication (optional)
    -Password        Password for authentication (optional)
    -Verbose         Enable verbose output
    -Help            Show this help message

EXAMPLES:
    .\rbac.ps1 -TargetDomain "OT-SERVER-01" -Verbose
    .\rbac.ps1 -TargetDomain "maritime.local" -Username "admin" -OutputFile "rbac_audit.json"
    .\rbac.ps1 -Help

REQUIREMENTS:
    - PowerShell 5.1 or later
    - Appropriate permissions to query target systems
    - Network access to target domain/computer

"@
}

# Main audit class
class RBACAuditor {
    [string]$TargetDomain
    [string]$OutputFile
    [hashtable]$Results
    [array]$CriticalGroups
    [array]$OTSystems
    [array]$PrivilegeEscalationRisks
    
    RBACAuditor([string]$domain, [string]$outputFile) {
        $this.TargetDomain = $domain
        $this.OutputFile = $outputFile
        $this.Results = @{
            "audit_timestamp" = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ss")
            "target_domain" = $domain
            "critical_groups" = @()
            "user_privileges" = @()
            "privilege_escalation_risks" = @()
            "recommendations" = @()
        }
        
        # Define critical groups for maritime OT environments
        $this.CriticalGroups = @(
            "Domain Admins",
            "Enterprise Admins",
            "Schema Admins",
            "OT Administrators",
            "Maritime Engineers",
            "Vessel Control Operators",
            "Navigation System Admins",
            "Engine Control Admins",
            "SCADA Operators",
            "Network Administrators"
        )
        
        # Define critical OT systems
        $this.OTSystems = @(
            "Navigation Control System",
            "Engine Management System",
            "SCADA Network",
            "Vessel Communication System",
            "Cargo Management System",
            "Safety Systems",
            "Fire Suppression System",
            "Emergency Response System"
        )
    }
    
    # Get domain information
    [hashtable] Get-DomainInfo() {
        Write-Host "[*] Gathering domain information for: $($this.TargetDomain)"
        
        try {
            $domainInfo = @{
                "domain_name" = $this.TargetDomain
                "domain_controller" = ""
                "domain_functional_level" = ""
                "forest_functional_level" = ""
                "total_users" = 0
                "total_groups" = 0
                "total_computers" = 0
            }
            
            if ($this.TargetDomain -ne "localhost") {
                try {
                    $domain = Get-ADDomain -Server $this.TargetDomain -ErrorAction Stop
                    $domainInfo.domain_controller = $domain.PDCEmulator
                    $domainInfo.domain_functional_level = $domain.DomainMode
                    $domainInfo.forest_functional_level = $domain.ForestMode
                    $domainInfo.total_users = (Get-ADUser -Filter * -Server $this.TargetDomain).Count
                    $domainInfo.total_groups = (Get-ADGroup -Filter * -Server $this.TargetDomain).Count
                    $domainInfo.total_computers = (Get-ADComputer -Filter * -Server $this.TargetDomain).Count
                }
                catch {
                    Write-Warning "Could not query domain information: $($_.Exception.Message)"
                }
            }
            else {
                $domainInfo.domain_name = $env:COMPUTERNAME
                $domainInfo.total_users = (Get-LocalUser).Count
                $domainInfo.total_groups = (Get-LocalGroup).Count
            }
            
            return $domainInfo
        }
        catch {
            Write-Error "Error gathering domain information: $($_.Exception.Message)"
            return @{}
        }
    }
    
    # Audit critical groups
    [array] Audit-CriticalGroups() {
        Write-Host "[*] Auditing critical groups for privilege escalation risks"
        
        $groupAuditResults = @()
        
        foreach ($groupName in $this.CriticalGroups) {
            try {
                $groupInfo = @{
                    "group_name" = $groupName
                    "exists" = $false
                    "members" = @()
                    "privileges" = @()
                    "risk_level" = "LOW"
                    "recommendations" = @()
                }
                
                if ($this.TargetDomain -ne "localhost") {
                    try {
                        $group = Get-ADGroup -Identity $groupName -Server $this.TargetDomain -ErrorAction Stop
                        $groupInfo.exists = $true
                        $groupInfo.members = (Get-ADGroupMember -Identity $groupName -Server $this.TargetDomain).SamAccountName
                        $groupInfo.privileges = $this.Get-GroupPrivileges($group)
                    }
                    catch {
                        Write-Verbose "Group '$groupName' not found in domain"
                    }
                }
                else {
                    try {
                        $group = Get-LocalGroup -Name $groupName -ErrorAction Stop
                        $groupInfo.exists = $true
                        $groupInfo.members = (Get-LocalGroupMember -Group $groupName).Name
                        $groupInfo.privileges = $this.Get-LocalGroupPrivileges($groupName)
                    }
                    catch {
                        Write-Verbose "Local group '$groupName' not found"
                    }
                }
                
                # Assess risk level
                $groupInfo.risk_level = $this.Assess-GroupRisk($groupInfo)
                $groupInfo.recommendations = $this.Generate-GroupRecommendations($groupInfo)
                
                $groupAuditResults += $groupInfo
            }
            catch {
                Write-Warning "Error auditing group '$groupName': $($_.Exception.Message)"
            }
        }
        
        return $groupAuditResults
    }
    
    # Get group privileges
    [array] Get-GroupPrivileges([Microsoft.ActiveDirectory.Management.ADGroup]$group) {
        $privileges = @()
        
        try {
            # Check for dangerous privileges
            $dangerousPrivileges = @(
                "SeDebugPrivilege",
                "SeBackupPrivilege",
                "SeRestorePrivilege",
                "SeTakeOwnershipPrivilege",
                "SeLoadDriverPrivilege",
                "SeSystemtimePrivilege",
                "SeShutdownPrivilege",
                "SeRemoteShutdownPrivilege",
                "SeCreateTokenPrivilege",
                "SeAssignPrimaryTokenPrivilege"
            )
            
            foreach ($privilege in $dangerousPrivileges) {
                try {
                    $privilegeInfo = Get-ADObject -Filter "objectClass -eq 'groupPolicyContainer'" -SearchBase $group.DistinguishedName -Server $this.TargetDomain
                    if ($privilegeInfo) {
                        $privileges += $privilege
                    }
                }
                catch {
                    # Privilege not found or not accessible
                }
            }
        }
        catch {
            Write-Verbose "Could not enumerate group privileges: $($_.Exception.Message)"
        }
        
        return $privileges
    }
    
    # Get local group privileges
    [array] Get-LocalGroupPrivileges([string]$groupName) {
        $privileges = @()
        
        try {
            # Check for dangerous local privileges
            $dangerousLocalPrivileges = @(
                "Debug programs",
                "Back up files and directories",
                "Restore files and directories",
                "Take ownership of files or other objects",
                "Load and unload device drivers",
                "Change the system time",
                "Shut down the system",
                "Force shutdown from a remote system"
            )
            
            # This is a simplified check - in reality, you'd need to query the registry
            # or use other methods to get actual privileges
            foreach ($privilege in $dangerousLocalPrivileges) {
                $privileges += $privilege
            }
        }
        catch {
            Write-Verbose "Could not enumerate local group privileges: $($_.Exception.Message)"
        }
        
        return $privileges
    }
    
    # Assess group risk level
    [string] Assess-GroupRisk([hashtable]$groupInfo) {
        $riskScore = 0
        
        # Check if group exists
        if (-not $groupInfo.exists) {
            return "LOW"
        }
        
        # Check member count
        $memberCount = $groupInfo.members.Count
        if ($memberCount -gt 10) {
            $riskScore += 2
        }
        elseif ($memberCount -gt 5) {
            $riskScore += 1
        }
        
        # Check for dangerous privileges
        if ($groupInfo.privileges.Count -gt 0) {
            $riskScore += $groupInfo.privileges.Count * 2
        }
        
        # Check for service accounts in privileged groups
        foreach ($member in $groupInfo.members) {
            if ($member -like "*svc*" -or $member -like "*service*") {
                $riskScore += 3
            }
        }
        
        # Determine risk level
        if ($riskScore -ge 8) {
            return "CRITICAL"
        }
        elseif ($riskScore -ge 5) {
            return "HIGH"
        }
        elseif ($riskScore -ge 2) {
            return "MEDIUM"
        }
        else {
            return "LOW"
        }
    }
    
    # Generate group recommendations
    [array] Generate-GroupRecommendations([hashtable]$groupInfo) {
        $recommendations = @()
        
        if (-not $groupInfo.exists) {
            $recommendations += "Group does not exist - verify if this is intentional"
            return $recommendations
        }
        
        if ($groupInfo.risk_level -eq "CRITICAL") {
            $recommendations += "IMMEDIATE ACTION REQUIRED: Review and reduce group membership"
            $recommendations += "Implement additional monitoring for this group"
            $recommendations += "Consider implementing just-in-time access controls"
        }
        
        if ($groupInfo.members.Count -gt 10) {
            $recommendations += "Group has excessive membership - consider role separation"
        }
        
        if ($groupInfo.privileges.Count -gt 0) {
            $recommendations += "Group has dangerous privileges - review necessity"
            $recommendations += "Implement privilege escalation monitoring"
        }
        
        # Check for service accounts
        $serviceAccounts = $groupInfo.members | Where-Object { $_ -like "*svc*" -or $_ -like "*service*" }
        if ($serviceAccounts.Count -gt 0) {
            $recommendations += "Service accounts found in privileged group - review security"
        }
        
        return $recommendations
    }
    
    # Audit user privileges
    [array] Audit-UserPrivileges() {
        Write-Host "[*] Auditing user privileges and access rights"
        
        $userAuditResults = @()
        
        try {
            if ($this.TargetDomain -ne "localhost") {
                $users = Get-ADUser -Filter * -Server $this.TargetDomain -Properties MemberOf, LastLogonDate, PasswordLastSet
            }
            else {
                $users = Get-LocalUser | ForEach-Object {
                    [PSCustomObject]@{
                        SamAccountName = $_.Name
                        MemberOf = @()
                        LastLogonDate = $_.LastLogon
                        PasswordLastSet = $_.PasswordLastSet
                    }
                }
            }
            
            foreach ($user in $users) {
                $userInfo = @{
                    "username" = $user.SamAccountName
                    "member_of" = @()
                    "privilege_escalation_risk" = "LOW"
                    "last_logon" = $user.LastLogonDate
                    "password_age" = ""
                    "recommendations" = @()
                }
                
                # Get group memberships
                if ($user.MemberOf) {
                    $userInfo.member_of = $user.MemberOf
                }
                
                # Calculate password age
                if ($user.PasswordLastSet) {
                    $passwordAge = (Get-Date) - $user.PasswordLastSet
                    $userInfo.password_age = $passwordAge.Days.ToString() + " days"
                }
                
                # Assess privilege escalation risk
                $userInfo.privilege_escalation_risk = $this.Assess-UserRisk($userInfo)
                $userInfo.recommendations = $this.Generate-UserRecommendations($userInfo)
                
                $userAuditResults += $userInfo
            }
        }
        catch {
            Write-Error "Error auditing user privileges: $($_.Exception.Message)"
        }
        
        return $userAuditResults
    }
    
    # Assess user risk
    [string] Assess-UserRisk([hashtable]$userInfo) {
        $riskScore = 0
        
        # Check for membership in critical groups
        foreach ($group in $userInfo.member_of) {
            if ($group -in $this.CriticalGroups) {
                $riskScore += 3
            }
        }
        
        # Check password age
        if ($userInfo.password_age -and $userInfo.password_age -ne "") {
            $age = [int]($userInfo.password_age -replace " days", "")
            if ($age -gt 90) {
                $riskScore += 2
            }
            elseif ($age -gt 180) {
                $riskScore += 3
            }
        }
        
        # Check for inactive accounts
        if ($userInfo.last_logon) {
            $lastLogon = [DateTime]$userInfo.last_logon
            $daysSinceLogon = ((Get-Date) - $lastLogon).Days
            if ($daysSinceLogon -gt 30) {
                $riskScore += 1
            }
        }
        
        # Determine risk level
        if ($riskScore -ge 6) {
            return "CRITICAL"
        }
        elseif ($riskScore -ge 4) {
            return "HIGH"
        }
        elseif ($riskScore -ge 2) {
            return "MEDIUM"
        }
        else {
            return "LOW"
        }
    }
    
    # Generate user recommendations
    [array] Generate-UserRecommendations([hashtable]$userInfo) {
        $recommendations = @()
        
        if ($userInfo.privilege_escalation_risk -eq "CRITICAL") {
            $recommendations += "IMMEDIATE REVIEW REQUIRED: User has high privilege escalation risk"
        }
        
        if ($userInfo.password_age -and $userInfo.password_age -ne "") {
            $age = [int]($userInfo.password_age -replace " days", "")
            if ($age -gt 90) {
                $recommendations += "Password is over 90 days old - consider password reset"
            }
        }
        
        if ($userInfo.last_logon) {
            $lastLogon = [DateTime]$userInfo.last_logon
            $daysSinceLogon = ((Get-Date) - $lastLogon).Days
            if ($daysSinceLogon -gt 30) {
                $recommendations += "Account has not been used recently - consider disabling if not needed"
            }
        }
        
        return $recommendations
    }
    
    # Generate privilege escalation risks report
    [array] Generate-PrivilegeEscalationRisks() {
        Write-Host "[*] Analyzing privilege escalation risks"
        
        $risks = @()
        
        # Check for common privilege escalation vectors
        $escalationVectors = @(
            @{
                "vector" = "Weak Service Account Passwords"
                "description" = "Service accounts with weak or default passwords"
                "risk_level" = "HIGH"
                "mitigation" = "Implement strong password policies for service accounts"
            },
            @{
                "vector" = "Excessive Group Memberships"
                "description" = "Users with membership in multiple privileged groups"
                "risk_level" = "MEDIUM"
                "mitigation" = "Implement principle of least privilege"
            },
            @{
                "vector" = "Stale Accounts"
                "description" = "Inactive accounts with privileged access"
                "risk_level" = "MEDIUM"
                "mitigation" = "Regular account review and cleanup"
            },
            @{
                "vector" = "Default Administrator Accounts"
                "description" = "Default administrator accounts with unchanged passwords"
                "risk_level" = "CRITICAL"
                "mitigation" = "Change default passwords and disable unused accounts"
            }
        )
        
        foreach ($vector in $escalationVectors) {
            $risks += $vector
        }
        
        return $risks
    }
    
    # Generate security recommendations
    [array] Generate-SecurityRecommendations() {
        $recommendations = @(
            @{
                "category" = "Access Control"
                "description" = "Implement multi-factor authentication for privileged accounts"
                "priority" = "HIGH"
            },
            @{
                "category" = "Monitoring"
                "description" = "Deploy privilege escalation monitoring and alerting"
                "priority" = "HIGH"
            },
            @{
                "category" = "Account Management"
                "description" = "Implement regular account review and cleanup procedures"
                "priority" = "MEDIUM"
            },
            @{
                "category" = "Network Security"
                "description" = "Implement network segmentation for OT systems"
                "priority" = "HIGH"
            },
            @{
                "category" = "Incident Response"
                "description" = "Develop incident response procedures for privilege escalation attacks"
                "priority" = "MEDIUM"
            }
        )
        
        return $recommendations
    }
    
    # Run complete audit
    [void] Run-Audit() {
        Write-Host "[*] Starting RBAC audit for: $($this.TargetDomain)"
        Write-Host "[*] Audit timestamp: $((Get-Date).ToString('yyyy-MM-dd HH:mm:ss'))"
        
        # Gather domain information
        $domainInfo = $this.Get-DomainInfo()
        $this.Results.domain_info = $domainInfo
        
        # Audit critical groups
        $groupResults = $this.Audit-CriticalGroups()
        $this.Results.critical_groups = $groupResults
        
        # Audit user privileges
        $userResults = $this.Audit-UserPrivileges()
        $this.Results.user_privileges = $userResults
        
        # Generate privilege escalation risks
        $escalationRisks = $this.Generate-PrivilegeEscalationRisks()
        $this.Results.privilege_escalation_risks = $escalationRisks
        
        # Generate recommendations
        $recommendations = $this.Generate-SecurityRecommendations()
        $this.Results.recommendations = $recommendations
        
        Write-Host "[*] RBAC audit completed successfully"
    }
    
    # Save results to file
    [void] Save-Results() {
        if (-not $this.OutputFile) {
            $timestamp = (Get-Date).ToString("yyyyMMdd_HHmmss")
            $this.OutputFile = "rbac_audit_$timestamp.json"
        }
        
        try {
            $this.Results | ConvertTo-Json -Depth 10 | Out-File -FilePath $this.OutputFile -Encoding UTF8
            Write-Host "[*] Results saved to: $($this.OutputFile)"
        }
        catch {
            Write-Error "Error saving results: $($_.Exception.Message)"
        }
    }
    
    # Display summary
    [void] Show-Summary() {
        Write-Host "`n" + "="*60
        Write-Host "RBAC AUDIT SUMMARY"
        Write-Host "="*60
        
        Write-Host "Target Domain: $($this.TargetDomain)"
        Write-Host "Audit Timestamp: $($this.Results.audit_timestamp)"
        
        if ($this.Results.domain_info) {
            Write-Host "Domain Controller: $($this.Results.domain_info.domain_controller)"
            Write-Host "Total Users: $($this.Results.domain_info.total_users)"
            Write-Host "Total Groups: $($this.Results.domain_info.total_groups)"
        }
        
        Write-Host "`nCritical Groups Audited: $($this.Results.critical_groups.Count)"
        $highRiskGroups = $this.Results.critical_groups | Where-Object { $_.risk_level -in @("HIGH", "CRITICAL") }
        Write-Host "High Risk Groups: $($highRiskGroups.Count)"
        
        Write-Host "`nUsers Audited: $($this.Results.user_privileges.Count)"
        $highRiskUsers = $this.Results.user_privileges | Where-Object { $_.privilege_escalation_risk -in @("HIGH", "CRITICAL") }
        Write-Host "High Risk Users: $($highRiskUsers.Count)"
        
        Write-Host "`nPrivilege Escalation Risks: $($this.Results.privilege_escalation_risks.Count)"
        
        Write-Host "`nRecommendations: $($this.Results.recommendations.Count)"
        foreach ($rec in $this.Results.recommendations) {
            Write-Host "  [$($rec.priority)] $($rec.description)"
        }
        
        Write-Host "`n[*] RBAC audit completed successfully!"
    }
}

# Main execution
if ($Help) {
    Show-Help
    exit 0
}

try {
    # Create auditor instance
    $auditor = [RBACAuditor]::new($TargetDomain, $OutputFile)
    
    # Run audit
    $auditor.Run-Audit()
    
    # Save results
    $auditor.Save-Results()
    
    # Show summary
    $auditor.Show-Summary()
}
catch {
    Write-Error "Error during RBAC audit: $($_.Exception.Message)"
    exit 1
}

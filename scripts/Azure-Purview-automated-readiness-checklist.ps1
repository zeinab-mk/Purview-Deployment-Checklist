#requires -version 5.1
#requires -RunAsAdministrator
##requires -Module Az

<#
.SYNOPSIS
This script is aimed to help organizations verify missing RBAC and network access for various Azure Data Sources before registring and scanning Azure data sources in Azure Purview. 

.DESCRIPTION
This PowerShell script is aimed to assist Azure Subscriptions administrators to identify required RBAC and network access for Azure Purview Account to scan resources under a defined Management Group or a Subscription. 

PRE-REQUISITES:

1. Required PowerShell Modules:
    Az 
    Az.Synpase
    AzureAD

    Note: If you already have the Az modules installed, you may still encounter the following error:
        The script cannot be run because the following modules that are specified by the "#requires" statements of the script are missing: Az.at line:0 char:0
        To resolve this issue, please run the following command to import the Az modules into your current session:
        Import-Module -Name Az -Verbose

2. An Azure Purview Account.

3. Azure resources such as Storage Accounts, ADLS Gen2 Azure SQL Databases or Azure SQL Managed Instances.

4. Required minimum permissions to run the script:
    4.1 For BlobStorage: Reader on data sources' subscription or Management Group
    4.2 For ADLSGen1 and ADLSGen2: Reader on data sources' subscription or Management Group
    4.3 For AzureSQLDB: Azure SQL Admin user (Authentication method: Azure Active Directory Authentication) 
    4.4 For AzureSQLMI: Azure SQL Managed Identity Admin user (Authentication method: Azure Active Directory Authentication)
    4.5 For Azure Synapse: Read Key Vault and have access to get/list Azure Key Vault secret where Azure Synapse Admin credentials are stored.
    4.6 Azure AD (at least Global Reader) to read Azure AD users and Groups.
    4.7 Azure Reader role on data source subscription. 

5. SQLCMD    

.NOTES

CONTRIBUTORS
1. Zeinab Mokhtarian Koorabbasloo zeinam@microsoft.com

LEGAL DISCLAIMER:
This Code is provided for the purpose of assisting organizations to deploy Azure Purview. It should be tested prior using in production environment. Users are responsible for evaluating the impact on production environment. 
THIS SAMPLE CODE AND ANY RELATED INFORMATION ARE PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR PURPOSE. 
We grant You a nonexclusive, royalty-free right to use and modify the Sample Code and to reproduce and distribute the object code form of the Sample Code, provided that You agree:
(i) to not use Our name, logo, or trademarks to market Your software product in which the Sample Code is embedded;
(ii) to include a valid copyright notice on Your software product in which the Sample Code is embedded; and
(iii) to indemnify, hold harmless, and defend Us and Our suppliers from and against any claims or lawsuits, including attorneys' fees, that arise or result from the use or distribution of the Sample Code.
This posting is provided "AS IS" with no warranties, and confers no rights.

.LINK

1. https://docs.microsoft.com/en-us/azure/purview/overview
2. https://docs.microsoft.com/en-us/sql/tools/sqlcmd-utility?view=sql-server-ver15 



.COMPONENT
Azure Infrastructure, PowerShell

#>

Param
(
 [ValidateSet("BlobStorage", "AzureSQLMI", "AzureSQLDB", "ADLSGen2", "ADLSGen1", "Synapse", "All")]
 [string] $AzureDataType = ""
 
)

$ErrorActionPreference = 'Continue'
$WarningPreference ='silentlycontinue'

# Set-StrictMode -Version Latest

<#if (-not($skipAzModules))
{
    #region Az modules
    Install-Module -Name Az -AllowClobber -Verbose
    Import-Module -Name Az    
    #endregion Az modules
} # end if 
#>

<#Select Azure Data Source Type
Select one of the following Azure Data Sources to check readiness:
BlobStorage     for Azure Blob Storage
AzureSQLDB      for Azure SQL Database
AzureSQLMI      for Azure SQL Managed Instance
ADLSGen2        for Azure Data Lake Storage Gen 2
ADLSGen1        for Azure Data Lake Storage Gen 1
Synapse         for Azure Synapse Analytics
All             for all the above data sources 
 #>

write-host "`n"
Write-host "Please provide the required information! " -ForegroundColor blue

Do {
    $AzureDataType = Read-Host -Prompt "Type any of the following data sources: BlobStorage, ADLSGen2, ADLSGen1, AzureSQLDB, AzureSQLMI or type 'All' to check readiness for all data types"
}#end Do
Until ($AzureDataType -in "BlobStorage", "ADLSGen2", "ADLSGen1", "AzureSQLDB", "AzureSQLMI", "Synapse", "All")

Write-Host "$AzureDataType is selected as Data Source." -ForegroundColor Magenta

#Clear any possible cached credentials for other subscriptions
Clear-AzContext

#Login to Azure AD 
Write-Host "Please sign in with your Azure AD administrator account:"
Connect-AzureAD

#Authentication to Azure 

Login-AzAccount
Write-Host "Please sign in with your Azure administrator credentials:"


#List subscriptions
Get-AzSubscription | Format-table -Property Name, Id, tenantid, state

Write-host "Please provide the required information! " -ForegroundColor blue

Do
{
    ## Get Azure Subscription where Purview Account is created
	$PurviewSub = Read-Host -Prompt "Enter the name of your Azure Subscription where Azure Purview Account is deployed"
	
} #end Do
Until ($PurviewSub -in (Get-AzSubscription).Name)
Set-AzContext -Subscription $PurviewSub | Out-Null

#$tenantName = (Get-AzContext).Tenant
$PurviewSubContext = Get-AzContext
Write-Host "Subscription: $($PurviewSubContext.Name) is selected" -ForegroundColor Magenta

## Get Azure Purview Account
write-host "`n"
Write-host "Please provide the required information! " -ForegroundColor blue

$PurviewAccount = Read-Host -Prompt "Enter the name of your Azure Purview Account"
$Purviewlocation = (Get-AzResource -Name $PurviewAccount).Location

$PurviewAccountMSI = (Get-AzResource -Name $PurviewAccount).Identity.PrincipalId
If ($null -ne $PurviewAccountMSI) {
    Write-Host "Azure Purview Account $($PurviewAccount) is selected" -ForegroundColor Magenta
}else {
    Write-Host "There is no Managed Identity for Azure Purview Account $($PurviewAccount)! Terminating..." -ForegroundColor red
    Break
}
#Select readiness checklist scope

write-host "`n"
Write-host "Please provide the required information! " -ForegroundColor blue
Write-Host "Select the scope of your data sources to run the readiness check:"
Write-Host "1: Management Group"
Write-Host "2: Subscription"

Do 
{
    $Scope = Read-Host
}  #end Do
Until ($Scope -in "1","2")

$DataSourceSubsIds.clear()
$DataSourceSubsIds = [System.Collections.ArrayList]::new()

if ($Scope -eq "1") 
{
    Write-Host "Management Group is selected as data sources scope." -ForegroundColor Magenta
    
    ## List MGs
    Get-AzManagementGroup | Format-Table Name, DisplayName, Id
    Write-host "Please provide the required information! " -ForegroundColor blue
    Do 
    {
        #Get Top Level Azure Management Group 
        $TopLMG = Read-Host -Prompt "Enter the name of your top-level Azure Management Group where your data sources reside"
    }  #end Do
    Until ($TopLMG -in (Get-AzManagementGroup).Name)
    $TopLMG = Get-AzManagementGroup -GroupName $TopLMG 
   
    Write-Host "'$($TopLMG.Name)' is selected as Top-level Management Group." -ForegroundColor Magenta
    Write-Host ""
    Write-Host "Running readiness check on '$($TopLMG.Name)' Management Group..." -ForegroundColor Magenta
   
    $DataSourceMGs =  Get-AzManagementGroup 
    foreach ($DataSourceMG in $DataSourceMGs) {

        $DataSourceMG = Get-AzManagementGroup -GroupName $DataSourceMG.Name -Expand -Recurse
        if ((($null -ne $DataSourceMG.ParentId) -and (($DataSourceMG.ParentId.Equals($TopLMG.Id)))) -or ($DataSourceMG.Id.StartsWith($TopLMG.Id))) {
            foreach ($DataSourceChildMG in $DataSourceMG.Children) { #| Where-Object { $_.Type -eq "/subscriptions" }) {         
                if ($DataSourceChildMG.Type -eq "/subscriptions") {
                    $DataSourceChildMGSubId = $DataSourceChildMG.Id -replace '/subscriptions/',''
                    $DataSourceSubsIds.Add($DataSourceChildMGSubId)    
                }
                if ($DataSourceChildMG.Children.Type -eq "/subscriptions") {
                    $DataSourceChildMGSubId = $DataSourceChildMG.Children.Id -replace '/subscriptions/',''
                    $DataSourceSubsIds.Add($DataSourceChildMGSubId) 
                }

                if ($DataSourceChildMG.Children.Children.Type -eq "/subscriptions") {
                    $DataSourceChildMGSubId = $DataSourceChildMG.Children.Children.Id -replace '/subscriptions/',''
                    $DataSourceSubsIds.Add($DataSourceChildMGSubId) 
                }
            }    
        }    
    }    
    $DataSourceSubsIds = $DataSourceSubsIds | select -Unique
    Write-Host "The following Subscriptions are identified in the Management Group hierarchy:" -ForegroundColor Magenta
    $DataSourceSubsIds

}else{
    Write-Host "Subscription is selected as data sources scope." -ForegroundColor Magenta
    Get-AzSubscription | Format-table -Property Name, Id, tenantid, state
    write-host ""
    Write-host "Please provide the required information! " -ForegroundColor blue
    
    Do
    {
       # Get Azure Subscription
        $DataSub = Read-Host -Prompt "Enter the name of your Azure Subscription where your data sources reside"
        
    } #end Do
    Until ($DataSub -in (Get-AzSubscription).Name)
    $DataSub = Select-AzSubscription -SubscriptionName $DataSub
    Write-Host "Subscription: $($DataSub.Subscription.Name) is selected" -ForegroundColor Magenta
    write-host "`n"
    $DataSourceSubsIds.Add($DataSub.Subscription.id) 
} 
# Key Vault
#Validate if there is a KV in Purview RG
If (($AzureDataType -eq "all") -or ($AzureDataType -eq "AzureSQLDB") -or ($AzureDataType -eq "AzureSQLMI") -or ($AzureDataType -eq "Synapse")) {

    Set-AzContext -Subscription $PurviewSub | Out-Null
    $PurviewKVs = Get-AzKeyVault -ResourceGroupName (Get-AzResource -Name $PurviewAccount).ResourceGroupName
    If (!$PurviewKVs)
    {
        #Create Azure Key Vault and keep Authentication information to get access to Azure SQL and Azure SQL MI
        $random6 = -join ((48..57) + (97..122) | Get-Random -Count 6 | % {[char]$_})
        $PurviewKV = $PurviewAccount + "-kv-" + $random6
        $PurviewKV = New-AzKeyVault -Name $PurviewKV -ResourceGroupName (Get-AzResource -Name $PurviewAccount).ResourceGroupName -Location (Get-AzResource -Name $PurviewAccount).Location
    }else{
        #Validate if there is already a secret 
        foreach ($PurviewKV in $PurviewKVs)
        {
            $AzSQLCreds = Get-AzKeyVaultSecret -VaultName $PurviewKV.VaultName | Where-Object { $_.Name -eq "AzSQLCreds" }
        }          
    }
    
    If (!$AzSQLCreds){
    
        write-host "`n"
        Write-host "Please provide the required information! Enter Azure AD Admin's username and password to login to Azure SQL Servers:" -ForegroundColor blue
        $cred = Get-Credential
        $SecretString = ConvertTo-SecureString -AsPlainText -Force -String ($Cred.UserName + "`v" + $Cred.GetNetworkCredential().Password)
        
    }
        
        $PurviewKVAccessPolicy = @{
            ObjectId                  = $PurviewAccountMSI
            VaultName                 = $PurviewKV.VaultName
            ResourceGroupName         = $PurviewKV.ResourceGroupName
            PermissionsToSecrets      = @('Get','List')
        
        }
        Set-AzKeyVaultAccessPolicy @PurviewKVAccessPolicy
        $AzSQLCreds = Set-AzKeyVaultSecret -Name "AzSQLCreds" -VaultName $PurviewKV.VaultName -SecretValue $SecretString -ContentType 'PSCredential'
        $AzSQLCreds = $AzSQLCreds.SecretValue
}

#If Azure SQL Database (AzureSQLDB) is selected for Azure Data Sources
If (($AzureDataType -eq "all") -or ($AzureDataType -eq "AzureSQLDB")) {
    Write-Host ""
    Write-Host "Running readiness check for Azure SQL Servers..." -ForegroundColor Magenta
    Write-Host ""
    foreach ($DataSourceSubId in $DataSourceSubsIds)
    {             
        $DataSub = Select-AzSubscription -SubscriptionId $DataSourceSubId 
        Write-Host "Processing Subscription:'$($DataSub.Subscription.Name)' ID: '$($DataSub.Subscription.Id)'..." -ForegroundColor Magenta
        $AzureSqlServers = Get-AzSqlServer
        foreach ($AzureSqlServer in $AzureSqlServers) {
                   
            #Readiness check for SQL Servers  
            write-host ""
            Write-Host "Running readiness check on Azure SQL server: '$($AzureSqlServer.ServerName)'..." -ForegroundColor Magenta
                                  
            #Public endpoint enabled
                  
            If ($AzureSqlServer.PublicNetworkAccess -like 'False') {
                #Public EndPoint disabled
                Write-Output "Awareness! Public Endpoint is not allowd on Azure SQL server: '$($AzureSqlServer.ServerName)',verifying Private Endpoints..."

            }else {
                #Public EndPoint enabled
                       
                Write-Output "Awareness! Public Endpoint is allowed on Azure SQL server: '$($AzureSqlServer.ServerName)'"

            }

            #Private Endpoint enabled 
            $PrivateEndPoints = Get-AzPrivateEndpointConnection -PrivateLinkResourceId $AzureSqlServer.ResourceId
            if ($PrivateEndPoints.Count -ne 0) {
                Write-Host "Awareness! Private Endpoint is configured on Azure SQL Server: '$($PrivateEndPoints.Name)' on Azure SQL server: '$($AzureSqlServer.ServerName)'"
            }else {
                    Write-Host "Awareness! Private Endpoint is not configured on Azure SQL Server: '$($AzureSqlServer.ServerName)'"
                }
     
            #Verify Azure SQL Server Firewall settings

            $AzureSqlServerFw = Get-AzSqlServerFirewallRule -ServerName $AzureSqlServer.ServerName -ResourceGroup $AzureSqlServer.ResourceGroupName "Rule*"
            if (($AzureSqlServerFw.FirewallRuleName -contains "AllowAllWindowsAzureIps" ) -or $AzureSqlServerFw.FirewallRuleName -contains "AllowAllAzureIPs")
            {

                Write-Output "Passed! 'Allow Azure services and resources to access this server' is enabled on Azure SQL Server's Firewall: '$($AzureSqlServer.ServerName)'." 
            }else {
                #Azure IPs are not allowed to access Azure SQL Server
                
                Write-Host "Not Passed! 'Allow Azure services and resources to access this server' is not enabled on Azure SQL Server's Firewall: '$($AzureSqlServer.ServerName)'!" -ForegroundColor red
            }
                
            #Verify if AAD Admin is configured 
                    
            $AzSQLAADAdminConfigured = Get-AzSqlServerActiveDirectoryAdministrator -ServerName $AzureSqlServer.ServerName -ResourceGroup $AzureSqlServer.ResourceGroupName
            if (!$AzSQLAADAdminConfigured) {
                Write-Host "Not passed! Azure AD Admin is not configured for Azure SQL Server '$($AzureSqlServer.ServerName)!'" -ForegroundColor red
                Write-Host "Not passed! db_datareader role not granted to Azure Purview Account MSI for databases on '$($AzureSqlServer.ServerName)'!" -ForegroundColor red
            }else {
                Write-Host "Passed! Azure AD Admin '$($AzSQLAADAdminConfigured.DisplayName)' is configured for Azure SQL Server '$($AzureSqlServer.ServerName)!'"
                #Get databases in an Azure SQL Server 
                $AzureSQLDBs = Get-AzSqlDatabase -ServerName $AzureSqlServer.ServerName -ResourceGroup $AzureSqlServer.ResourceGroupName
                foreach ($AzureSQLDB in $AzureSQLDBs) {
                    if ($AzureSQLDB.DatabaseName -ne "master") {
                          
                        Write-Host "`n"
                        Write-Host "Connecting to '$($AzureSQLDB.DatabaseName)' on Azure SQL Server: '$($AzureSqlServer.ServerName)'..." -ForegroundColor Magenta
                        
                        $AzurePurviewMSISQLRole = sqlcmd -S $AzureSqlServer.FullyQualifiedDomainName -d $AzureSQLDB.DatabaseName -U ((([System.Net.NetworkCredential]::new("", $AzSQLCreds).Password) -Split "`v")[0]) -P ((([System.Net.NetworkCredential]::new("", $AzSQLCreds).Password) -Split "`v")[1]) -G -Q "SELECT r.name role_principal_name FROM sys.database_role_members rm JOIN sys.database_principals r ON rm.role_principal_id = r.principal_id JOIN sys.database_principals m ON rm.member_principal_id = m.principal_id where m.name = '$PurviewAccount'"

                        if (($null -ne $AzurePurviewMSISQLRole) -and ($AzurePurviewMSISQLRole -notlike "*Error*")) {
                            $AzurePurviewMSISQLRole = $AzurePurviewMSISQLRole.trim()
                            if (($AzurePurviewMSISQLRole.Contains("db_datareader")) -or ($AzurePurviewMSISQLRole.Contains("db_owner"))) {
                                Write-Output "Passed! db_datareader is granted to Azure Purview Account: '$PurviewAccount'."
                            }else {
                                Write-Host "Not Passed! db_datareader role not granted to Azure Purview Account: '$PurviewAccount' on Database: '$($AzureSQLDB.DatabaseName)' on Server:'$($AzureSqlServer.ServerName)'" -ForegroundColor red
                            } 

                        }
                                                            
                    }             
                } 
            }
        }
        Write-Host ""
        write-host "Readiness check completed for SQL Servers in '$($DataSub.Subscription.Name)'." -ForegroundColor Green
        write-host "-".PadRight(98, "-") -ForegroundColor Green
        write-host "`n"
    }
}

# If Azure SQL Managed Instance (AzureSQLMI) is selected for Azure Data Source
If (($AzureDataType -eq "all") -or ($AzureDataType -eq "AzureSQLMI")) {
    Write-Host ""
    Write-Host "Running readiness check for Azure SQL Managed Instances..." -ForegroundColor Magenta
    Write-Host ""    
    foreach ($DataSourceSubId in $DataSourceSubsIds)
    {             
        $DataSub = Select-AzSubscription -SubscriptionId $DataSourceSubId 
        Write-Host "Processing Subscription:'$($DataSub.Subscription.Name)' ID: '$($DataSub.Subscription.Id)'..." -ForegroundColor Magenta
        
        $AzureSqlMIs = Get-AzSqlInstance
        foreach ($AzureSqlMI in $AzureSqlMIs) {
                      
            #Readiness check for SQL Managed Instances  
            Write-Host ""
            Write-Host "Running readiness check on Azure SQL Managed Instance: '$($AzureSqlMI.ManagedInstanceName)'..." -ForegroundColor Magenta

            # Public / Private Endpoint    
            If ($AzureSqlMI.PublicDataEndpointEnabled -like 'False')
            {
                Write-Host "Not Passed! Public Endpoint is disabled on Azure SQL Managed Instance: '$($AzureSqlMI.ManagedInstanceName)'. Scanning Azure SQL Managed Instances through public endpoint is not yet supported by Purview!" -ForegroundColor red
            }else{
                Write-Host "Passed! Public Endpoint is enabled on Azure SQL Managed Instance: '$($AzureSqlMI.ManagedInstanceName)'."
            }    
                                        
            #Verify NSG Rules
                
            If ($AzureSqlMI.ProxyOverride = "Redirect") {
                #ProxyOverride is Redirect
                $AzureSQLMIPorts = "11000-11999"
                Write-Host "Azure SQL Managed Instance:'$($AzureSqlMI.ManagedInstanceName)' is configured as 'Redirect'. Checking ports 11000-11999 and 1433 in NSG rules..."
            }else {
                #ProxyOverride is Proxy (default) 
                $AzureSQLMIPorts = 3342
                Write-Host "Azure SQL Managed Instance:'$($AzureSqlMI.ManagedInstanceName)' is configured as 'Proxy'. Checking port 3342 in NSG rules..."
            }

            $AzureSqlMISubnet = $AzureSqlMI.SubnetId
            $AzureSqlMISubnet =  Get-AzVirtualNetworkSubnetConfig -ResourceId $AzureSqlMISubnet
            $nsg = $AzureSqlMISubnet.NetworkSecurityGroup
            $nsg = Get-AzResource -ResourceId $NSG.id
            $nsg = Get-AzNetworkSecurityGroup -Name $nsg.Name -ResourceGroupName $nsg.ResourceGroupName
            $NsgRules = $nsg.SecurityRules
            $nsgRuleAllowing = 0

            foreach ($nsgRule in $nsgRules) {
                if ((($nsgRule.Direction -eq "Inbound") -AND ($nsgRule.Access -eq "Allow" )) -And (($nsgRule.SourceAddressPrefix -eq "AzureCloud") -or ($nsgRule.SourceAddressPrefix -match $PurviewLocation) -or ($nsgRule.SourceAddressPrefix -eq "*")) -And (($nsgRule.Protocol -eq "TCP") -or ($nsgRule.Protocol -eq "*"))) {
                    if (($nsgRule.DestinationPortRange -eq "*") -or ($nsgRule.DestinationPortRange -contains $AzureSQLMIPorts)) {
                        Write-Host "Passed! NSG Rule:'$($nsgRule.Name)' in NSG: '$($NSG.Name)' allows Azure Purview to connect to Azure SQL Managed Instance '$($AzureSqlMI.ManagedInstanceName)' through port(s) $AzureSQLMIPorts."
                                $nsgRuleAllowing = 1
                    }else{
                        $nsgRulePortRanges = $nsgrule.DestinationPortRange -split ","
                        foreach ($nsgRulePortRange in $nsgRulePortRanges) {
                            if ($nsgRulePortRange -match "-") {
                                $nsgRulePortRangeLow, $nsgRulePortRangeHigh = $nsgRulePortRange -split "-"
                                    if (($AzureSQLMIPorts -le $nsgRulePortRangeHigh) -and ($AzureSQLMIPorts -ge $nsgRulePortRangeLow)) {
                                        Write-Host "Passed! NSG Rule:'$($nsgRule.Name)' in NSG: '$($NSG.Name)' allows Azure Purview to connect to Azure SQL Managed Instance '$($AzureSqlMI.ManagedInstanceName)' through port(s) $AzureSQLMIPorts."
                                        $nsgRuleAllowing = 1
                                    }
                                }
                            }
                        }		
                    }else{
                                  
                }
            }
                 
            if ($nsgRuleAllowing -eq 0) {
                Write-Host "Not Passed! No NSG rules inside '$($NSG.Name)' configured to allow Azure Purview to reach Azure SQL Managed Instance '$($AzureSqlMI.ManagedInstanceName)' through port(s) $AzureSQLMIPorts!" -ForegroundColor Red 
            }
                    
            #Checking port 1433
                    
            If ($AzureSqlMI.ProxyOverride = "Redirect") 
            {
                foreach ($nsgRule in $nsgRules) {
                    if ((($nsgRule.Direction -eq "Inbound") -AND ($nsgRule.Access -eq "Allow" )) -And (($nsgRule.SourceAddressPrefix -eq "AzureCloud") -or ($nsgRule.SourceAddressPrefix -match $PurviewLocation) -or ($nsgRule.SourceAddressPrefix -eq "*")) -And (($nsgRule.Protocol -eq "TCP") -or ($nsgRule.Protocol -eq "*"))) {
                        if (($nsgRule.DestinationPortRange -eq "*") -or ($nsgRule.DestinationPortRange -contains "1433")) {
                            Write-Host "Passed! NSG Rule:'$($nsgRule.Name)' in NSG: '$($NSG.Name)' allows Azure Purview to connect to Azure SQL Managed Instance '$($AzureSqlMI.ManagedInstanceName)' through port 1433."
                            $nsgRuleAllowing = 1
                        }else{
                            $nsgRulePortRanges = $nsgrule.DestinationPortRange -split ","
                            foreach ($nsgRulePortRange in $nsgRulePortRanges) {
                                if ($nsgRulePortRange -match "-") {
                                           
                                    $nsgRulePortRangeLow, $nsgRulePortRangeHigh = $nsgRulePortRange -split "-"
                                    if ((1433 -le $nsgRulePortRangeHigh) -and (1433 -ge $nsgRulePortRangeLow)) {
                                        Write-Host "Passed! NSG Rule:'$($nsgRule.Name)' in NSG: '$($NSG.Name)' allows Azure Purview to connect to Azure SQL Managed Instance '$($AzureSqlMI.ManagedInstanceName)' through ports 1433."
                                        $nsgRuleAllowing = 1
                                    }
                                }
                            }
                        }		
                    }else{
                                    
                }
            }
                      
            if ($nsgRuleAllowing -eq 0) {
                Write-Host "Not Passed! No NSG rules inside '$($NSG.Name)' configured to allow Azure Purview to reach Azure SQL Managed Instance '$($AzureSqlMI.ManagedInstanceName)' through port 1433!" -ForegroundColor Red 
            }
        }
                    
        #Verify if AAD Admin is configured
                    
        $AzSQLMIAADAdminConfigured = Get-AzSqlInstanceActiveDirectoryAdministrator -InstanceName $AzureSqlMI.ManagedInstanceName -ResourceGroup $AzureSqlMI.ResourceGroupName
                    
           if (!$AzSQLMIAADAdminConfigured) {
                        Write-Host "Not passed! Azure AD Admin is not configured for Azure SQL Managed Instance '$($AzureSqlMI.ManagedInstanceName)!'" -ForegroundColor red
                        Write-Host "Not passed! db_datareader role not granted to Azure Purview Account MSI for databases on '$($AzureSqlMI.ManagedInstanceName)'!" -ForegroundColor red
            }else {
                Write-Host "Passed! Azure AD Admin '$($AzSQLMIAADAdminConfigured.DisplayName)' is configured for Azure SQL Managed Instance $($AzureSqlMI.ManagedInstanceName)!'"
                        
                #Get databases in an Azure SQL Managed Instance 
                $AzureSQLMIDBs = Get-AzSqlInstanceDatabase -InstanceName $AzureSqlMI.ManagedInstanceName -ResourceGroup $AzureSqlMI.ResourceGroupName
                   
                foreach ($AzureSQLMIDB in $AzureSQLMIDBs) {
                    if (($AzureSQLMIDB.Name -ne "master") -or ($AzureSQLMIDB.Name -ne "model") -or ($AzureSQLMIDB.Name -ne "msdb") -or ($AzureSQLMIDB.Name -ne "tempdb")) 
                    {
                        $AzureSqlMIFQDN = $AzureSqlMI.ManagedInstanceName + ".public." + $AzureSqlMI.DnsZone +"."+ "database.windows.net,3342"
                        Write-Host "`n"
                        Write-Host "Connecting to '$($AzureSQLMIDB.Name)' on Azure SQL Managed Instance '$($AzureSqlMIFQDN)'" -ForegroundColor Magenta
                                                              
                        $AzurePurviewMSISQLMIRole = sqlcmd -S $AzureSqlMIFQDN -d $AzureSQLMIDB.Name -U ((([System.Net.NetworkCredential]::new("", $AzSQLCreds).Password) -Split "`v")[0]) -P ((([System.Net.NetworkCredential]::new("", $AzSQLCreds).Password) -Split "`v")[1]) -G -Q "SELECT r.name role_principal_name FROM sys.database_role_members rm JOIN sys.database_principals r ON rm.role_principal_id = r.principal_id JOIN sys.database_principals m ON rm.member_principal_id = m.principal_id where m.name = '$PurviewAccount'"
                                                                
                        if (($null -ne $AzurePurviewMSISQLMIRole) -and ($AzurePurviewMSISQLMIRole -notlike "*Error*")) {
                            $AzurePurviewMSISQLMIRole = $AzurePurviewMSISQLMIRole.trim()
                            if (($AzurePurviewMSISQLMIRole.Contains("db_datareader")) -or ($AzurePurviewMSISQLMIRole.Contains("db_owner"))) {
                                Write-Output "Passed! db_datareader is granted to Azure Purview Account: '$PurviewAccount'." 
                            }else {
                                Write-Host "Not Passed! db_datareader role not granted to Azure Purview Account: '$PurviewAccount' on Database: '$($AzureSQLMIDB.Name)' on Server:'$($AzureSqlMI.ManagedInstanceName)'" -ForegroundColor red
                            } 
    
                        }             
                    }
                }    

            }
        }
            
        write-host "Readiness check completed for Azure SQL Managed Instances in '$($DataSub.Subscription.Name)'." -ForegroundColor Green
        write-host "-".PadRight(98, "-") -ForegroundColor Green
        Write-host "`n"
    }       
}

# If Azure Storage Account (BlobStorage) is selected for Azure Data Source 

If (($AzureDataType -eq "all") -or ($AzureDataType -eq "BlobStorage"))
{
    Write-Host ""
    Write-Host "Running readiness check for Azure Storage Accounts..." -ForegroundColor Magenta
    Write-host ""
    
    $ControlPlaneRole = "Reader"

    If ($Scope -eq 1) #MG
    {
        Write-Host "Running readiness check for RBAC assignments for Azure Purview Account $PurviewAccount for Storage Accounts inside '$($TopLMG.Name)' Management Group..." -ForegroundColor Magenta
        $ExistingReaderRole = Get-AzRoleAssignment -ObjectId $PurviewAccountMSI -RoleDefinitionName $ControlPlaneRole -Scope $TopLMG.Id
    
    
    }else { #Sub
        Write-Host "Running readiness check for RBAC assignments for Azure Purview Account $PurviewAccount for Storage Accounts inside '$($DataSub.Subscription.Name)' Subscription..." -ForegroundColor Magenta
        $ExistingReaderRole = Get-AzRoleAssignment -ObjectId $PurviewAccountMSI -RoleDefinitionName $ControlPlaneRole
        }
     
    #Check if Reader role is assigned at scope
  
    if ($ExistingReaderRole.RoleDefinitionName -ne 'Reader') {
        Write-Host "Not Passed! Azure RBAC 'Reader' role is not assigned to Azure Purview Account: '$PurviewAccount'!" -ForegroundColor red
     }else {
        Write-Output "Passed! Azure RBAC 'Reader' role is assigned to Azure Purview Account: '$PurviewAccount'."
     }
    
    Write-Host ""
    $Role = "Storage Blob Data Reader"

    foreach ($DataSourceSubId in $DataSourceSubsIds)
    {             
        $DataSub = Select-AzSubscription -SubscriptionId $DataSourceSubId 
        Write-Host "Processing Subscription:'$($DataSub.Subscription.Name)' ID: '$($DataSub.Subscription.Id)'..." -ForegroundColor Magenta
        $AzureSqlServers = Get-AzSqlServer       

        #Verify whether RBAC is assigned
        $RBACScope = "/subscriptions/" + $DataSub.Subscription.Id
        $ExistingRole = Get-AzRoleAssignment -ObjectId $PurviewAccountMSI -RoleDefinitionName $Role -Scope $RBACScope
                        
        if (!$ExistingRole) {
              
            Write-Host "Not Passed! 'Storage Blob Data Reader' Azure RBAC role is not assigned to Azure Purview Account: '$PurviewAccount'!" -ForegroundColor Red
        }else {
            Write-Output "Passed! 'Storage Blob Data Reader' Azure RBAC role is assigned to  Azure Purview Account: '$PurviewAccount'." 
        }
                        
        $StorageAccounts = Get-AzstorageAccount
        Write-host ""
        Write-Host "Running readiness check on Azure Storage Accounts' Network Rules..." -ForegroundColor Magenta
        foreach ($StorageAccount in $StorageAccounts) {
                   
            # Verify if VNet Integration is enabled on Azure Storage Accounts in the subscription AND 'Allow trusted Microsoft services to access this storage account' is not enabled
            $StorageAccountNet = Get-AzStorageAccountNetworkRuleSet -ResourceGroupName $StorageAccount.ResourceGroupName -Name $StorageAccount.StorageAccountName
            If (($StorageAccountNet.DefaultAction -eq 'Deny') -AND ($StorageAccountNet.Bypass -Notlike "*AzureServices"))
            {
                Write-Host "Not Passed! 'Allow trusted Microsoft services to access this storage account' is not enabled on Storage Account: '$($StorageAccount.StorageAccountName)'!" -ForegroundColor red
                        
            }else {
                Write-Host "Passed! 'Allow trusted Microsoft services to access this storage account' is enabled on Storage Account: '$($StorageAccount.StorageAccountName)'."
            }
                   
            #Private Endpoint enabled 
            $PrivateEndPoints = Get-AzPrivateEndpointConnection -PrivateLinkResourceId $StorageAccount.Id
            if ($PrivateEndPoints.Count -ne 0) {
                Write-Host "Awareness! Private Endpoint is configured for Storage Account: '$($StorageAccount.StorageAccountName)': '$($PrivateEndPoints.Name)'"
            }else {
                Write-Host "Awareness! Private Endpoint is not configured on Storage Account: '$($StorageAccount.StorageAccountName)"
            }
            write-host ""
        }
         
        write-host "Readiness check completed for Storage Accounts in '$($DataSub.Subscription.Name)'." -ForegroundColor Green
        write-host "-".PadRight(98, "-") -ForegroundColor Green
        Write-host "`n" 
    }    
}

# If Azure Data Lake Storage Gen2 (ADLSGen2) is selected for Azure Data Source 
                   
If (($AzureDataType -eq "all") -or ($AzureDataType -eq "ADLSGen2"))
{
    Write-Host ""
    Write-Host "Running readiness check for Azure Data Lake Storage Gen 2..." -ForegroundColor Magenta
    Write-host ""

    If ($Scope -eq 1) #MG
    {
        Write-Host "Running readiness check for RBAC assignments for Azure Purview Account $PurviewAccount for Azure Data Lake Storage Gen 2 inside '$($TopLMG.Name)' Management Group..." -ForegroundColor Magenta
        $ExistingReaderRole = Get-AzRoleAssignment -ObjectId $PurviewAccountMSI -RoleDefinitionName $ControlPlaneRole -Scope $TopLMG.Id
    
    
    }else { #Sub
        Write-Host "Running readiness check for RBAC assignments for Azure Purview Account $PurviewAccount for Azure Data Lake Storage Gen 2 inside '$($DataSub.Subscription.Name)' Subscription..." -ForegroundColor Magenta
        $ExistingReaderRole = Get-AzRoleAssignment -ObjectId $PurviewAccountMSI -RoleDefinitionName $ControlPlaneRole
        }
     
    #Check if Reader role is assigned at scope
    
    $ControlPlaneRole = "Reader"    
    
    if ($ExistingReaderRole.RoleDefinitionName -ne 'Reader') {
        Write-Host "Not Passed! Azure RBAC 'Reader' role is not assigned to Azure Purview Account: '$PurviewAccount'!" -ForegroundColor red
     }else {
        Write-Output "Passed! Azure RBAC 'Reader' role is assigned to Azure Purview Account: '$PurviewAccount'." 
     }
    
    Write-Host "" 
    $Role = "Storage Blob Data Reader"

    foreach ($DataSourceSubId in $DataSourceSubsIds)
    {             
        $DataSub = Select-AzSubscription -SubscriptionId $DataSourceSubId 
        Write-Host "Processing Subscription:'$($DataSub.Subscription.Name)' ID: '$($DataSub.Subscription.Id)'..." -ForegroundColor Magenta
        $AzureSqlServers = Get-AzSqlServer
                
                       
        #Verify whether RBAC is assigned
        $RBACScope = "/subscriptions/" + $DataSub.Subscription.Id
        $ExistingRole = Get-AzRoleAssignment -ObjectId $PurviewAccountMSI -RoleDefinitionName $Role -Scope $RBACScope
                 
        if (!$ExistingRole) {
                   
            Write-Host "Not Passed! 'Storage Blob Data Reader' Azure RBAC role is not assigned to $PurviewAccount!" -ForegroundColor Red
        }else {
            Write-Output "Passed! 'Storage Blob Data Reader' Azure RBAC role is assigned to $PurviewAccount." 
        }
         
        $StorageAccounts = Get-AzStorageAccount | Where-Object {$_.EnableHierarchicalNamespace -eq 'True'}    
                                            
        Write-host ""
        Write-Host "Running readiness check on Azure Storage Accounts' Network Rules..." -ForegroundColor Magenta
        foreach ($StorageAccount in $StorageAccounts) {
                    
            # Verify if VNet Integration is enabled on Azure Storage Accounts in the subscription AND 'Allow trusted Microsoft services to access this storage account' is not enabled
            $StorageAccountNet = Get-AzStorageAccountNetworkRuleSet -ResourceGroupName $StorageAccount.ResourceGroupName -Name $StorageAccount.StorageAccountName
            If (($StorageAccountNet.DefaultAction -eq 'Deny') -AND ($StorageAccountNet.Bypass -Notlike "*AzureServices"))
            {
                Write-Host "Not Passed! 'Allow trusted Microsoft services to access this storage account' is not enabled on Azure Data Lake Storage Gen 2: '$($StorageAccount.StorageAccountName)'!" -ForegroundColor red
            }else {
                Write-Host "Passed! 'Allow trusted Microsoft services to access this storage account' is enabled on Azure Data Lake Storage Gen 2: '$($StorageAccount.StorageAccountName)'."
            }
                    
            #Private Endpoint enabled 
            $PrivateEndPoints = Get-AzPrivateEndpointConnection -PrivateLinkResourceId $StorageAccount.Id
            if ($PrivateEndPoints.Count -ne 0) {
                Write-Host "Awareness! Private Endpoint is configured for Azure Data Lake Storage Gen 2: '$($StorageAccount.StorageAccountName)': '$($PrivateEndPoints.Name)'"
            }else {
                Write-Host "Awareness! Private Endpoint is not configured on Azure Data Lake Storage Gen 2: '$($StorageAccount.StorageAccountName)"
            }
            write-host ""
        }
            
        write-host "Readiness check completed for Azure Data Lake Storage Gen 2 in '$($DataSub.Subscription.Name)'." -ForegroundColor Green
        write-host "-".PadRight(98, "-") -ForegroundColor Green
        Write-host "`n" 
    }
}

# If Azure Data Lake Storage Gen1 (ADLSGen1) is selected for Azure Data Source 

If (($AzureDataType -eq "all") -or ($AzureDataType -eq "ADLSGen1")) {
    Write-Host ""
    Write-Host "Running readiness check for Azure Data Lake Storage Gen 1..." -ForegroundColor Magenta
    Write-host ""  
      
    foreach ($DataSourceSubId in $DataSourceSubsIds)
    {             
        $DataSub = Select-AzSubscription -SubscriptionId $DataSourceSubId 
        Write-Host "Processing Subscription:'$($DataSub.Subscription.Name)' ID: '$($DataSub.Subscription.Id)'..." -ForegroundColor Magenta
        Write-host ""
        Write-Host "Running readiness check on Azure Data Lake Storage Gen 1 Account' Network Rules and Permissions..." -ForegroundColor Magenta
        $AzureDataLakes = Get-AzDataLakeStoreAccount
        foreach ($AzureDataLake in $AzureDataLakes) {
                    
            # Verify if VNet Integration is enabled on Azure Data Lake Gen 1 Accounts in the subscription AND 'Allow all Azure services to access this Data Lake Storage Gen1 account' is not enabled
            $AzureDataLake = Get-AzDataLakeStoreAccount -name $AzureDataLake.Name
                  
            If (($AzureDataLake.FirewallState -eq 'Enabled') -and ($AzureDataLake.FirewallAllowAzureIps -eq 'Disabled')) {
                Write-Host "Not Passed! 'Allow all Azure services to access this Data Lake Storage Gen 1 account' is not enabled on Azure Data Lake Storage Gen 1 Account: '$($AzureDataLake.Name)'!" -ForegroundColor red
                        
            }else {
                Write-Host "Passed! 'Allow all Azure services to access this Data Lake Storage Gen 1 account' is enabled on Azure Data Lake Storage Gen 1 Account: '$($AzureDataLake.Name)'."
            }
                
            #Verify ACL
            $AzureDataLakeACLs = Get-AzDataLakeStoreItemAclEntry -Account $AzureDataLake.Name -Path / -ErrorAction SilentlyContinue -ErrorVariable error1
            if ($error1 -match "doesn't originate from an allowed virtual network, based on the configuration of the Azure Data Lake account") {
                #Missing network rules from client machine to ADLS Gen 1
                Write-host "Not Passed! Unable to access Azure Data Lake Storage Gen 1 Account: '$($AzureDataLake.Name)'! Update firewall rules to allow access from your IP Address!" -ForegroundColor red 
                      
            }else {
                        
                $missingacl = $null
                foreach ($AzureDataLakeACL in $AzureDataLakeACLs) {
                    if (($AzureDataLakeACL.Permission -match 'x') -and ($AzureDataLakeACL.Permission -match 'r') -and ($AzureDataLakeACL.id -eq $PurviewAccountMSI)) {
                        Write-host "Passed! 'Read' and 'Execute' permission is enabled for Azure Purview Account on Azure Data Lake Storage Gen 1 Account: '$($AzureDataLake.Name)'."
                        $missingacl = 1  
                        break
                    }
                }
                    
                if ($null -eq $missingacl) { Write-host "Not Passed! 'Read' and 'Execute' permission is not enabled for Azure Purview Account on Azure Data Lake Storage Gen 1 Account: '$($AzureDataLake.Name)'!" -ForegroundColor red }
                Write-host "`n"
            }    
        } 
               
        write-host "Readiness check completed for Azure Data Lake Storage Gen 1 Accounts in '$($DataSub.Subscription.Name)'." -ForegroundColor Green
        write-host "-".PadRight(98, "-") -ForegroundColor Green
        Write-host "`n"      
    }              
}

#If Azure Synapse (Synapse) is selected for Azure Data Sources
If (($AzureDataType -eq "all") -or ($AzureDataType -eq "synapse")) {
    Write-Host ""
    Write-Host "Running readiness check for Azure Synapse..." -ForegroundColor Magenta
    Write-Host ""

    $ControlPlaneRole = "Reader"

    If ($Scope -eq 1) #MG
    {
        Write-Host "Running readiness check for RBAC assignments for Azure Purview Account $PurviewAccount for Storage Accounts inside '$($TopLMG.Name)' Management Group..." -ForegroundColor Magenta
        $ExistingReaderRole = Get-AzRoleAssignment -ObjectId $PurviewAccountMSI -RoleDefinitionName $ControlPlaneRole -Scope $TopLMG.Id
    
    
    }else { #Sub
        Write-Host "Running readiness check for RBAC assignments for Azure Purview Account $PurviewAccount for Storage Accounts inside '$($DataSub.Subscription.Name)' Subscription..." -ForegroundColor Magenta
        $ExistingReaderRole = Get-AzRoleAssignment -ObjectId $PurviewAccountMSI -RoleDefinitionName $ControlPlaneRole
    }
     
    #Check if Reader role is assigned at scope
  
    if ($ExistingReaderRole.RoleDefinitionName -ne 'Reader') {
        Write-Host "Not Passed! Azure RBAC 'Reader' role is not assigned to Azure Purview Account: '$PurviewAccount'!" -ForegroundColor red
    }else {
        Write-Output "Passed! Azure RBAC 'Reader' role is assigned to Azure Purview Account: '$PurviewAccount'."
    }
    
    Write-Host ""
    $Role = "Storage Blob Data Reader"

    foreach ($DataSourceSubId in $DataSourceSubsIds)
    {             
        $DataSub = Select-AzSubscription -SubscriptionId $DataSourceSubId 
        Write-Host "Processing Subscription:'$($DataSub.Subscription.Name)' ID: '$($DataSub.Subscription.Id)'..." -ForegroundColor Magenta

        #Verify whether RBAC is assigned
        $RBACScope = "/subscriptions/" + $DataSub.Subscription.Id
        $ExistingRole = Get-AzRoleAssignment -ObjectId $PurviewAccountMSI -RoleDefinitionName $Role -Scope $RBACScope
                        
        if (!$ExistingRole) {
                   
            Write-Host "Not Passed! 'Storage Blob Data Reader' Azure RBAC role is not assigned to Azure Purview Account: '$PurviewAccount'!" -ForegroundColor Red
        }else {
            Write-Output "Passed! 'Storage Blob Data Reader' Azure RBAC role is assigned to  Azure Purview Account: '$PurviewAccount'." 
        }

        $AzureSynapseWorkspaces = Get-AzSynapseWorkspace
        foreach ($AzureSynapseWorkspace in $AzureSynapseWorkspaces) {
                
            #Readiness check for Synapse Workspaces  
            write-host ""
            Write-Host "Running readiness check on Azure Synapse Workspace: '$($AzureSynapseWorkspace.Name)'..." -ForegroundColor Magenta
                                     
            #Public endpoint enabled
                    
            If ($AzureSynapseWorkspace.PublicNetworkAccess -like 'False') {
                #Public EndPoint disabled
                Write-Output "Awareness! Public Endpoint is not allowed on Azure Synapse Workspace: '$($AzureSynapseWorkspace.Name)',verifying Private Endpoints..."
        
            }else 
            {
                #Public EndPoint enable         
                Write-Output "Awareness! Public Endpoint is allowed on Azure Synapse Workspace: '$($AzureSynapseWorkspace.Name)'"
            }

            #Private Endpoint enabled 
            $PrivateEndPoints = Get-AzPrivateEndpointConnection -PrivateLinkResourceId $AzureSynapseWorkspace.Id -ErrorAction SilentlyContinue -ErrorVariable error2
            if ($PrivateEndPoints.Count -ne 0) {
                Write-Host "Awareness! Private Endpoint is configured on Azure Synapse Workspace: '$($PrivateEndPoints.Name)' on Azure Synapse Workspace: '$($AzureSynapseWorkspace.Name)'"
            }else {
                Write-Host "Awareness! Private Endpoint is not configured on Azure Synapse Workspace: '$($AzureSynapseWorkspace.Name)'"
            }
            
            #Verify Azure Synapse Workspace Firewall settings

            $AzureSynapseServerFw = Get-AzSynapseFirewallRule -WorkspaceName $AzureSynapseWorkspace.Name 
            if (($AzureSynapseServerFw.FirewallRuleName -contains "AllowAllWindowsAzureIps" ) -or $AzureSynapseServerFw.FirewallRuleName -contains "AllowAllAzureIPs")
            {
                Write-Output "Passed! 'Allow Azure services and resources to access this server' is enabled on Azure Synapse Workspace's Firewall: '$($AzureSynapseWorkspace.Name)'." 
            }else {
                #Azure IPs are not allowed to access Azure Synapse Workspace
                Write-Host "Not Passed! 'Allow Azure services and resources to access this server' is not enabled on Azure Synapse Workspace's Firewall: '$($AzureSynapseWorkspace.Name)'!" -ForegroundColor red
            }
                                    
            #Verify if AAD Admin is configured 
            $AzSynapseAADAdminConfigured =  Get-AzSynapseSqlActiveDirectoryAdministrator -WorkspaceName $AzureSynapseWorkspace.Name 
            if (!$AzSynapseAADAdminConfigured) {
                Write-Host "Not passed! Azure AD Admin is not configured for Azure Synapse workspace '$($AzureSynapseWorkspace.Name)!'" -ForegroundColor red
                Write-Host "Not passed! db_datareader role not granted to Azure Purview Account MSI for databases on '$($AzureSynapseWorkspace.Name)'!" -ForegroundColor red
            }else {
                Write-Host "Passed! Azure AD Admin '$($AzSynapseAADAdminConfigured.DisplayName)' is configured for Azure Synapse workspace '$($AzureSynapseWorkspace.Name)!'"
                #Get databases in an Azure Synapse workspace 
                $AzureSynapsePools = Get-AzSynapseSqlPool -WorkspaceName $AzureSynapseWorkspace.Name
                                                                 
                foreach ($AzureSynapsePool in $AzureSynapsePools) {
                    Write-Host "`n"
                    Write-Host "Connecting to '$($AzureSynapsePool.SqlPoolName)' on Azure Synapse Workspace: '$($AzureSynapseWorkspace.Name)'..." -ForegroundColor Magenta                                                
                                                            
                    $AzurePurviewMSISynapseRole = sqlcmd -S $AzureSynapseWorkspace.ConnectivityEndpoints.sql -d $AzureSynapsePool.SqlPoolName -I -U ((([System.Net.NetworkCredential]::new("", $AzSQLCreds).Password) -Split "`v")[0]) -P ((([System.Net.NetworkCredential]::new("", $AzSQLCreds).Password) -Split "`v")[1]) -G -Q "SELECT r.name role_principal_name FROM sys.database_role_members rm JOIN sys.database_principals r ON rm.role_principal_id = r.principal_id JOIN sys.database_principals m ON rm.member_principal_id = m.principal_id where m.name = '$PurviewAccount'"


                    if (($null -ne $AzurePurviewMSISynapseRole) -and ($AzurePurviewMSISynapseRole -notlike "*Error*")) {
                    $AzurePurviewMSISynapseRole = $AzurePurviewMSISynapseRole.trim()
                        if (($AzurePurviewMSISynapseRole.Contains("db_datareader")) -or ($AzurePurviewMSISynapseRole.Contains("db_owner"))) {
                            Write-Output "Passed! db_datareader is granted to Azure Purview Account: '$PurviewAccount'."
                        }else {
                            Write-Host "Not Passed! db_datareader role not granted to Azure Purview Account: '$PurviewAccount' on Database: '$($AzureSQLDB.DatabaseName)' on Server:'$($AzureSqlServer.ServerName)'" -ForegroundColor red
                        } 

                    }  
                } 
            }
                  
        }
        Write-Host ""
        write-host "Readiness check completed for Azure Synapse in '$($DataSub.Subscription.Name)'." -ForegroundColor Green
        write-host "-".PadRight(98, "-") -ForegroundColor Green
        write-host "`n"
    }
}
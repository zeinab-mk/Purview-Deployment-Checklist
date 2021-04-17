#requires -version 5.1
#requires -RunAsAdministrator
##requires -Module Az

<#
.SYNOPSIS
This script is aimed to help you to configure Azure Purview Managed Identity with required access level over your Azure resources across your subscriptions inside a top-level Management Group.

.DESCRIPTION
This PowerShell script is aimed to assist Azure Subscriptions administrators to set up required authentication using Azure Purview MSI to scan resources under a defined Management Group. 

PRE-REQUISITES:
1. If you already have the Az modules installed, you may still encounter the following error:
    The script cannot be run because the following modules that are specified by the "#requires" statements of the script are missing: Az.at line:0 char:0
    To resolve this issue, please run the following command to import the Az modules into your current session:
    Import-Module -Name Az -Verbose

2. An Azure Purview Account.
3. Azure resources such as Storage Accounts, ADLS Gen2 Azure SQL Databases or Azure SQL Managed Instances.
4. Required permissions to run the script and assign the permissions:
    4.1 For BlobStorage: Owner or User Access Administrator on data sources' subscriptions
    4.2 For ADLSGen2: Owner or User Access Administrator on data sources' subscriptions
    4.3 For AzureSQLDB: Azure SQL Admin user (Authentication method: Azure Active Directory Authentication) 
    4.4 For AzureSQLMI: Azure SQL Managed Identity Admin user (Authentication method: Azure Active Directory Authentication)
    4.5 Azure AD (at least Global Reader) to read Azure AD users and Groups.

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
 #   [ValidateSet("BlobStorage", "ADLSGen1", "ADLSGen2", "AzureSQLDB", "AzureSQLMI")]
 [string] $AzureDataType = "BlobStorage"
 
)

#$ErrorActionPreference = 'Continue'
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
Select one of the following Azure Data Sources type to assign required RBAC roles to your Azure Purview Account:
BlobStorage     for Azure Blob Storage
AzureSQLDB      for Azure SQL Database
ADLSGen2 for    Azure Data Lake Storage Gen 2
 #>

Write-host ""
Write-host "Please provide the required information! " -ForegroundColor blue

Do {
    $AzureDataType = Read-Host -Prompt "Type any of the following data sources: Type any of the following data sources: BlobStorage, ADLSGen2, ADLSGen1, AzureSQLDB or AzureSQLMI"
}#end Do
Until ($AzureDataType -in "BlobStorage", "ADLSGen2", "ADLSGen1", "AzureSQLDB", "AzureSQLMI")

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
Write-Host "Subscription: $($PurviewSubContext.Subscription.Name) is selected" -ForegroundColor Magenta

## Get Azure Purview Account
Write-host ""
Write-host "Please provide the required information! " -ForegroundColor blue
$PurviewAccount = Read-Host -Prompt "Enter the name of your Azure Purview Account"
$PurviewAccountMSI = (Get-AzResource -Name $PurviewAccount).Identity.PrincipalId

If ($null -ne $PurviewAccountMSI) {
    Write-Host "Azure Purview Account $($PurviewAccount) is selected" -ForegroundColor Magenta
}else {
    Write-Host "There is no Managed Identity for Azure Purview Account $($PurviewAccount)! Terminating..." -ForegroundColor red
    Break
}

<## List MGs
Get-AzManagementGroup | Format-Table Name, DisplayName, Id

Do 
{
    #Get Top Level Azure Management Group 
    $TopLMG = Read-Host -Prompt "Please enter the name of your top-level Azure Management Group where your Data Sources reside"
}  #end Do
Until ($TopLMG -in (Get-AzManagementGroup).Name)
$TopLMG = Get-AzManagementGroup -GroupName $TopLMG 

Write-Host "Top-level Management Group: '$($TopLMG.Name)' is selected" 
#>

write-host "`n"
Write-host "Please provide the required information! " -ForegroundColor blue
Write-Host "Select the scope of your data sources reside:"
Write-Host "1: Management Group"
Write-Host "2: Subscription"
#Write-Host "3" Resource Group"
Do 
{
    $Scope = Read-Host
}  #end Do
Until ($Scope -in "1","2")

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
    Set-AzContext -Subscription $DataSub | Out-Null
    $DataSub = Select-AzSubscription -SubscriptionName $DataSub

    #$tenantName = (Get-AzContext).Tenant
    $DataSubContext = Get-AzContext
    Write-Host "Subscription: $($DataSubContext.Subscription.Name) is selected" -ForegroundColor Magenta
    write-host "`n"

}

#If Azure SQL Database (AzureSQLDB) is selected for Azure Data Source
If ($AzureDataType -eq "AzureSQLDB") {

    Write-Host ""
    Write-Host "Processing Azure SQL Servers..." -ForegroundColor Magenta
    Write-host ""

    $DataSourceMGs = Get-AzManagementGroup 
    foreach ($DataSourceMG in $DataSourceMGs) {

        $DataSourceMG = Get-AzManagementGroup -GroupName $DataSourceMG.Name -Expand -Recurse
        if ($DataSourceMG.Id.StartsWith($TopLMG.Id)) {
            foreach ($DataSourceChildMG in $DataSourceMG.Children | Where-Object { $_.Type -eq "/subscriptions" }) {
                $DataSourceChildMGSubId = $DataSourceChildMG.Id -replace '/subscriptions/',''
                
                If ($Scope -eq 1) {
                    Write-Host "Processing Subscription:'$($DataSourceChildMG.DisplayName)' ID:$DataSourceChildMGSubId ..." -ForegroundColor Magenta
                    
                }else {
                    #Write-Host "Processing Subscription:'$($DataSub.Name)'." -ForegroundColor Magenta
                    $DataSourceChildMGSubId = $datasub.Subscription.Id
                    $DataSourceChildMG.DisplayName = $DataSub.Subscription.Name
                }            
                
                Select-AzSubscription -SubscriptionId $DataSourceChildMGSubId | Out-Null
                                            
                $AzureSqlServers = Get-AzSqlServer
                foreach ($AzureSqlServer in $AzureSqlServers) {

                    Write-Host "Verifying SQL Server: '$($AzureSqlServer.ServerName)'... " -ForegroundColor Magenta

                    #Public and Private endpoint 
                    $PrivateEndPoints = Get-AzPrivateEndpointConnection -PrivateLinkResourceId $AzureSqlServer.ResourceId
                    if ($PrivateEndPoints.Count -ne 0) {
                         Write-Host "Awareness! Private Endpoints: '$($PrivateEndPoints.Name)' is configured on Azure SQL server: '$($AzureSqlServer.ServerName)'."
                    }else {
                        Write-Host "Awareness! Private Endpoint is not configured on Azure SQL Server: '$($AzureSqlServer.ServerName), Verifying Firewall Rules...'."
                    }    
                    If ($AzureSqlServer.PublicNetworkAccess -like 'Enabled') {
                        #Public EndPoint enabled
                        Write-Output "Awareness! Public Endpoint is allowed on Azure SQL server: '$($AzureSqlServer.ServerName)'."
                        $AzureSqlServerFw = Get-AzSqlServerFirewallRule -ServerName $AzureSqlServer.ServerName -ResourceGroup $AzureSqlServer.ResourceGroupName "Rule*"
                        if (($AzureSqlServerFw.FirewallRuleName -contains "AllowAllWindowsAzureIps") -or ($AzureSqlServerFw.FirewallRuleName -contains "AllowAllAzureIPs"))
                        {
                            Write-Output "'Allow Azure services and resources to access this server' is enabled! No action is needed." 
                        }else {
                            #Azure IPs are not allowed to access Azure SQL Server
                            
                            Write-host ""
                            Write-host "Please provide the required information! " -ForegroundColor blue
                            Write-Output "'Allow Azure services and resources to access this server' is not enabled on Azure SQL Server: '$($AzureSqlServer.ServerName)'! You need to allow AzureServices to bypass." 
                            $Confirmation = Read-Host -Prompt "Press Y to enable 'Allow Azure services and resources to access this server' on SQL Server: '$($AzureSqlServer.ServerName)'."
                            if ($Confirmation -eq "Y") 
                            {
                                New-AzSqlServerFirewallRule -ResourceGroupName $AzureSqlServer.ResourceGroupName -ServerName $AzureSqlServer.ServerName -AllowAllAzureIPs
                                Write-Output "'Allow Azure services and resources to access this server' is now enabled on Azure SQL Server: '$($AzureSqlServer.ServerName)' "

                            }else {
                                    Write-Host "Skipping '$($AzureSqlServer.ServerName)'. Azure Purview will not be able to scan this Azure SQL Server!" -ForegroundColor Red
                            } 

                        }        
                    }
                   
                    #Verify / Assign Azure AD Admin 
                                  
                    $AzSQLAADAdminConfigured = Get-AzSqlServerActiveDirectoryAdministrator -ServerName $AzureSqlServer.ServerName -ResourceGroup $AzureSqlServer.ResourceGroupName
                    Write-host "Please provide the required information! " -ForegroundColor blue 
                    $AzSQLAADAdminPrompted = Read-Host -Prompt "Enter your Azure SQL Administrator account that is Azure AD Integrated on Azure SQL Server or enter a username to configure as Admin on the server: '$($AzureSqlServer.ServerName)'"
                    $AzSQLAADAdminPrompted = Get-AzureADUser -ObjectId $AzSQLAADAdminPrompted
                    $AzSQLAADAdminPromptedGroups = Get-AzureADUserMembership -ObjectId $AzSQLAADAdminPrompted.ObjectId  

                    If ($null -ne $AzSQLAADAdminConfigured){

                        # Azure AD Authentucation is enabled on Azure SQL Server
                        Write-Host "Verifying Azure AD Authentication on Azure SQL Server: '$($AzureSqlServer.ServerName)' ..." -ForegroundColor Magenta
                    
                    }else {
                        
                        # Azure AD Authentucation is not enabled on Azure SQL Server
                        Write-Host "Azure AD Authentication is not enabled on Azure SQL Server: '$($AzureSqlServer.ServerName)'!"
                        Write-host ""
                        Write-host "Please provide the required information! " -ForegroundColor blue
                        $Confirmation = Read-Host -Prompt "Press Y to enable Azure AD Authentication on SQL Server: '$($AzureSqlServer.ServerName)'"
                        if ($Confirmation -eq "Y") 
                        {
                            # Set Azure AD Authentication on Azure SQL Server
                            Set-AzSqlServerActiveDirectoryAdministrator -ServerName $AzureSqlServer.ServerName -ResourceGroupName $AzureSqlServer.ResourceGroupName -DisplayName $AzSQLAADAdminPrompted.DisplayName
                            Write-Output "Azure AD Authentication is now enabled for user: '$($AzSQLAADAdminPrompted.DisplayName)' on Azure SQL Server: '$($AzureSqlServer.ServerName)'"
                            $AzSQLAADAdminConfigured = Get-AzSqlServerActiveDirectoryAdministrator -ServerName $AzureSqlServer.ServerName -ResourceGroup $AzureSqlServer.ResourceGroupName 

                        }else {
                        Write-Host "Skipping '$($AzureSqlServer.ServerName)'. Azure Purview will not be able to scan this Azure SQL Server!" -ForegroundColor Red
                        } 
                    }    
                    #Assign SQL db_datareader Role to Azure Purview MSI on each Azure SQL Database 
                    $AzureSQLDBs = Get-AzSqlDatabase -ServerName $AzureSqlServer.ServerName -ResourceGroup $AzureSqlServer.ResourceGroupName
                    foreach ($AzureSQLDB in $AzureSQLDBs) {
                        if ($AzureSQLDB.DatabaseName -ne "master") {
                                             
                            #Validate if the provided admin user is actually configured as AAD Admin in Azure SQL Server
                            If (($AzSQLAADAdminConfigured.DisplayName -eq $AzSQLAADAdminPrompted.DisplayName) -OR ($AzSQLAADAdminPromptedGroups.ForEach({$_.ObjectId}) -contains $AzSQLAADAdminConfigured.ObjectId))

                            {

                            }else {    
                                Write-Output "'$($AzSQLAADAdminPrompted.UserPrincipalName)' is not Admin in Azure SQL Server:'$($AzureSqlServer.ServerName)'."
                                $Confirmation = Read-Host -Prompt "Press Y to enter new Administrator credentials to connect to Azure SQL Server"
                                if ($Confirmation -eq "Y") 
                                    {
                                        Write-host "Please provide the required information! " -ForegroundColor blue
                                        $AzSQLAADAdminPrompted = Read-Host -Prompt "Enter your Azure SQL Server Administrator account that is Azure AD Integrated"
                                        $AzSQLAADAdminPrompted = Get-AzureADUser -ObjectId $AzSQLAADAdminPrompted

                                    }else {
                                        Write-Host "Skipping '$($AzureSqlServer.ServerName)'. Azure Purview will not be able to scan this Azure SQL Server!" -ForegroundColor Red
                                    } 

                                }

                            sqlcmd -S $AzureSqlServer.FullyQualifiedDomainName -d $AzureSQLDB.DatabaseName -U $AzSQLAADAdminPrompted.UserPrincipalName -G -Q "CREATE USER [$PurviewAccount] FROM EXTERNAL PROVIDER; EXEC sp_addrolemember 'db_datareader', [$PurviewAccount];"
                            Write-Output "Azure SQL DB: db_datareader role is now assigned to $PurviewAccount in '$($AzureSQLDB.DatabaseName)' on Azure SQL Server '$($AzureSqlServer.ServerName)'."
                        }             
                    } 
                                
                write-host ""
                }
            
                Write-host "`n"
                write-host "Readiness deployment completed for Azure SQL Servers in '$($DataSourceChildMG.DisplayName)'." -ForegroundColor Green
                write-host "-".PadRight(98, "-") -ForegroundColor Green
                Write-host "`n" 
            }
            if ($Scope -eq 2) { break }    
        }
              
    }
}


# If Azure SQL Managed Instance (AzureSQLMI) is selected for Azure Data Source
If ($AzureDataType -eq "AzureSQLMI") {
    
    Write-Host "Processing Azure SQL Managed Instances ..." -ForegroundColor Magenta 
       
    $DataSourceMGs = Get-AzManagementGroup 
    foreach ($DataSourceMG in $DataSourceMGs) {

        $DataSourceMG = Get-AzManagementGroup -GroupName $DataSourceMG.Name -Expand -Recurse
        if ($DataSourceMG.Id.StartsWith($TopLMG.Id)) {
            foreach ($DataSourceChildMG in $DataSourceMG.Children | Where-Object { $_.Type -eq "/subscriptions" }) {
                $DataSourceChildMGSubId = $DataSourceChildMG.Id -replace '/subscriptions/',''


                If ($Scope -eq 1) {
                    Write-Host "Processing Subscription:'$($DataSourceChildMG.DisplayName)' ID:$DataSourceChildMGSubId ..." -ForegroundColor Magenta
                    
                }else {
                    #Write-Host "Processing Subscription:'$($DataSub.Name)'." -ForegroundColor Magenta
                    $DataSourceChildMGSubId = $datasub.Subscription.Id
                    $DataSourceChildMG.DisplayName = $DataSub.Subscription.Name
                }            
                
                Select-AzSubscription -SubscriptionId $DataSourceChildMGSubId | Out-Null
           
                $AzureSqlMIs = Get-AzSqlInstance
                foreach ($AzureSqlMI in $AzureSqlMIs) {
                      
                    #Verify if Public endpoint is enabled                    
                    If ($AzureSqlMI.PublicDataEndpointEnabled -like 'False')
                    {
                        Write-Output "Private endpoint is not yet supported by Azure Purview. Your organization must allow public endpoint in '$($AzureSqlMI.ManagedInstanceName)'."
                        $Confirmation = Read-Host -Prompt "Press Y to allow Public endpoint on your Azure SQL Managed Instance: '$($AzureSqlMI.ManagedInstanceName)'"
                        if ($Confirmation -eq "Y") 
                        {
                            Set-AzSqlInstance -Name $AzureSqlMI.ManagedInstanceName -ResourceGroupName $AzureSqlMI.ResourceGroupName -PublicDataEndpointEnabled $true -force
                            Write-Output "Public endpoint on your Azure SQL Managed Instance: '$($AzureSqlMI.ManagedInstanceName)'."

                        }else {
                            Write-Host "Skipping '$($AzureSqlMI.ManagedInstanceName)'. Azure Purview will not be able to scan this Azure SQL Managed Instance!" -ForegroundColor Red
                        } 
                    }
                    

                   #Verify and configure NSG Rules
                   
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
                    $Priority = $null
                    foreach ($nsgRule in $nsgRules) {
                        $Priority += @($NsgRule.Priority) 
                        if ((($nsgRule.Direction -eq "Inbound") -AND ($nsgRule.Access -eq "Allow" )) -And (($nsgRule.SourceAddressPrefix -eq "AzureCloud") -or ($nsgRule.SourceAddressPrefix -match $PurviewLocation) -or ($nsgRule.SourceAddressPrefix -eq "*")) -And (($nsgRule.Protocol -eq "TCP") -or ($nsgRule.Protocol -eq "*"))) {
                            if (($nsgRule.DestinationPortRange -eq "*") -or ($nsgRule.DestinationPortRange -contains $AzureSQLMIPorts)) {
                                Write-Host "NSG Rule:'$($nsgRule.Name)' in NSG: '$($NSG.Name)' allows Azure Purview to connect to Azure SQL Managed Instance '$($AzureSqlMI.ManagedInstanceName)' through port(s) $AzureSQLMIPorts. No action is needed."
                                $nsgRuleAllowing = 1
                            }else{
                                $nsgRulePortRanges = $nsgrule.DestinationPortRange -split ","
                                foreach ($nsgRulePortRange in $nsgRulePortRanges) {
                                    if ($nsgRulePortRange -match "-") {
                                        $nsgRulePortRangeLow, $nsgRulePortRangeHigh = $nsgRulePortRange -split "-"
                                        if (($AzureSQLMIPorts -le $nsgRulePortRangeHigh) -and ($AzureSQLMIPorts -ge $nsgRulePortRangeLow)) {
                                            Write-Host "NSG Rule:'$($nsgRule.Name)' in NSG: '$($NSG.Name)' allows Azure Purview to connect to Azure SQL Managed Instance '$($AzureSqlMI.ManagedInstanceName)' through port(s) $AzureSQLMIPorts. No action is needed."
                                            $nsgRuleAllowing = 1
                                        }
                                    }
                                }
                            }		
                        }else{
                                  
                        }
                    }
                  
                    if ($nsgRuleAllowing -eq 0) {
                        Write-Host "No NSG rules inside '$($NSG.Name)' configured to allow Azure Purview to reach Azure SQL Managed Instance '$($AzureSqlMI.ManagedInstanceName)' through port(s) $AzureSQLMIPorts!" 
                        
                        Write-host ""
                        Write-host "Please provide the required information! " -ForegroundColor blue
                        $Confirmation = Read-Host -Prompt "Press Y to create a new NSG rule and allow AzureCloud to access Azure SQL Managed Instance: '$($AzureSqlMI.ManagedInstanceName)'"
                        if ($Confirmation -eq "Y") 
                        {
                            $NSGRuleName = "AllowAzureCloudSQLMI"
                            $Priority = $Priority.Where({ 100 -le $_ })
                            $lowest = $Priority | sort-object | Select-Object -First 1
                            Do {
                            $lowest = $lowest + 1
                            }
                            Until (($lowest -notin $Priority) -and ($lowest -le 4096))

                            Add-AzNetworkSecurityRuleConfig -NetworkSecurityGroup $NSG -Name $NSGRuleName -Access Allow -Protocol tcp -Direction Inbound -Priority $lowest -SourceAddressPrefix "AzureCloud" -SourcePortRange * -DestinationAddressPrefix * -DestinationPortRange $AzureSQLMIPorts | Set-AzNetworkSecurityGroup        
                            Write-Output "A NSG Rule 'AllowAzureCloudINSQLMI' is added to '$($NSG.Name)'." 
                        }else {
                            Write-Host "Skipping '$($AzureSqlMI.ManagedInstanceName)'. Azure Purview will not be able to scan this Azure SQL Managed Instance!" -ForegroundColor Red
                        } 


                    }
                    
                    #Checking port 1433
                    
                    If ($AzureSqlMI.ProxyOverride = "Redirect") 
                    {
                        foreach ($nsgRule in $nsgRules) {
                            $Priority += @($NsgRule.Priority) 
                            if ((($nsgRule.Direction -eq "Inbound") -AND ($nsgRule.Access -eq "Allow" )) -And (($nsgRule.SourceAddressPrefix -eq "AzureCloud") -or ($nsgRule.SourceAddressPrefix -match $PurviewLocation) -or ($nsgRule.SourceAddressPrefix -eq "*")) -And (($nsgRule.Protocol -eq "TCP") -or ($nsgRule.Protocol -eq "*"))) {
                                if (($nsgRule.DestinationPortRange -eq "*") -or ($nsgRule.DestinationPortRange -contains "1433")) {
                                    Write-Host "NSG Rule:'$($nsgRule.Name)' in NSG: '$($NSG.Name)' allows Azure Purview to connect to Azure SQL Managed Instance '$($AzureSqlMI.ManagedInstanceName)' through port 1433.  No action is needed."
                                    $nsgRuleAllowing = 1
                                }else{
                                    $nsgRulePortRanges = $nsgrule.DestinationPortRange -split ","
                                    foreach ($nsgRulePortRange in $nsgRulePortRanges) {
                                        if ($nsgRulePortRange -match "-") {
                                            
                                            $nsgRulePortRangeLow, $nsgRulePortRangeHigh = $nsgRulePortRange -split "-"
                                            if ((1433 -le $nsgRulePortRangeHigh) -and (1433 -ge $nsgRulePortRangeLow)) {
                                                Write-Host "NSG Rule:'$($nsgRule.Name)' in NSG: '$($NSG.Name)' allows Azure Purview to connect to Azure SQL Managed Instance '$($AzureSqlMI.ManagedInstanceName)' through ports 1433. No action is needed."
                                                $nsgRuleAllowing = 1
                                            }
                                        }
                                    }
                                }		
                            }else{
                                      
                            }
                        }
                      
                        if ($nsgRuleAllowing -eq 0) {
                            Write-Host "No NSG rules inside '$($NSG.Name)' configured to allow Azure Purview to reach Azure SQL Managed Instance '$($AzureSqlMI.ManagedInstanceName)' through port 1433!"

                            Write-host ""
                            Write-host "Please provide the required information! " -ForegroundColor blue
                            $Confirmation = Read-Host -Prompt "Press Y to create a new NSG rule and allow AzureCloud to access Azure SQL Managed Instance through port 1433: '$($AzureSqlMI.ManagedInstanceName)'"
                            if ($Confirmation -eq "Y") 
                            {
                                $NSGRuleName = "AllowAzureCloud1433"
                                $Priority = $Priority.Where({ 100 -le $_ })
                                $lowest = $Priority | sort-object | Select-Object -First 1
                                Do {
                                $lowest = $lowest + 1
                                }
                                Until (($lowest -notin $Priority) -and ($lowest -le 4096))
                                
                                Add-AzNetworkSecurityRuleConfig -NetworkSecurityGroup $NSG -Name $NSGRuleName -Access Allow -Protocol tcp -Direction Inbound -Priority $lowest -SourceAddressPrefix "AzureCloud" -SourcePortRange * -DestinationAddressPrefix * -DestinationPortRange 1433 | Set-AzNetworkSecurityGroup        
                                Write-Output "A NSG Rule 'AllowAzureCloudINSQLMI' is added to '$($NSG.Name)'." 
                            }else {
                                Write-Host "Skipping '$($AzureSqlMI.ManagedInstanceName)'. Azure Purview will not be able to scan this Azure SQL Managed Instance!" -ForegroundColor Red
                            } 
    
                        }
                    }
                    write-host ""
                    Write-host "Please provide the required information! " -ForegroundColor blue
                    $AzSQLMIAADAdminPrompted = Read-Host -Prompt "Enter your Azure SQL Administrator account that is Azure AD Integrated or enter a username to configure as Admin on Azure SQL Managed Instance: '$($AzureSqlMI.ManagedInstanceName)'"
                    $AzSQLMIAADAdminPrompted = Get-AzureADUser -ObjectId $AzSQLMIAADAdminPrompted
                    $AzSQLMIAADAdminPromptedGroups = Get-AzureADUserMembership -ObjectId $AzSQLMIAADAdminPrompted.ObjectId     
                    
                    $AzSQLMIAADAdminConfigured = Get-AzSqlInstanceActiveDirectoryAdministrator -InstanceName $AzureSqlMI.ManagedInstanceName -ResourceGroup $AzureSqlMI.ResourceGroupName

                    If ($null -ne $AzSQLMIAADAdminConfigured) {
                        #AAD Authentication is configured on Azure SQL Managed Instance
                        Write-Host "Verifying Azure AD Authentication on Azure SQL Server: '$($AzureSqlMI.ManagedInstanceName)' ..." -ForegroundColor Magenta
                        
                    }else {
                        # Azure AD Authentucation is not enabled on Azure SQL Managed Instance
                        Write-Host "Azure AD Authentication is not enabled on Azure SQL Managed Instance: '$($AzureSqlMI.ManagedInstanceName)'!"
                        Write-host ""
                        Write-host "Please provide the required information! " -ForegroundColor blue
                        $Confirmation = Read-Host -Prompt "Press Y to enable Azure AD Authentication on Azure SQL Managed Instance: '$( $AzureSqlMI.ManagedInstanceName)'"
                        if ($Confirmation -eq "Y") 
                        {
                            
                        #Assign Azure Active Directory read permission to a Service Principal representing the SQL Managed Instance.
                        $AzureADReader = Get-AzureADDirectoryRole | Where-Object {$_.displayName -eq "Directory Readers"}
                        $AzureADReaderMember = Get-AzureADServicePrincipal -SearchString $AzureSqlMI.ManagedInstanceName

                        if ($null -eq $AzureADReader) {
                            # Instantiate an instance of the role template
                            $AzureADReaderTemplate = Get-AzureADDirectoryRoleTemplate | Where-Object {$_.displayName -eq "Directory Readers"}
                            Enable-AzureADDirectoryRole -RoleTemplateId $AzureADReaderTemplate.ObjectId
                            $AzureADReader = Get-AzureADDirectoryRole | Where-Object {$_.displayName -eq "Directory Readers"}
                        }

                        # Check if service principal is already member of readers role
                       $AzureADReaderMembers = Get-AzureADDirectoryRoleMember -ObjectId $AzureADReader.ObjectId
                       $selDirReader =$AzureADReaderMembers | where{$_.ObjectId -match $AzureADReaderMember.ObjectId}

                        if ($selDirReader -eq $null) {
                            # Add principal to AAD Readers role
                            Write-Host "Adding service principal '$($AzureSqlMI.ManagedInstanceName)' to 'Directory Readers' role'..."
                            Add-AzureADDirectoryRoleMember -ObjectId $AzureADReader.ObjectId -RefObjectId $AzureADReaderMember.ObjectId
                            Write-Output "'$($AzureSqlMI.ManagedInstanceName)' service principal is now added to 'Directory Readers' role'."
                            
                        }else {
                            Write-Output "Service principal '$($AzureSqlMI.ManagedInstanceName)' is already member of 'Directory Readers' role'."
                        }

                        # Set Azure AD Authentication on Azure Managed Instance
                        Set-AzSqlInstanceActiveDirectoryAdministrator -InstanceName $AzureSqlMI.ManagedInstanceName -ResourceGroup $AzureSqlMI.ResourceGroupName -DisplayName $AzSQLMIAADAdminPrompted.UserPrincipalName -ObjectId $AzSQLMIAADAdminPrompted.ObjectId
                        Write-Output "Azure AD Authentication is now enabled for user: '$($AzureSqlMI.ManagedInstanceName)' on Azure SQL Managed Instance: '$($AzureSqlMI.ManagedInstanceName)' "
                        $AzSQLMIAADAdminConfigured = Get-AzSqlInstanceActiveDirectoryAdministrator -InstanceName $AzureSqlMI.ManagedInstanceName -ResourceGroup $AzureSqlMI.ResourceGroupName 

                        }else {
                            Write-Host "Skipping '$($AzureSqlMI.ManagedInstanceName)'. Azure Purview will not be able to scan this Azure SQL Managed Instance!" -ForegroundColor Red
                        } 
                    }
                    
                    $AzureSQLMIDBs = Get-AzSqlInstanceDatabase -InstanceName $AzureSqlMI.ManagedInstanceName -ResourceGroup $AzureSqlMI.ResourceGroupName                        
                    foreach ($AzureSQLMIDB in $AzureSQLMIDBs) {
                        if (($AzureSQLMIDB.Name -ne "master") -or ($AzureSQLMIDB.Name -ne "model") -or ($AzureSQLMIDB.Name -ne "msdb") -or ($AzureSQLMIDB.Name -ne "tempdb")) 
                        {
                            $AzureSqlMIFQDN = $AzureSqlMI.ManagedInstanceName + ".public." + $AzureSqlMI.DnsZone +"."+ "database.windows.net,3342"
                            Write-Host "Connecting to '$($AzureSQLMIDB.Name)' on Azure SQL Manage Instance '$($AzureSqlMIFQDN)'..." -ForegroundColor Magenta

                            $AzSQLMIAADAdminConfigured = Get-AzSqlInstanceActiveDirectoryAdministrator -InstanceName $AzureSqlMI.ManagedInstanceName -ResourceGroup $AzureSqlMI.ResourceGroupName
                                
                            #Validate if the provided admin user is actually configured as AAD Admin in Azure SQL Managed Instance 

                            If (($AzSQLMIAADAdminConfigured.DisplayName -eq $AzSQLMIAADAdminPrompted.UserPrincipalName) -OR ($AzSQLMIAADAdminPromptedGroups.ForEach({$_.ObjectId}) -contains $AzSQLMIAADAdminConfigured.ObjectId))
                            {

                                }else {
                                    Write-Output "'$($AzSQLMIAADAdminPrompted.UserPrincipalName)' is not Admin in Azure SQL Managed Instance:'$($AzureSqlMI.ManagedInstanceName)'."
                                    $Confirmation = Read-Host -Prompt "Press Y to enter new Administrator credentials"
                                    if ($Confirmation -eq "Y") 
                                        {
                                            Write-host "Please provide the required information! " -ForegroundColor blue
                                            $AzSQLMIAADAdminPrompted = Read-Host -Prompt "Enter your Azure SQL Managed Instances Administrator account that is Azure AD Integrated"
                                            $AzSQLMIAADAdminPrompted = Get-AzureADUser -ObjectId $AzSQLMIAADAdminPrompted
                                   
                                        }else {
                                            Write-Host "Skipping '$($AzureSqlMIFQDN)'. Azure Purview will not be able to scan this Azure SQL Managed Instance!" -ForegroundColor Red
                                        } 
                                     
                                }

                                sqlcmd -S $AzureSqlMIFQDN -d $AzureSQLMIDB.Name -U $($AzSQLMIAADAdminPrompted.UserPrincipalName) -G -Q "CREATE USER [$PurviewAccount] FROM EXTERNAL PROVIDER; EXEC sp_addrolemember 'db_datareader', [$PurviewAccount];"
                                Write-Output  "Azure SQL DB: db_datareader role is now assigned to $PurviewAccount in '$($AzureSQLMIDB.Name)' on Azure SQL Managed Instance '$($AzureSQLMIDBs.ManagedInstanceName)'."   
                            }
                        }
   
                    }                
                    Write-host "`n"
                    write-host "Readiness deployment completed for Azure SQL Managed Instances in '$($DataSourceChildMG.DisplayName)'." -ForegroundColor Green
                    write-host "-".PadRight(98, "-") -ForegroundColor Green
                    Write-host "`n" 
                }
            if ($Scope -eq 2) { break } 
        }   
                
    }
}

# If Azure Storage Account (BlobStorage) or Azure Data Lake Gen 2 (ADLSGen2) is selected for Azure Data Source 

If (($AzureDataType -eq "BlobStorage") -or ($AzureDataType -eq "ADLSGen2"))
{
    Write-Host "Processing RBAC assignments for Azure Purview Account $($PurviewAccount) for $AzureDataType ..." -ForegroundColor Magenta
    
    $ControlPlaneRole = "Reader"
    
    #Check if Reader role is assigned at MG level
    
    $ExistingReaderRole = Get-AzRoleAssignment -ObjectId $PurviewAccountMSI -RoleDefinitionName $ControlPlaneRole -Scope $TopLMG.Id
    
    if (!$ExistingReaderRole) {
        #Assign Reader role to Azure Purview at MG 
        New-AzRoleAssignment -ObjectId $PurviewAccountMSI -RoleDefinitionName $ControlPlaneRole -Scope $TopLMG.Id  
        Write-Output "Azure RBAC 'Reader' role is now assigned to Azure Purview at the selected scope!"
     }else {
        Write-Output "Azure RBAC 'Reader' role is already assigned to Azure Purview at the selected scope. No action is needed." 
     }
    
    Write-Host ""
    $Role = "Storage Blob Data Reader"

    $DataSourceMGs = Get-AzManagementGroup 
    foreach ($DataSourceMG in $DataSourceMGs) {
    
        $DataSourceMG = Get-AzManagementGroup -GroupName $DataSourceMG.Name -Expand -Recurse
        if ($DataSourceMG.Id.StartsWith($TopLMG.Id)) {
            foreach ($DataSourceChildMG in $DataSourceMG.Children | Where-Object { $_.Type -eq "/subscriptions" }) {
                $DataSourceChildMGSubId = $DataSourceChildMG.Id -replace '/subscriptions/',''

                If ($Scope -eq 1) {
                    Write-Host "Processing Subscription:'$($DataSourceChildMG.DisplayName)' ID:$DataSourceChildMGSubId ..." -ForegroundColor Magenta
                    
                }else {
                    #Write-Host "Processing Subscription:'$($DataSub.Name)'." -ForegroundColor Magenta
                    $DataSourceChildMGSubId = $datasub.Subscription.Id
                    $DataSourceChildMG.DisplayName = $DataSub.Subscription.Name
                }            
                
                Select-AzSubscription -SubscriptionId $DataSourceChildMGSubId | Out-Null

                #Verify whether RBAC is already assigned, otherwise assign RBAC
                $ExistingRole = Get-AzRoleAssignment -ObjectId $PurviewAccountMSI -RoleDefinitionName $Role -Scope "/subscriptions/$DataSourceChildMGSubId"
                        
                if (!$ExistingRole) {
                   New-AzRoleAssignment -ObjectId $PurviewAccountMSI -RoleDefinitionName $Role -Scope "/subscriptions/$DataSourceChildMGSubId"  
                   Write-Output  "Azure RBAC 'Storage Blob Data Reader' role is now assigned to '$PurviewAccount' at '$($DataSourceChildMGSubId) Subscription'."
                }else {
                    Write-Output "Azure RBAC 'Storage Blob Data Reader' role is already assigned to '$PurviewAccount' at $DataSourceChildMGSubId Subscription. No action is needed." 
                }
            
                # Verify if VNet Integration is enabled on Azure Storage Accounts in the subscription AND 'Allow trusted Microsoft services to access this storage account' is not enabled
                
                # If ADLSGen2
                If ($AzureDataType -eq "ADLSGen2")
                {
                    $StorageAccounts = Get-AzStorageAccount | Where-Object {$_.EnableHierarchicalNamespace -eq 'True'}    
                }else
                {
                    $StorageAccounts = Get-AzstorageAccount
                }
                Write-Host ""             
                Write-Host "Verifying your Azure Storage Accounts Networks and Firewall Rules inside Azure Subscription: $DataSourceChildMGSubId ..." -ForegroundColor Magenta
                write-host ""
                foreach ($StorageAccount in $StorageAccounts) {
                    $StorageAccountNet = Get-AzStorageAccountNetworkRuleSet -ResourceGroupName $StorageAccount.ResourceGroupName -Name $StorageAccount.StorageAccountName
                    Write-Host "Verifying Storage Account: '$($StorageAccount.StorageAccountName)'... " -ForegroundColor Magenta

                    #Private Endpoint enabled 
                    $PrivateEndPoints = Get-AzPrivateEndpointConnection -PrivateLinkResourceId $StorageAccount.Id
                    if ($PrivateEndPoints.Count -ne 0) {
                        Write-Host "Awareness! Private Endpoint is configured for Storage Account: '$($StorageAccount.StorageAccountName)': '$($PrivateEndPoints.Name)'."
                    }else {
                        # No Private Endpoint
                        Write-Host "Awareness! Private Endpoint is not configured on Storage Account: '$($StorageAccount.StorageAccountName)'."                 
                        If (($StorageAccountNet.DefaultAction -eq 'Deny') -AND ($StorageAccountNet.Bypass -Notlike "*AzureServices"))
                        {
                            Write-host ""
                            Write-host "Please provide the required information! " -ForegroundColor blue
                            Write-Output "Firewall Rules detected on your Storage Account: '$($StorageAccount.StorageAccountName)'. You need to enable 'Allow trusted Microsoft services to access this storage account'." 
                            $Confirmation = Read-Host -Prompt "Press Y to enable 'Allow trusted Microsoft services to access this storage account' in Storage Account: '$($StorageAccount.StorageAccountName)'."
                            if ($Confirmation -eq "Y") 
                            {
                                $Bypass = $StorageAccountNet.Bypass + "AzureServices"
                                Update-AzStorageAccountNetworkRuleSet $StorageAccount.ResourceGroupName -Name $StorageAccount.StorageAccountName -Bypass $Bypass
                                Write-Output "'Allow trusted Microsoft services to access this storage account' is now enabled in your Azure Storage Account '$($StorageAccount.StorageAccountName)' Network Firewall Rule" 
                            }else {
                                Write-Host "Skipping '$($StorageAccount.StorageAccountName)'. Azure Purview will not be able to scan this Storage Account!" -ForegroundColor Red
                            } 
                        }else {
                             Write-Host "Public Endpoint is enabled with 'Allow trusted Microsoft services to access this storage account' in Storage Account: '$($StorageAccount.StorageAccountName)'. No action is needed." 
                        }
                    }
                    write-host ""
                }
                   
                Write-host "`n"
                write-host "Readiness deployment completed for Storage Accounts in '$($DataSourceChildMG.DisplayName)'." -ForegroundColor Green
                write-host "-".PadRight(98, "-") -ForegroundColor Green
                Write-host "`n" 
            }
            if ($Scope -eq 2) { break } 
        }
    }
}


# If Azure Data Lake Gen 1 (ADLSGen1) is selected for Azure Data Source 
If ($AzureDataType -eq "ADLSGen1") {
    Write-Host "Processing Azure Data Lake Storage Gen 1..." -ForegroundColor Magenta
    Write-host ""

    $DataSourceMGs = Get-AzManagementGroup 
    foreach ($DataSourceMG in $DataSourceMGs) {
    
        $DataSourceMG = Get-AzManagementGroup -GroupName $DataSourceMG.Name -Expand -Recurse
        if ($DataSourceMG.Id.StartsWith($TopLMG.Id)) {
            foreach ($DataSourceChildMG in $DataSourceMG.Children | Where-Object { $_.Type -eq "/subscriptions" }) {
                $DataSourceChildMGSubId = $DataSourceChildMG.Id -replace '/subscriptions/',''

                If ($Scope -eq 1) {
                    Write-Host "Processing Subscription:'$($DataSourceChildMG.DisplayName)' ID:$DataSourceChildMGSubId ..." -ForegroundColor Magenta
                    
                }else {
                    #Write-Host "Processing Subscription:'$($DataSub.Name)'." -ForegroundColor Magenta
                    $DataSourceChildMGSubId = $datasub.Subscription.Id
                    $DataSourceChildMG.DisplayName = $DataSub.Subscription.Name
                }            
                
                Select-AzSubscription -SubscriptionId $DataSourceChildMGSubId | Out-Null

                Write-host ""
                Write-Host "Verifying Azure Data Lake Storage Gen 1 Account' Network Rules and Permissions..." -ForegroundColor Magenta
                $AzureDataLakes = Get-AzDataLakeStoreAccount
                
                foreach ($AzureDataLake in $AzureDataLakes) {
                    
                    # Verify if VNet Integration is enabled on Azure Data Lake Gen 1 Accounts in the subscription AND 'Allow all Azure services to access this Data Lake Storage Gen1 account' is not enabled
                    $AzureDataLake = Get-AzDataLakeStoreAccount -name $AzureDataLake.Name 
                  
                    If (($AzureDataLake.FirewallState -eq 'Enabled') -and ($AzureDataLake.FirewallAllowAzureIps -eq 'Disabled')) {
                       
                       Write-host ""
                       Write-host "Please provide the required information! " -ForegroundColor blue
                       Write-Output "Firewall Rules detected on your Azure Data Lake Storage: '$($AzureDataLake.Name)'. You need to enable 'Allow all Azure services to access this Data Lake Storage Gen 1 account'." 
                       $Confirmation = Read-Host -Prompt "Press Y to enable 'Allow all Azure services to access this Data Lake Storage Gen 1 account' in Storage Account: '$($AzureDataLake.Name)'."
                       if ($Confirmation -eq "Y") 
                       {
                                          
                           set-AzDataLakeStoreAccount -AllowAzureIpState Enabled -Name $AzureDataLake.Name
                           Write-Output "'Allow all Azure services to access this Data Lake Storage Gen 1 account' is now enabled in your Azure Storage Account '$($StorageAccount.StorageAccountName)' Network Firewall Rule" 
                       }else {
                           Write-Host "Skipping '$($AzureDataLake.Name)'. Azure Purview will not be able to scan this Storage Account!" -ForegroundColor Red
                       } 
                        
                    }else {
                        Write-Host "'Allow all Azure services to access this Data Lake Storage Gen 1 account' is enabled on Azure Data Lake Storage Gen 1 Account: '$($AzureDataLake.Name)'. No action is needed."
                    }
                
                    #Set ACL
                    $AzureDataLakeACLs = Get-AzDataLakeStoreItemAclEntry -Account $AzureDataLake.Name -Path / -ErrorAction SilentlyContinue -ErrorVariable error1
                    if ($error1 -match "doesn't originate from an allowed virtual network, based on the configuration of the Azure Data Lake account") {
                        #Missing network rules from client machine to ADLS Gen 1
                        Write-host "Unable to access Azure Data Lake Storage Gen 1 Account: '$($AzureDataLake.Name)'! Update firewall rules to allow access from your IP Address!" -ForegroundColor red 
                      
                    }else {
                        $missingacl = $null
                        foreach ($AzureDataLakeACL in $AzureDataLakeACLs) {
                            if (($AzureDataLakeACL.Permission -match 'x') -and ($AzureDataLakeACL.Permission -match 'r') -and ($AzureDataLakeACL.id -eq $PurviewAccountMSI)) {
                                Write-host "'Read' and 'Execute' permission is enabled for Azure Purview Account on Azure Data Lake Storage Gen 1 Account: '$($AzureDataLake.Name)'. No action is needed."
                                $missingacl = 1  
                                break
                            }
                        }
                        if ($null -eq $missingacl) { 
                                        
                            Write-host ""
                            Write-host "Please provide the required information! " -ForegroundColor blue
                            Write-Output "'Read' and 'Execute' permission is not enabled for Azure Purview Account on Azure Data Lake Storage Gen 1 Account: '$($AzureDataLake.Name)'!" 
                            $Confirmation = Read-Host -Prompt "Press Y to add Read' and 'Execute' permission to '$AzurePurview' on Data Lake Storage Gen 1 account' in Storage Account: '$($AzureDataLake.Name)'"
                            if ($Confirmation -eq "Y") 
                            {

                                Set-AzDataLakeStoreItemAclEntry -Account $AzureDataLake.Name -Path / -Permissions ReadExecute -AceType user -id $PurviewAccountMSI -Recurse
                                Write-Output "'Read' and 'Execute' permission is now enabled for Azure Purview Account on Azure Data Lake Storage Gen 1 Account: '$($AzureDataLake.Name)'."
                        }else {
                            Write-Host "Skipping '$($AzureDataLake.Name)'. Azure Purview will not be able to scan this Data Lake Storage Account!" -ForegroundColor Red
                        } 

                        }
                    }
                         
                    Write-host "`n"
                } 
                
                write-host "Readiness deployment completed for Azure Data Lake Storage Gen 1 Accounts in '$($DataSourceChildMG.DisplayName)'." -ForegroundColor Green
                write-host "-".PadRight(98, "-") -ForegroundColor Green
                Write-host "`n"                    
            }  
            if ($Scope -eq 2) { break }
        }    
    
    
    }
    
}
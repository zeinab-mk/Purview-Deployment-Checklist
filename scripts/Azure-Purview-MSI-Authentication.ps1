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

1. https://docs.microsoft.com/en-us/sql/tools/sqlcmd-utility?view=sql-server-ver15 


.COMPONENT
Azure Infrastructure, PowerShell

#>

Param
(
 #   [ValidateSet("BlobStorage", "ADLSGen2", "AzureSQLDB", "ADLSGen2")]
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

Do {
    $AzureDataType = Read-Host -Prompt "Please type any of the following data sources; BlobStorage, ADLSGen2, AzureSQLDB or AzureSQLMI"
}#end Do
Until ($AzureDataType -in "BlobStorage", "ADLSGen2", "AzureSQLDB", "AzureSQLMI")

Write-Output "$AzureDataType is selected as Data Source."


#Clear any possible cached credentials for other subscriptions
Clear-AzContext

#Login to Azure AD 
Write-Host "Please sign in with your Azure AD administrator account"
Connect-AzureAD

#Authentication to Azure 

Login-AzAccount
Write-Host "Please sign in with your Azure administrator credentials"

#List subscriptions
Get-AzSubscription | Format-table -Property Name, Id, tenantid, state

Do
{
    ## Get Azure Subscription where Purview Account is created
	$PurviewSub = Read-Host -Prompt "Please enter the name of your Azure Subscription where Azure Purview Account is deployed"
	
} #end Do
Until ($PurviewSub -in (Get-AzSubscription).Name)
Set-AzContext -Subscription $PurviewSub | Out-Null

#$tenantName = (Get-AzContext).Tenant
$PurviewSubContext = Get-AzContext
Write-Host "Subscription: $($PurviewSubContext.Name) is selected"

## Get Azure Purview Account
$PurviewAccount = Read-Host -Prompt "Please enter the name of your Azure Purview Account"
$PurviewAccountMSI = (Get-AzResource -Name $PurviewAccount).Identity.PrincipalId
Write-Host "Azure Purview Account $($PurviewAccount) is selected"

## List MGs
Get-AzManagementGroup | Format-Table Name, DisplayName, Id

Do 
{
    #Get Top Level Azure Management Group 
    $TopLMG = Read-Host -Prompt "Please enter the name of your top-level Azure Management Group where your Data Sources reside"
}  #end Do
Until ($TopLMG -in (Get-AzManagementGroup).Name)
$TopLMG = Get-AzManagementGroup -GroupName $TopLMG 

Write-Host "Top-level Management Group: '$($TopLMG.Name)' is selected" 


#If Azure SQL Database (AzureSQLDB) is selected for Azure Data Source
If ($AzureDataType -eq "AzureSQLDB") {

    Write-Output "Processing role assignments for Azure Purview Account $PurviewAccount for $AzureDataType inside '$($TopLMG.Name)' Management Group" 
        
    $AzSQLAADAdminPrompted = Read-Host -Prompt "Please enter your Azure SQL Administrator account that is Azure AD Integrated"
    
    $AzSQLAADAdminPrompted = Get-AzureADUser -ObjectId $AzSQLAADAdminPrompted
    $AzSQLAADAdminPromptedGroups = Get-AzureADUserMembership -ObjectId $AzSQLAADAdminPrompted.ObjectId


    $DataSourceMGs = Get-AzManagementGroup 
    foreach ($DataSourceMG in $DataSourceMGs) {

        $DataSourceMG = Get-AzManagementGroup -GroupName $DataSourceMG.Name -Expand -Recurse
        if ($DataSourceMG.Id.StartsWith($TopLMG.Id)) {
            foreach ($DataSourceChildMG in $DataSourceMG.Children | Where-Object { $_.Type -eq "/subscriptions" }) {
                $DataSourceChildMGSubId = $DataSourceChildMG.Id -replace '/subscriptions/',''
                Write-Output "Processing Subscription Name:'$($DataSourceChildMG.DisplayName)' ID:$DataSourceChildMGSubId"
                Select-AzSubscription -SubscriptionId $DataSourceChildMGSubId
            
                $AzureSqlServers = Get-AzSqlServer
                foreach ($AzureSqlServer in $AzureSqlServers) {
                   
                    #Assign SQL db_datareader Role to Azure Purview MSI on each Azure SQL Database 
                    $AzureSQLDBs = Get-AzSqlDatabase -ServerName $AzureSqlServer.ServerName -ResourceGroup $AzureSqlServer.ResourceGroupName
                    
                    foreach ($AzureSQLDB in $AzureSQLDBs) {
                        if ($AzureSQLDB.DatabaseName -ne "master") {

                            Write-output "Connecting to '$($AzureSQLDB.DatabaseName)' on Azure SQL Server: '$($AzureSqlServer.ServerName)'"

                            $AzSQLAADAdminConfigured = Get-AzSqlServerActiveDirectoryAdministrator -ServerName $AzureSqlServer.ServerName -ResourceGroup $AzureSqlServer.ResourceGroupName

                            #Validate if the provided admin user is actually configured as AAD Admin in Azure SQL Server

                            If (($AzSQLAADAdminConfigured.DisplayName -eq $AzSQLAADAdminPrompted.UserPrincipalName) -OR ($AzSQLAADAdminPromptedGroups.ForEach({$_.ObjectId}) -contains $AzSQLAADAdminConfigured.ObjectId))

                            {

                            }else {    
                                Write-Output "'$($AzSQLAADAdminPrompted.UserPrincipalName)' is not Admin in Azure SQL Server:'$($AzureSqlServer.ServerName)'."
                                $Confirmation = Read-Host -Prompt "Press Y to enter new Administrator credentials to connect to Azure SQL Server"
                                if ($Confirmation -eq "Y") 
                                {
                                    $AzSQLAADAdminPrompted = Read-Host -Prompt "Please enter your Azure SQL Server Administrator account that is Azure AD Integrated"
                                    $AzSQLAADAdminPrompted = Get-AzureADUser -ObjectId $AzSQLAADAdminPrompted

                                }else {
                                    Write-Output "Skipping '$($AzureSqlServer.ServerName)'. Azure Purview will not be able to scan this Azure SQL Server!"
                                } 

                            }

                            sqlcmd -S $AzureSqlServer.FullyQualifiedDomainName -d $AzureSQLDB.DatabaseName -U $AzSQLAADAdminPrompted.UserPrincipalName -G -Q "CREATE USER [$PurviewAccount] FROM EXTERNAL PROVIDER; EXEC sp_addrolemember 'db_datareader', [$PurviewAccount];"
                            Write-Output "Azure SQL DB: db_datareader role is now assigned to $PurviewAccount in '$($AzureSQLDB.DatabaseName)' on Azure SQL Server '$($AzureSqlServer.ServerName)'"
                        }             
                    } 
                
                  #Verify Azure SQL Server Firewall settings

                  $AzureSqlServerFw = Get-AzSqlServerFirewallRule -ServerName $AzureSqlServer.ServerName -ResourceGroup $AzureSqlServer.ResourceGroupName "Rule*"
                  if ($AzureSqlServerFw.FirewallRuleName -contains "AllowAllWindowsAzureIps")
                  {

                  }else {
                      #Azure IPs are not allowed to access Azure SQL Server
                      
                      Write-Output "Azure services are not allowed to access Azure SQL Server '$($AzureSqlServer.ServerName)'. You would need to allow AzureServices to bypass." 
                      $Confirmation = Read-Host -Prompt "Press Y to allow AzureServices to access Azure SQL Server: '$($AzureSqlServer.ServerName)'"
                      if ($Confirmation -eq "Y") 
                      {
                        New-AzSqlServerFirewallRule -ResourceGroupName $AzureSqlServer.ResourceGroupName -ServerName $AzureSqlServer.ServerName -AllowAllAzureIPs
                        Write-Output "AzureServices IP addresses are added to Network Firewall Rules on Azure SQL Server: '$($AzureSqlServer.ServerName)' "

                      }else {
                          Write-Output "Skipping '$($AzureSqlServer.ServerName)'. Azure Purview will not be able to scan this Azure SQL Server!"
                      }
                  }
                
                }
             
            }
        }
    }

}


# If Azure SQL Managed Instance (AzureSQLMI) is selected for Azure Data Source
If ($AzureDataType -eq "AzureSQLMI") {
    
    Write-Output "Processing role assignments for Azure Purview Account $PurviewAccount for $AzureDataType inside '$($TopLMG.Name)' Management Group" 
    $AzSQLMIAADAdminPrompted = Read-Host -Prompt "Please enter your Azure SQL Managed Instances Administrator account that is Azure AD Integrated"

    $AzSQLMIAADAdminPrompted = Get-AzureADUser -ObjectId $AzSQLMIAADAdminPrompted
    $AzSQLMIAADAdminPromptedGroups = Get-AzureADUserMembership -ObjectId  $AzSQLMIAADAdminPrompted.ObjectId


    $DataSourceMGs = Get-AzManagementGroup 
    foreach ($DataSourceMG in $DataSourceMGs) {

        $DataSourceMG = Get-AzManagementGroup -GroupName $DataSourceMG.Name -Expand -Recurse
        if ($DataSourceMG.Id.StartsWith($TopLMG.Id)) {
            foreach ($DataSourceChildMG in $DataSourceMG.Children | Where-Object { $_.Type -eq "/subscriptions" }) {
                $DataSourceChildMGSubId = $DataSourceChildMG.Id -replace '/subscriptions/',''
                Write-Output "Processing Subscription Name:'$($DataSourceChildMG.DisplayName)' ID:$DataSourceChildMGSubId"
                Select-AzSubscription -SubscriptionId $DataSourceChildMGSubId
            
                $AzureSqlMIs = Get-AzSqlInstance
                foreach ($AzureSqlMI in $AzureSqlMIs) {
                      
                    #Verify if Public endpoint is enabled                    
                    If ($AzureSqlMI.PublicDataEndpointEnabled -like 'False')
                    {
                        Write-Output "Private endpoint is not yet supported by Azure Purview. Your organization must allow public endpoint on '$($AzureSqlMI.ManagedInstanceName)'"
                        $Confirmation = Read-Host -Prompt "Press Y to allow Public endpoint on your Azure SQL Managed Instance: '$($AzureSqlMI.ManagedInstanceName)'"
                        if ($Confirmation -eq "Y") 
                        {
                            Set-AzSqlInstance -Name $AzureSqlMI.ManagedInstanceName -ResourceGroupName $AzureSqlMI.ResourceGroupName -PublicDataEndpointEnabled $true -force
                            Write-Output "Public endpoint on your Azure SQL Managed Instance: '$($AzureSqlMI.ManagedInstanceName)'. Do not forget to add a new Inbound Rule in the NSG to allow Azure Services to access Azure SQL Managed Instance through port 3342."

                        }else {
                            Write-Output "Skipping '$($AzureSqlMI.ManagedInstanceName)'. Azure Purview will not be able to scan this Azure SQL Managed Instance!"
                        } 
                    }
                    
                    #Assign SQL db_datareader Role to Azure Purview MSI on each Azure SQL Managed Instances Database 
                    $AzureSQLMIDBs = Get-AzSqlInstanceDatabase -InstanceName $AzureSqlMI.ManagedInstanceName -ResourceGroup $AzureSqlMI.ResourceGroupName
                    
                    foreach ($AzureSQLMIDB in $AzureSQLMIDBs) {
                          if (($AzureSQLMIDB.Name -ne "master") -or ($AzureSQLMIDB.Name -ne "model") -or ($AzureSQLMIDB.Name -ne "msdb") -or ($AzureSQLMIDB.Name -ne "tempdb")) 
                          {
                            $AzureSqlMIFQDN = $AzureSqlMI.ManagedInstanceName + ".public." + $AzureSqlMI.DnsZone +"."+ "database.windows.net,3342"
                            Write-output "Connecting to '$($AzureSQLMIDB.Name)' on Azure SQL Manage Instance '$($AzureSqlMIFQDN)'"

                            $AzSQLMIAADAdminConfigured = Get-AzSqlInstanceActiveDirectoryAdministrator -InstanceName $AzureSqlMI.ManagedInstanceName -ResourceGroup $AzureSqlMI.ResourceGroupName
                            
                            #Validate if the provided admin user is actually configured as AAD Admin in Azure SQL Managed Instance 

                            If (($AzSQLMIAADAdminConfigured.DisplayName -eq $AzSQLMIAADAdminPrompted.UserPrincipalName) -OR ($AzSQLMIAADAdminPromptedGroups.ForEach({$_.ObjectId}) -contains $AzSQLMIAADAdminConfigured.ObjectId))

                            {

                            }else {    
                                Write-Output "'$($AzSQLMIAADAdminPrompted.UserPrincipalName)' is not Admin in Azure SQL Managed Instance:'$($AzureSqlMIFQDN)'."
                                $Confirmation = Read-Host -Prompt "Press Y to enter new Administrator credentials"
                                if ($Confirmation -eq "Y") 
                                {
                                    $AzSQLMIAADAdminPrompted = Read-Host -Prompt "Please enter your Azure SQL Managed Instances Administrator account that is Azure AD Integrated"
                                    $AzSQLMIAADAdminPrompted = Get-AzureADUser -ObjectId $AzSQLMIAADAdminPrompted

                                }else {
                                    Write-Output "Skipping '$($AzureSqlMIFQDN)'. Azure Purview will not be able to scan this Azure SQL Managed Instance!"
                                } 

                            }

                            sqlcmd -S $AzureSqlMIFQDN -d $AzureSQLMIDB.Name -U $($AzSQLMIAADAdminPrompted.UserPrincipalName) -G -Q "CREATE USER [$PurviewAccount] FROM EXTERNAL PROVIDER; EXEC sp_addrolemember 'db_owner', [$PurviewAccount];"
                            Write-Output  "Azure SQL DB: db_owner role is now assigned to $PurviewAccount in '$($AzureSQLMIDB.Name)' on Azure SQL Managed Instance '$($AzureSQLMIDBs.ManagedInstanceName)'"                       
  
                          }             
                      }
                }
            }
        }
    }
}

# If Azure Storage Account (BlobStorage) is selected for Azure Data Source 

If (($AzureDataType -eq "BlobStorage") -or ($AzureDataType -eq "ADLSGen2"))
{
    Write-Output "Processing RBAC assignments for Azure Purview Account $PurviewAccount for $AzureDataType inside '$($TopLMG.Name)' Management Group" 
    
    $ControlPlaneRole = "Reader"
    
    #Check if Reader role is assigned at MG level
    
    $ExistingReaderRole = Get-AzRoleAssignment -ObjectId $PurviewAccountMSI -RoleDefinitionName $ControlPlaneRole -Scope $TopLMG.Id
    
    if (!$ExistingReaderRole) {
        #Assign Reader role to Azure Purview at MG 
        New-AzRoleAssignment -ObjectId $PurviewAccountMSI -RoleDefinitionName $ControlPlaneRole -Scope $TopLMG.Id  
        Write-Output "Reader role assigned to Azure Purview at '$($TopLMG.Name)'"
     }else {
        Write-Output "Reader role is already assigned to Azure Purview at '$($TopLMG.Name)'. No action is needed." 
     }
    
    $Role = "Storage Blob Data Reader"

    $DataSourceMGs = Get-AzManagementGroup 
    foreach ($DataSourceMG in $DataSourceMGs) {
    
        $DataSourceMG = Get-AzManagementGroup -GroupName $DataSourceMG.Name -Expand -Recurse
        if ($DataSourceMG.Id.StartsWith($TopLMG.Id)) {
            foreach ($DataSourceChildMG in $DataSourceMG.Children | Where-Object { $_.Type -eq "/subscriptions" }) {
                $DataSourceChildMGSubId = $DataSourceChildMG.Id -replace '/subscriptions/',''
                Write-Output "Processing Subscription Name:'$($DataSourceChildMG.DisplayName) ID:'$DataSourceChildMGSubId''"
                Select-AzSubscription -SubscriptionId $DataSourceChildMGSubId
          
                #Verify whether RBAC is already assigned, otherwise assign RBAC
                $ExistingRole = Get-AzRoleAssignment -ObjectId $PurviewAccountMSI -RoleDefinitionName $Role -Scope "/subscriptions/$DataSourceChildMGSubId"
                        
                if (!$ExistingRole) {
                   New-AzRoleAssignment -ObjectId $PurviewAccountMSI -RoleDefinitionName $Role -Scope "/subscriptions/$DataSourceChildMGSubId"  
                   Write-Output  "Storage Blob Data Reader role is now assigned to $PurviewAccount at '$($DataSourceMG.Children)'"
                }else {
                    Write-Output "Storage Blob Data Reader role is already assigned to $PurviewAccount at $DataSourceChildMGSubId Subscription. No action is needed." 
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
                             
                Write-Output "Verifying your Azure Storage Accounts' Network Rules inside Azure Subsription: $DataSourceChildMGSubId"
                foreach ($StorageAccount in $StorageAccounts) {
                    $StorageAccountNet = Get-AzStorageAccountNetworkRuleSet -ResourceGroupName $StorageAccount.ResourceGroupName -Name $StorageAccount.StorageAccountName
                    If (($StorageAccountNet.DefaultAction -eq 'Deny') -AND ($StorageAccountNet.Bypass -Notlike "*AzureServices"))
                    {
                        
                        Write-Output "Network Rules detected on your Storage Account '$($StorageAccount.StorageAccountName)'. You would need to allow AzureServices to bypass." 
                        $Confirmation = Read-Host -Prompt "Press Y to allow AzureServices to access Storage Account: '$($StorageAccount.StorageAccountName)'"
                        if ($Confirmation -eq "Y") 
                        {
                            $Bypass = $StorageAccountNet.Bypass + "AzureServices"
                            Update-AzStorageAccountNetworkRuleSet $StorageAccount.ResourceGroupName -Name $StorageAccount.StorageAccountName -Bypass $Bypass
                            Write-Output "AzureServices is added as exception in your Azure Storage Account '$($StorageAccount.StorageAccountName)' Network Firewall Rule" 
                        }else {
                            Write-Output "Skipping '$($StorageAccount.StorageAccountName)'. Azure Purview will not be able to scan this Storage Account!"
                        } 
                    }
                }

            }
    
       }
    }
    
}





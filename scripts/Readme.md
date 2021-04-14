---
title: Azure Purview Deployment Checklist
description: Azure Purview Deployment Checklist
ms.author: Zeinab Mokhtarian Koorabbasloo
ms.date: 04/13/2020
ms.file: Readme.md
---
| Update: 04/13/2020  |
---
<br>

# Azure Purview Deployment Checklist

Azure Purview is a unified data governance service that helps you manage and govern your on-premises, multi-cloud, and software-as-a-service (SaaS) data. Easily create a holistic, up-to-date map of your data landscape with automated data discovery, sensitive data classification, and end-to-end data lineage. Empower data consumers to find valuable, trustworthy data.

In order to perform a successful deployment of Azure Purview including registering and scanning all your data sources in Azure so you can create a unified data governance across all your data in the organization, you need to plan carefully and consider all the required steps. In some cases, you may need to work with other teams in your organization to prepare your environment.
This guide and scripts are aimed to help you to achieve this goal.

These PowerShell scripts are aimed assist Azure Subscription owners and Azure Purview Data Source Administrators to identify required access and setup required authentication and network rules for Azure Purview Account across Azure data sources.

## 1. Readiness Checklist

[Azure Purview Readiness Checklist](https://github.com/zeinab-mk/Purview-Deployment-Checklist/blob/main/docs/Azure-Purview-Deployment-Readiness-Checklist.md) is a list of high-level steps to guide you to plan and deploy Azure Purview as your data governance solution. The guide is divided into four phases:

1. **Readiness** – Learn the pre-requisite tools and approaches important to all adoption efforts.
2. **Build Foundation** – Deploy Azure Purview Accounts to establish your unified data governance model.
3. **Register Data Sources** – Setup first landing zone and onboard initial group of data sources.
4. **Curate and consume data** – Enable a unified Data Governance solution for data consumers using Azure Purview.

## 2. Azure Purview Automated Readiness Checklist

This is an automated PowerShell based script that helps you to run a thorough validation about network and permissions in order to be able to register and scan data sources from your Azure environment in Azure Purview.

## 2.1 Features

### 2.1.1 Authentication type
To scan data sources, Azure Purview requires access registered data sources. This is done by using **Credentials**. A credential is an authentication information that Azure Purview can use to authenticate to your registered data sources. There are few options to setup the credentials for Azure Purview such as using Managed Identity assigned to the Purview Account, using a Key Vault or a Service Principals.

The automated readiness checklist currently is supported for **Managed Identity**.

### 2.1.2 Data Sources types

Currently, the following **data sources** are supported in the script:

- Azure Blob Storage (BlobStorge)
- Azure Data Lake Storage Gen 2 (ADLSGen2)
- Azure Data Lake Storage Gen 1 (ADLSGen1)
- Azure SQL Database (AzureSQLDB)
- Azure SQL Managed Instance (AzureSQLMI)

You can choose **all** or any of these data sources as input when running the script.

**Azure Blob Storage (BlobStorge):**

- RBAC: Verify if Azure Purview MSI has 'Storage Blob Data Reader role' in each of the subscriptions below the selected scope.
- RBAC: Verify if Azure Purview MSI has 'Reader' role on selected scope.
- Service Endpoint: Verify if Service Endpoint is ON, AND check if 'Allow trusted Microsoft services to access this storage account' is enabled.
- Networking: check if Private Endpoint is created for storage and enabled for Blob.

**Azure Data Lake Storage Gen 2 (ADLSGen2)**

- RBAC: Verify if Azure Purview MSI has 'Storage Blob Data Reader' role in each of the subscriptions below the selected scope.
- RBAC: Verify if Azure Purview MSI has 'Reader' role on selected scope.
- Service Endpoint: Verify if Service Endpoint is ON, AND check if 'Allow trusted Microsoft services to access this storage account' is enabled.
- Networking: check if Private Endpoint is created for storage and enabled for Blob.

**Azure Data Lake Storage Gen 1 (ADLSGen1)**

- Permissions: Verify if Azure Purview MSI has access to Read/Execute.
- Networking: Verify if Service Endpoint is ON, AND check if 'Allow all Azure services to access this Data Lake Storage Gen1 account' is enabled.

**Azure SQL Database (AzureSQLDB)**

- SQL Servers:
  - Network: Verify if Public or Private Endpoint is enabled.
  - Firewall: Verify if 'Allow Azure services and resources to access this server'is enabled.
  - Azure AD Admin: Check if Azure SQL Server has AAD Authentication.
  - AAD Admin: Populate Azure SQL Server AAD Admin user or group.

- SQL Databases:
  - SQL Role: Check if Azure Purview MSI has db_datareader role.

**Azure SQL Managed Instance (AzureSQLMI)**

- SQL Managed Instance Servers:
  - Network: Verify if Public or Private Endpoint is enabled.
  - ProxyOverride: Verify if Azure SQL Managed Instance is configured as Proxy or Redirect.
  - Networking: Verify if NSG has an inbound rule to allow AzureCloud over required ports; Redirect: 1433 and 11000-11999 or Proxy: 3342.
  - Azure AD Admin: Check if Azure SQL Server has AAD Authentication.
  - AAD Admin: Populate Azure SQL Server AAD Admin user or group.

- SQL Databases:
  - SQL Role: Check if Azure Purview MSI has db_datareader role.

### 2.1.3 Data Sources Scopes

As your data sources scope, you can select a top-level **Management Group** or a **Subscription**. If you select a Management Group, the readiness check script will run on all subscriptions inside the Management Group including child Management Groups. If you select a Subscription as data source scope, the script will only run on the resources selected subscription.

## 2.2 Required Permissions

The following permissions (minimum) are needed run the script in your Azure environment:
Role | Scope |
|-------|--------|
| Global Reader | Azure AD Tenant |
| Reader | Management Group or Subscription where your Azure Data Sources reside |
| Reader | Subscription where Azure Purview Account is created |
| SQL Admin (Azure AD Authentication) | Azure SQL Servers or Azure SQL Managed Instances |

## 2.3 Required Modules

This script requires Azure PowerShell [Az](https://docs.microsoft.com/en-us/powershell/azure/new-azureps-module-az?view=azps-5.8.0) Modules.

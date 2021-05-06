---
title: Azure Purview Readiness Checklist
description: Azure Purview Readiness Checklist
ms.author: Microsoft
ms.date: 03/24/2021
ms.file: Azure-Purview-Deployment-Readiness-Checklist.md
---

| Update: 03/24/2021

---

## Azure Purview Readiness Checklist

Following these steps will help better prepare your environment for data governance and data democratization:

### **1. Readiness - Learn the pre-requisite tools and approaches important to all adoption efforts.**

* Identify sources of data across your organization to digital state of your data across organization. Identify and document:
  * Who are the Data Owners?
  * Who does have write access to the data?
  * Where is Data? in the Cloud? on-premises?
  * What Data Source types do you have in the organization? (e.g. Azure SQL DB, Amazon S3, on-premises SQL Servers)

* Define Roles and Responsibilities to build and manage a unified data governance solution:
  * Data Curators: Manage Classifications and Glossary Terms.
  * Data Readers: Require read-only access to Search and Insights Reports.
  * Data Source Administrators + Curators: Register and Scan Data Sources, Manage Catalog.
  * Data Source Administrators + Readers: Register and Scan Data Sources.
  * Supporting Roles for building an end-to-end data governance solution using Azure Purview:
    * Azure Subscription Administrators to manage Azure resources, Policies, RBAC, Resource Providers.
    * Azure AD Administrators to manage identity and application registration.
    * NetOps to prepare the network to support Azure Purview connectivity requirements.
    * SecOps to manage Azure Key Vaults and secrets.
    * M365 Administrators (Microsoft M365 Information Protection if M365 Sensitivity Labels will be used)
    * Data Source Owners to map them for roles in Azure Purview.

* Manage budget, costs and licensing. Currently, Microsoft offers [Azure Purview](https://azure.microsoft.com/en-us/pricing/details/azure-purview) in a pay-as-you-go model. Understand how billing works, and see how you can control costs. Know the additional costs; to extend Microsoft 365 Sensitivity Labels to Azure Purview, you need M365 E5 licenses.

* Plan for communication, readiness and awareness across organization.

* Setup Authentication model for Azure Purview:
  * Locate data sources. If they are in Azure, what subscriptions are in scope.
  * Identify Subscription Owners in the data source subscriptions.
  * Define what [authentication methods](https://docs.microsoft.com/en-us/azure/purview/manage-data-sources) to be used for each data source type to allow Azure Purview to connect to data sources.
  * If data sources reside in IaaS or on-premises VMs, deploy Microsoft Integration Runtime.
  * Define Azure Key Vaults requirements to keep required keys and secrets for data governance
  * Create required users for authentication to data sources and store secrets in Azure Key Vaults.
  
* Prepare Network and connectivity:
  * Define if you need to deploy Azure Purview Account using Azure Private Endpoint.
  * Check if Service Endpoint is enabled on Azure data sources. Allow AzureServices to bypass.
  * Verify if data sources are deployed using Private Endpoints. Check Azure Purview support for [Private Link](https://docs.microsoft.com/en-us/azure/purview/catalog-private-link).
  * Configure required NSG rules to allow Azure Purview access to VMs and Azure SQL Managed Instances.

### **2 Build Foundation – Deploy Azure Purview Accounts to establish your unified data governance model.**

* Prepare your Azure Subscriptions and deploy Azure Purview:
  * Define what Azure Subscriptions will be used to deploy Azure Purview.
  * Register required Azure Resource Providers in Purview subscription.
  * Review and update Azure Policy assigned to Purview subscriptions to allow deployment of Azure Storage, EventHub Namespace and Purview Accounts.
  * Deploy Azure Purview Accounts for production and non-production environments.
  * If Azure Purview MSI used: assign required RBAC roles to Azure Purview MSI.
  * If Key Vault used, assign the [required access](https://docs.microsoft.com/en-us/azure/purview/manage-credentials) to key vault secrets to Azure Purview Account's MSI.
  * Create Credentials and map to Key Vault's secrets in Azure Purview.
  * Register Application and configure service principals if SP is used.
  * Generate and Register Integration Runtime for data sources inside IaaS or on-premises VMs.

* Import your glossary terms to Azure Purview. Format your glossary terms using Azure Purview default [template](https://docs.microsoft.com/en-us/azure/purview/tutorial-import-create-glossary-terms) or create a new term templates in Azure Purview.

* Build your custom classifications / classification rules.

* Consent to extend Sensitivity Labels to Azure Purview.

* Validate / Update M365 Sensitivity Labels in Microsoft Security & Compliance dashboard.

* Create Auto-labeling Rules in M365.

* Grant Data Reader or Data Curator access to Azure Purview to data, governance and security teams in the organization.

* Perform initial Security review.

* Build and communicate detailed plan of tasks, roles and responsibilities to operate Azure Purview.  

### **3 Register Data Sources – Setup first landing zone and onboard initial group of data sources.**

* Define Azure Purview Collection architecture.

* Create Collection hierarchy inside Azure Purview Account

* Register pilot data sources, test connectivity, perform initial scans.

* Verify classifications in assets and adjust custom classification rules.

* Verify Assets with assigned labels.

* Assign Data Experts and Data Owners to assets in Azure Purview.

* Assign Glossary Terms to data assets.

* Setup automatic scan rules.

* Validate and adjust budget.

* Review security, business and operational requirements, identify gaps and adjust configuration.

* Adjust and share roles and responsibilities plan.

### **4 Curate and consume data – Enable a unified Data Governance solution for data consumers using Azure Purview.**

* Adjust scan rules.

* Onboard additional data sources.

* Optimize glossary terms.

* Optimize classifications rules.

* Adjust access levels.

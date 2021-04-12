[Back][0]

# Azure Firewall Premium Preview Tutorial with PowerShell

| Command                                                            | Description        |
| ------------------------------------------------------------------ | ------------------ |
| `Connect-AzAccount`                                                | -                  |
| `Get-AzSubscription`                                               | -                  |
| `Set-AzContext -Subscription xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx` | use subscriptionID |
| `Get-AzContext`                                                    | -                  |
| `Get-AzResourceGroup \| Format-Table`                              | -                  |
| `Get-AzLocation \| Format-Table -Property Location, DisplayName`   | -                  |

0. **Initialize required Params used along the lab**

   ```PowerShell
   # ---
   # REQUIRED
   # Replace the following param values within $p
   # ---
   $p = @{
      Suffix = "lk"
      Location = "EastUS"
      AddressPrefix = "10.4"  # generates a 10.4.0.0/16 vnet address space of . Valid inputs could be "10.10" that generated "10.10.0.0/16" or "20.15" which generated "20.15.0.0/16.
      InterCAFilePath = "C:\ArtiomLK\github\azure-firewall-premium-lab\scripts\interCA.pfx" # by now don't worry, once we reach the generating self signed certificate part in this guide, we will update this intermediateCA file path
   }

   # ---
   # OPTIONAL
   # You could replace the following param values within $c
   # ---
   $c = @{
      AppName = "fwp"
      Env = "test"
   }

   # ---
   # DO NOT REPLACE THESE PARAMS
   # You shouldn't replace the following params unless you specifically require it
   # ---
   $rgParams = @{
      Name = "rg-$($c.AppName)-$($c.Env)-$($p.Suffix)"
      Location = "$($p.Location)"
   }
   # Virtual Network parameters
   $vNetParams = @{
      Name = "vnet-$($c.AppName)-$($c.Env)-$($p.Suffix)"
      ResourceGroupName = $rgParams.Name
      Location = $rgParams.Location
      AddressPrefix = "$($p.AddressPrefix).0.0/16"
   }
   # Virtual Network Azure Firewall Subnet parameters
   $vNetFirewallSubnetParams = @{
      Name = "AzureFirewallSubnet"
      AddressPrefix = "$($p.AddressPrefix).0.0/24"
   }
   # Virtual Network default Subnet parameters
   $vNetDefaultSubnetParams = @{
      Name = "default"
      AddressPrefix = "$($p.AddressPrefix).1.0/24"
   }
   # Virtual Network default Subnet parameters
   $vNetBastionSubnetParams = @{
      Name = "AzureBastionSubnet"
      AddressPrefix = "$($p.AddressPrefix).2.0/27"
   }
   # Windows 10 Pro Virtual Machine parameters for testing purposes
   $vmTestParams = @{
      Name = "vm-$($c.AppName)-$($c.Env)-$($p.Suffix)"
      Size = "Standard_DS3_v2"
      NICName = "nic-vm-$($c.AppName)-$($c.Env)-$($p.Suffix)"
      PublisherName = "MicrosoftWindowsDesktop"
      Offer = "Windows-10"
      SKU = "19h2-pro"
   }
   # Bastion params to connect to our Windows 10 Pro testing Virtual Machine
   $bastionParams = @{
      Name = "bastion-$($c.AppName)-$($c.Env)-$($p.Suffix)"
   }
   #Bastion Public Ip parameters
   $bastionPipParams = @{
      Name = "pip-bastion-$($c.AppName)-$($c.Env)-$($p.Suffix)"
      Location = $rgParams.Location
      AllocationMethod = "Static"
      Sku = "Standard"
      Zone = "1", "2", "3"
      ResourceGroupName = $rgParams.Name
   }
   #Public Ip parameters
   $FirewallPipParams = @{
      Name = "pip-fw-$($c.AppName)-$($c.Env)-$($p.Suffix)"
      Location = $rgParams.Location
      AllocationMethod = "Static"
      Sku = "Standard"
      Zone = "1", "2", "3"
      ResourceGroupName = $rgParams.Name
   }
   # Firewall Premium params
   $firewallPremiumParams = @{
      Name = "fw-$($c.AppName)-$($c.Env)-$($p.Suffix)"
      ResourceGroupName = $rgParams.Name
      Location = $rgParams.Location
      VirtualNetwork = $vNet
      PublicIpAddress = $firewallPip
      SkuTier = "Premium"
   }
   # Key Vault parameters
   $keyVaultSettingsParams = @{
      Name = "kv-$($c.AppName)-$($c.Env)-$($p.Suffix)"
      ResourceGroupName = $rgParams.Name
      Location = $rgParams.Location
   }
   # Key Vault Intermediate Cert
   $keyVaultIntermediateCertParams = @{
      Name = "intermediate-cert"
      FilePath = "$($p.InterCAFilePath)"
      Password = "Password123!"
   }
   # Managed Identity parameters
   $managedIdentityParams = @{
      Name = "id-$($c.AppName)-$($c.Env)-$($p.Suffix)"
      ResourceGroupName = $rgParams.Name
      Location = $rgParams.Location
   }
   #Log Analytics Workspace Params
   $logParams = @{
      Name = "log-$($c.AppName)-$($c.Env)-$($p.Suffix)"
      ResourceGroupName = $rgParams.Name
      Location = $rgParams.Location
      Sku = "Standard"
   }
   # Create a route table
   $routeTableParams = @{
      Name = "route-$($c.AppName)-$($c.Env)-$($p.Suffix)"
      ResourceGroupName = $rgParams.Name
      Location = $rgParams.Location
      DisableBgpRoutePropagation = $true
   }
   # Firewall Premium policy
   $fwPolicyParams = @{
      Name = "fw-policy-$($c.AppName)-$($c.Env)-$($p.Suffix)"
      ResourceGroupName = $rgParams.Name
      Location = $rgParams.Location
      SkuTier = "Premium"
      TransportSecurityName = "tls-premium-fw"
      TransportSecurityKeyVaultSecretId = $tlsCert.SecretId
      UserAssignedIdentityId = $keyVaultManagedIdentity.Id
      IntrusionDetection = $idpsSettings
   }

   # Test our created variables
   echo $rgParams
   echo $vNetParams
   echo $vNetFirewallSubnetParams
   echo $vNetDefaultSubnetParams
   echo $vNetBastionSubnetParams
   echo $vmTestParams
   echo $bastionParams
   echo $FirewallPipParams
   echo $bastionPipParams
   echo $firewallPremiumParams # MUST be recreated latter on during the lab, read comments while working on this guide
   echo $keyVaultSettingsParams
   echo $keyVaultIntermediateCertParams
   echo $managedIdentityParams
   echo $logParams
   echo $routeTableParams
   echo $fwPolicyParams # MUST be recreated latter on during lab, read comments while working on this guide

   # ---
   # PSObjects used by PowerShell commands along the lab
   # ---
   $vNet = Get-AzVirtualNetwork -ResourceGroupName $rgParams.Name -Name $vNetParams.Name
   $firewallPip = Get-AzPublicIpAddress -ResourceGroupName $rgParams.Name -Name $FirewallPipParams.Name
   $firewallPremium = Get-AzFirewall -ResourceGroupName $vNet.ResourceGroupName -Name $firewallPremiumParams.Name
   $keyVault = Get-AzKeyVault -VaultName $keyVaultSettingsParams.Name -ResourceGroupName $keyVaultSettingsParams.ResourceGroupName
   $keyVaultManagedIdentity = Get-AzUserAssignedIdentity -ResourceGroupName $managedIdentityParams.ResourceGroupName -Name $managedIdentityParams.Name
   $tlsCert = Get-AzKeyVaultCertificate -Name $keyVaultIntermediateCertParams.Name -InputObject $keyVault
   $fwPolicy = Get-AzFirewallPolicy -Name $fwPolicyParams.Name -ResourceGroupName $fwPolicyParams.ResourceGroupName

   # Review Created Azure Resources
   echo $vNet | Format-Table
   echo $firewallPip | Format-Table
   echo $firewallPremium | Format-Table
   echo $keyVault | Format-Table
   echo $keyVaultManagedIdentity | Format-Table
   echo $tlsCert | Format-Table
   echo $fwPolicy | Format-Table
   ```

1. **Create an Azure Resource Group where all our Azure Resources will be grouped**

   ```PowerShell
   # Create the ResourceGroup
   New-AzResourceGroup @rgParams
   ```

2. **Create the VNet**

   ```PowerShell
   # Create the VNet
   $vNet = New-AzVirtualNetwork @vNetParams
   ```

3. **Add a default, bastion and firewall subnet to our VNet**

   ```PowerShell
   # Get the VNet
   $vNet = Get-AzVirtualNetwork -ResourceGroupName $rgParams.Name -Name $vNetParams.Name

   # Add an AzureFirewallSubnet to our VNet
   $vNet | Add-AzVirtualNetworkSubnetConfig @vNetFirewallSubnetParams
   $vNet | Add-AzVirtualNetworkSubnetConfig @vNetDefaultSubnetParams
   $vNet | Add-AzVirtualNetworkSubnetConfig @vNetBastionSubnetParams
   $vNet | Set-AzVirtualNetwork
   ```

4. **Create a Windows 10 Pro VM for testing purposes**

   ```PowerShell
   # The NIC should be added to the subnet where VMs will be deployed (Not the AzureFirewallSubnet), you could double check with echo
   echo $ $vNet.Subnets[1]
   # Create a Network Interface Card
   $NIC = New-AzNetworkInterface -Name $vmTestParams.NICName -ResourceGroupName $rgParams.Name -Location $rgParams.Location -SubnetId $vNet.Subnets[1].Id

   $VirtualMachine = New-AzVMConfig -VMName $vmTestParams.Name -VMSize $vmTestParams.Size
   $VirtualMachine = Set-AzVMOperatingSystem -VM $VirtualMachine -Windows -ComputerName $vmTestParams.Name -ProvisionVMAgent -EnableAutoUpdate # Provide a User and Password which later on will be used to login into the test VM
   $VirtualMachine = Add-AzVMNetworkInterface -VM $VirtualMachine -Id $NIC.Id
   $VirtualMachine = Set-AzVMSourceImage -VM $VirtualMachine -PublisherName $vmTestParams.PublisherName -Offer $vmTestParams.Offer -Skus $vmTestParams.SKU -Version latest
   $VirtualMachine | Set-AzVMBootDiagnostic -Disable

   # Create our test VM
   New-AzVM -ResourceGroupName $rgParams.Name -Location $rgParams.Location -VM $VirtualMachine -Verbose
   ```

5. **Create a bastion to connect to our Windows 10 Pro VM for testing purposes**

   ```PowerShell
   # Deploy a zone-redundant public IP for our bastion
   $bastionPip = New-AzPublicIpAddress @bastionPipParams

   # Deploy our bastion
   $bastion = New-AzBastion -ResourceGroupName $rgParams.Name -Name $bastionParams.Name -PublicIpAddress $bastionPip -VirtualNetwork $vNet
   ```

6. **Deploy a zone-redundant public IP**

   ```PowerShell
   # Deploy a zone-redundant public IP
   $firewallPip = New-AzPublicIpAddress @FirewallPipParams
   ```

7. **Deploy Azure Firewall Premium**

   ```PowerShell
   # Gather PSVirtualNetwork and PSPublicIpAddress
   $vNet = Get-AzVirtualNetwork -ResourceGroupName $rgParams.Name -Name $vNetParams.Name
   $firewallPip = Get-AzPublicIpAddress -ResourceGroupName $rgParams.Name -Name $FirewallPipParams.Name

   <# !!! READ COMMENT
   Recreate the Firewall Premium params
   RUN THE ABOVE CODE: $firewallPremiumParams = @{ ... }
   #>
   echo $firewallPremiumParams

   # Deploy Azure Firewall Premium
   $firewallPremium = New-AzFirewall @firewallPremiumParams
   ```

8. **Create an Azure Key Vault**

   ```PowerShell
   # Create an Azure Key Vault
   $keyVault = New-AzKeyVault @keyVaultSettingsParams
   ```

9. **Create a Managed Identity with access to our KeyVault**

   ```PowerShell
   # Get a reference to our Azure Key Vault
   $keyVault = Get-AzKeyVault -VaultName $keyVaultSettingsParams.Name -ResourceGroupName $keyVaultSettingsParams.ResourceGroupName

   # Create our Managed Identity resource
   $keyVaultManagedIdentity = New-AzUserAssignedIdentity @managedIdentityParams
   $objectId = Get-AzADServicePrincipal -DisplayName $keyVaultManagedIdentity.Name
   $keyVault | New-AzRoleAssignment -RoleDefinitionName "Reader" -objectId $objectId.Id # if the 'ObjectId' argument is null or empty just wait until the resource fully created
   $keyVault | Set-AzKeyVaultAccessPolicy -objectId $objectId.Id -PermissionsToCertificates "Get","List" -PermissionsToSecrets "Get","List"
   ```

10. **Create a self-signed certificate for TLS inspection**

    ```PowerShell
    # Run the following command if you get an error stating cert.ps1 is not digitally signed
    Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass

    # Create our self Signed Certificates
    cd .\scripts\ ; .\cert.ps1 ; cd ..
    ```

    > Note: After the certificates are created, deploy them to the following locations:
    >
    > - rootCA.crt - Deploy on endpoint machines (Public certificate only). (use any method u like, e.g. upload cert to storage account and create a sas url to download from endpoint machines)
    > - interCA.pfx - Import as certificate on a Key Vault and assign to firewall policy.

    ```PowerShell
    # Get a reference to our Azure Key Vault
    $keyVault = Get-AzKeyVault -VaultName $keyVaultSettingsParams.Name -ResourceGroupName $keyVaultSettingsParams.ResourceGroupName

    # Create a Cert password for testing purposes, ( in real env this should not be in code)
    $CertPassword = ConvertTo-SecureString -String $keyVaultIntermediateCertParams.Password -Force -AsPlainText
    # Import the generated Certificate to Azure KeyVault (You are required to change the FilePath)
    $tlsCert = $keyVault | Import-AzKeyVaultCertificate -Name $keyVaultIntermediateCertParams.Name -Password $CertPassword -FilePath $keyVaultIntermediateCertParams.FilePath
    ```

11. **Create a Log Analytics Workspace to analyze logs from our Premium Firewall**

    ```PowerShell
    $firewallPremium = Get-AzFirewall -ResourceGroupName $vNet.ResourceGroupName -Name $firewallPremiumParams.Name

    # Create a Log Analytics Workspace
    $log = New-AzOperationalInsightsWorkspace @logParams

    # Enables and forwards AzureFirewallApplicationRule, AzureFirewallNetworkRule and AzureFirewallDnsProxy diagnostics rules to our Azure Log Analytics Workspace
    $logDiagnosticSettingsParams = @{
       Name = "FW-Premium-Diagnostics-next"
       ResourceId = $firewallPremium.Id
       WorkspaceId = $log.ResourceId
       Enabled = $true
       RetentionEnable = $true
       RetentionInDays = 30
    }
    echo $logDiagnosticSettingsParams

    # Enables and forwards AzureFirewallApplicationRule, AzureFirewallNetworkRule and AzureFirewallDnsProxy diagnostics rules to our Log Analytics Workspace
    Set-AzDiagnosticSetting @logDiagnosticSettingsParams
    ```

12. **Route all traffic to our Firewall with a Azure Route**

    ```PowerShell
    $firewallPremium = Get-AzFirewall -ResourceGroupName $vNet.ResourceGroupName -Name $firewallPremiumParams.Name
    $vNet = Get-AzVirtualNetwork -ResourceGroupName $rgParams.Name -Name $vNetParams.Name

    # Create a route table
    $routeTable = New-AzRouteTable @routeTableParams

    # Create a route config; 0-route will send all the traffic to the firewall
    $toFwRouteConfigParams = @{
       Name = "to-firewall-route"
       RouteTable = $routeTable
       AddressPrefix = "0.0.0.0/0"
       NextHopType = "VirtualAppliance"
       NextHopIpAddress = $firewallPremium.IpConfigurations.privateIpAddress
    }
    Add-AzRouteConfig @toFwRouteConfigParams | Set-AzRouteTable

    # Associate the route table to the subnet
    $subnetParameters = @{
       Name = $vNetDefaultSubnetParams.Name
       VirtualNetwork = $vNet
       AddressPrefix = $vNetDefaultSubnetParams.AddressPrefix
       RouteTable = $routeTable
    }

    # Assign the route table to the vNet
    Set-AzVirtualNetworkSubnetConfig @subnetParameters | Set-AzVirtualNetwork
    ```

13. **Deploy and associate a premium azure firewall policy with Intrusion Detection and Prevention System (IDPS)**

    ```PowerShell
    $keyVaultManagedIdentity = Get-AzUserAssignedIdentity -ResourceGroupName $managedIdentityParams.ResourceGroupName -Name $managedIdentityParams.Name
    $tlsCert = Get-AzKeyVaultCertificate -Name $keyVaultIntermediateCertParams.Name  -InputObject $keyVault
    $firewallPremium = Get-AzFirewall -ResourceGroupName $vNet.ResourceGroupName -Name $firewallPremiumParams.Name

    # Enable IDPS
    $idpsSettings = New-AzFirewallPolicyIntrusionDetection -Mode "Alert"

    <# !!! READ COMMENT
    Recreate the Firewall Policy Premium params
    RUN THE ABOVE CODE: $fwPolicyParams = @{ ... }
    #>
    echo $fwPolicyParams

    # Create our Azure Premium Firewall Policy
    $fwPolicy = New-AzFirewallPolicy @fwPolicyParams

    # Associate our policy to our Azure premium firewall
    $firewallPremium.FirewallPolicy = $fwPolicy.Id
    $firewallPremium | Set-AzFirewall

    <# !!! READ COMMENT
    Manually add our SelfSigned Certificate into our Azure Firewall Policy by enabling TLS inside our Firewall Policy
    #>
    ```

14. **Configure web category filtering in our Azure Firewall Premium Policy**

    ```PowerShell
    $fwPolicy = Get-AzFirewallPolicy -Name $fwPolicyParams.Name -ResourceGroupName $fwPolicyParams.ResourceGroupName
    # Create a rule collection category group first
    #$RuleCatCollectionGroup = New-AzFirewallPolicyRuleCollectionGroup -Name App-Categories -Priority 200 -FirewallPolicyObject $fwPolicy


    $categoryRuleD1 =  New-AzFirewallPolicyApplicationRule  -WebCategory 'Gambling' -Name 'Gambling' -Protocol "http:80","https:443" -SourceAddress $vNetDefaultSubnetParams.AddressPrefix -TerminateTLS
    $categoryRuleD2 =  New-AzFirewallPolicyApplicationRule  -WebCategory 'Games' -Name 'Games' -Protocol "http:80","https:443"  -SourceAddress $vNetDefaultSubnetParams.AddressPrefix -TerminateTLS

    # Create a Deny app rule collection
    $AppCategoryCollectionDeny = New-AzFirewallPolicyFilterRuleCollection -Name App-Categories-Deny -Priority 205 -Rule $categoryRuleD1,$categoryRuleD2 -ActionType "Deny"

    $categoryRuleA1 =  New-AzFirewallPolicyApplicationRule  -WebCategory 'Education' -Name 'Education' -Protocol "http:80","https:443" -SourceAddress $vNetDefaultSubnetParams.AddressPrefix -TerminateTLS
    $categoryRuleA2 =  New-AzFirewallPolicyApplicationRule  -WebCategory 'ProfessionalNetworking' -Name 'ProfessionalNetworking' -Protocol "http:80","https:443"  -SourceAddress $vNetDefaultSubnetParams.AddressPrefix -TerminateTLS

    # Create an Allow app rule collection
    $AppCategoryCollectionAllow = New-AzFirewallPolicyFilterRuleCollection -Name App-Categories-Allow -Priority 210 -Rule $categoryRuleA1,$categoryRuleA2 -ActionType "Allow"

    # Deploy to created rule collection group
    New-AzFirewallPolicyRuleCollectionGroup -Name 'App-Categories' -Priority 200 -RuleCollection $AppCategoryCollectionAllow,$AppCategoryCollectionDeny -FirewallPolicyObject $fwPolicy
    ```

15. **Configure Application Firewall Policy Rules for Windows Virtual Desktop to function properly**

    ```PowerShell
    $fwPolicy = Get-AzFirewallPolicy -Name $fwPolicyParams.Name -ResourceGroupName $fwPolicyParams.ResourceGroupName
    # Create a rule collection group first
    # $RuleCollectionGroup = New-AzFirewallPolicyRuleCollectionGroup -Name WVD-APP-URL-ALLOW -Priority 100 -FirewallPolicyObject $AzFwPolicy

    # Define rules // part of the safe-url list https://docs.microsoft.com/en-us/azure/virtual-desktop/safe-url-list
    $ApplicationRule1 = New-AzFirewallPolicyApplicationRule -Name 'wvd-microsoft-com' -Protocol "http:80","https:443" -TargetFqdn "*.wvd.microsoft.com" -SourceAddress $vNetDefaultSubnetParams.AddressPrefix
    $ApplicationRule2 = New-AzFirewallPolicyApplicationRule -Name 'gcs-windows-net' -Protocol "http:80","https:443" -TargetFqdn "gcs.prod.monitoring.core.windows.net" -SourceAddress $vNetDefaultSubnetParams.AddressPrefix
    $ApplicationRule3 = New-AzFirewallPolicyApplicationRule -Name 'diagnostics-windows-net' -Protocol "http:80","https:443" -TargetFqdn "production.diagnostics.monitoring.core.windows.net" -SourceAddress $vNetDefaultSubnetParams.AddressPrefix

    # TLS Inspection Rules
    $ApplicationRule4 = New-AzFirewallPolicyApplicationRule -Name 'microsoft-com' -Protocol "http:80","https:443" -TargetFqdn "*.microsoft.com" -SourceAddress $vNetDefaultSubnetParams.AddressPrefix -TerminateTLS
    $ApplicationRule5 = New-AzFirewallPolicyApplicationRule -Name 'windows-net' -Protocol "http:80","https:443" -TargetFqdn "*.windows.net" -SourceAddress $vNetDefaultSubnetParams.AddressPrefix -TerminateTLS

    $ApplicationRuleCollection = @{
       Name       = "WVD-App-Rules-Allow"
       Priority   = 101
       ActionType = "Allow"
       Rule       = @($ApplicationRule1, $ApplicationRule2, $ApplicationRule3,$ApplicationRule4,$ApplicationRule5)
    }
    # Create a app rule collection
    $AppRuleCollection = New-AzFirewallPolicyFilterRuleCollection @ApplicationRuleCollection

    # Deploy to created rule collection group
    New-AzFirewallPolicyRuleCollectionGroup -Name 'WVD-APP-URLs' -Priority 100 -RuleCollection $AppRuleCollection -FirewallPolicyObject $fwPolicy
    ```

16. **Configure Network Firewall Policy Rules for Windows Virtual Desktop to function properly**

    ```PowerShell
    $fwPolicy = Get-AzFirewallPolicy -Name $fwPolicyParams.Name -ResourceGroupName $fwPolicyParams.ResourceGroupName
    # $RuleCollectionGroup = New-AzFirewallPolicyRuleCollectionGroup -Name WVD-NETWORK-ALLOW -Priority 104 -FirewallPolicyObject $AzFwPolicy
    $Rule1Parameters = @{
       Name               = "Allow-DNS"
       Protocol           = "UDP"
       sourceAddress      = $vNetDefaultSubnetParams.AddressPrefix
       DestinationPort    = "53"
       DestinationAddress = "*"
    }
    $Rule2Parameters = @{
       Name               = "Allow-KMS"
       Protocol           = "TCP"
       sourceAddress      = $vNetDefaultSubnetParams.AddressPrefix
       DestinationPort    = "1688"
       DestinationAddress = "23.102.135.246"
    }
    $Rule3Parameters = @{
       Name               = "Allow-NTP"
       Protocol           = "UDP"
       sourceAddress      = $vNetDefaultSubnetParams.AddressPrefix
       DestinationPort    = "123"
       DestinationAddress = "51.105.208.173"
    }

    $rule1 = New-AzFirewallPolicyNetworkRule @Rule1Parameters
    $rule2 = New-AzFirewallPolicyNetworkRule @Rule2Parameters
    $rule3 = New-AzFirewallPolicyNetworkRule @Rule3Parameters

    $NetworkRuleCollection = @{
       Name       = "WVD-Network-Rules-Allow"
       Priority   = 102
       ActionType = "Allow"
       Rule       = @($rule1, $rule2, $rule3)
    }
    # Create a app rule collection
    $NetworkRuleCategoryCollection = New-AzFirewallPolicyFilterRuleCollection @NetworkRuleCollection
    # Deploy to created rule collection group
    New-AzFirewallPolicyRuleCollectionGroup -Name WVD-NETWORK -Priority 104 -RuleCollection $NetworkRuleCategoryCollection -FirewallPolicyObject $fwPolicy
    ```

17. **Validate TLS**

    Update fqdn allow `*bing.com`

    ```SQL (KQL)
    AzureDiagnostics
    | where ResourceType == "AZUREFIREWALLS"
    | where Category == "AzureFirewallApplicationRule"
    | where msg_s contains "Url: wikipedia.com"
    | sort by TimeGenerated desc
    ```

### Additional Resources

- [Configure Azure Firewall Premium features for WVD automated][1]
- [MS | Docs | QuickStart: Create a virtual network using PowerShell][2]
- [MS | Docs | Example: Create a new public IP address][3]
- [MS | Docs | Example: Create a Firewall attached to a virtual network][4]
- [PowerShell Gallery | Install missing modules | Az.ManagedServiceIdentity][5]
- [MS | Docs | Create your own self-signed CA certificate][6]

[0]: ./azFirewallPremium.md
[1]: https://rozemuller.com/configure-azure-firewall-premium-features-for-wvd-automated/
[2]: https://docs.microsoft.com/en-us/azure/virtual-network/quick-create-powershell
[3]: https://docs.microsoft.com/en-us/powershell/module/az.network/new-azpublicipaddress?view=azps-5.7.0#example-1--create-a-new-public-ip-address
[4]: https://docs.microsoft.com/en-us/powershell/module/az.network/new-azfirewall?view=azps-5.7.0#example-1--create-a-firewall-attached-to-a-virtual-network
[5]: https://www.powershellgallery.com/packages/Az.ManagedServiceIdentity/0.7.3
[6]: https://docs.microsoft.com/en-us/azure/firewall/premium-certificates#certificates-used-by-azure-firewall-premium-preview

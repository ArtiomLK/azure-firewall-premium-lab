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
# Parameters used along the lab
# ---

# ResourceGroup parameters
$rgParams = @{
   Name = "rg-fw-premium-next"
   Location = "EastUS"
}

# Virtual Network parameters
$vNetParams = @{
   Name = 'vnet-fw-premium-next'
   ResourceGroupName = $rgParams.Name
   Location = $rgParams.Location
   AddressPrefix = '10.3.0.0/16'
}


# Virtual Network Azure Firewall Subnet parameters
$vNetFirewallSubnetParams = @{
   Name = 'AzureFirewallSubnet'
   AddressPrefix = '10.3.0.0/24'
}


# Virtual Network default Subnet parameters
$vNetDefaultSubnetParams = @{
   Name = 'default'
   AddressPrefix = '10.3.1.0/24'
}


# Virtual Network default Subnet parameters
$vNetBastionSubnetParams = @{
   Name = 'AzureBastionSubnet'
   AddressPrefix = '10.3.2.0/27'
}


# Windows 10 Pro Virtual Machine parameters for testing purposes
$vmTestParams = @{
   Name = 'vmTestFwPremium'
   Size = 'Standard_DS3_v2'
   NICName = 'vmTestFwPremiumNIC'
   PublisherName = 'MicrosoftWindowsDesktop'
   Offer = 'Windows-10'
   SKU = '19h2-pro'
}


# Bastion params to connect to our Windows 10 Pro testing Virtual Machine
$bastionParams = @{
   Name = 'testFwBastion'
}


#Bastion Public Ip parameters
$bastionPipParams = @{
   Name = "bastion-pip-002"
   Location = $rgParams.Location
   AllocationMethod = "Static"
   Sku = "Standard"
   Zone = "1", "2", "3"
   ResourceGroupName = $rgParams.Name
}


#Public Ip parameters
$FirewallPipParams = @{
   Name = "fw-pip-002"
   Location = $rgParams.Location
   AllocationMethod = "Static"
   Sku = "Standard"
   Zone = "1", "2", "3"
   ResourceGroupName = $rgParams.Name
}


# Firewall Premium params
$firewallPremiumParams = @{
   Name = "fw-premium-next"
   ResourceGroupName = $rgParams.Name
   Location = $rgParams.Location
   VirtualNetwork = $vNet
   PublicIpAddress = $firewallPip
   SkuTier = "Premium"
}


# Key Vault parameters
$keyVaultSettingsParams = @{
   Name = "kv-firewall-tls-lk-next"
   ResourceGroupName = $rgParams.Name
   Location = $rgParams.Location
}


# Key Vault Intermediate Cert
$keyVaultIntermediateCertParams = @{
   Name = "intermediate-cert"
   FilePath = "C:\ArtiomLK\github\azure-firewall-premium-lab\scripts\interCA.pfx"
   Password = "Password123!"
}


# Managed Identity parameters
$managedIdentityParams = @{
   Name = "fw-managed-identity-tls-next"
   ResourceGroupName = $rgParams.Name
   Location = $rgParams.Location
}


#Log Analytics Workspace Params
$logParams = @{
   Name = "FW-premium-Workspace-next"
   ResourceGroupName = $rgParams.Name
   Location = $rgParams.Location
   Sku = "Standard"
}


# Create a route table
$routeTableParams = @{
   Name = 'fw-premium-route-next'
   ResourceGroupName = $rgParams.Name
   Location = $rgParams.Location
   DisableBgpRoutePropagation = $true
}


# Firewall Premium policy
$fwPolicyParams = @{
   Name = 'fw-premium-policy-next'
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
echo $firewallPremiumParams
echo $keyVaultSettingsParams
echo $keyVaultIntermediateCertParams
echo $managedIdentityParams
echo $logParams
echo $routeTableParams
echo $fwPolicyParams

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

5. **Create a Windows 10 Pro VM for testing purposes**

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

   # Recreate the Firewall Premium params if required
   $firewallPremiumParams = @{
      Name = "fw-premium-next"
      ResourceGroupName = $rgParams.Name
      Location = $rgParams.Location
      VirtualNetwork = $vNet
      PublicIpAddress = $firewallPip
      SkuTier = "Premium"
   }

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
   $keyVault | New-AzRoleAssignment -RoleDefinitionName "Reader" -objectId $objectId.Id
   $keyVault | Set-AzKeyVaultAccessPolicy -objectId $objectId.Id -PermissionsToCertificates "Get","List" -PermissionsToSecrets "Get","List"
   ```

10. **Create a self-signed certificate for TLS inspection**

    ```PowerShell
    # Run the following command if you get an error stating cert.ps1 is not digitally signed
    Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass

    # Create our self Signed Certificates
    cd .\scripts\ & .\cert.ps1 & cd ..
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

    # Enables AzureFirewallApplicationRule, AzureFirewallNetworkRule and AzureFirewallDnsProxy rules
    $logDiagnosticSettingsParams = @{
       Name = "FW-Premium-Diagnostics-next"
       ResourceId = $firewallPremium.Id
       WorkspaceId = $log.ResourceId
       Enabled = $true
       RetentionEnable = $true
       RetentionInDays = 30
    }
    echo $logDiagnosticSettingsParams

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

13. **Deploy a premium azure firewall policy with Intrusion Detection and Prevention System (IDPS)**

    ```PowerShell
    $keyVaultManagedIdentity = Get-AzUserAssignedIdentity -ResourceGroupName $managedIdentityParams.ResourceGroupName -Name $managedIdentityParams.Name
    $tlsCert = Get-AzKeyVaultCertificate -Name $keyVaultIntermediateCertParams.Name  -InputObject $keyVault

    # Enable IDPS
    $idpsSettings = New-AzFirewallPolicyIntrusionDetection -Mode "Alert"

    $fwPolicyParams = @{
       Name = 'fw-premium-policy-next'
       ResourceGroupName = $rgParams.Name
       Location = $rgParams.Location
       SkuTier = "Premium"
       TransportSecurityName = "tls-premium-fw"
       TransportSecurityKeyVaultSecretId = $tlsCert.SecretId
       UserAssignedIdentityId = $keyVaultManagedIdentity.Id
       IntrusionDetection = $idpsSettings
    }

    $fwPolicy = New-AzFirewallPolicy @fwPolicySettings
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

targetScope = 'resourceGroup'

@description('Name of the Log Analytics workspace to create or use.')
@minLength(4)
param workspaceName string

@description('Create the workspace when true. Set false to reference an existing workspace.')
param createWorkspace bool = true

@description('Region for a new workspace. Empty uses this resource group region.')
param workspaceLocation string = ''

@description('SKU applied only when a new workspace is created.')
@allowed([
  'PerGB2018'
])
param workspaceSkuName string = 'PerGB2018'

@description('Interactive retention for a new workspace.')
@allowed([
  30
  31
  60
  90
  120
  180
  270
  365
  550
  730
])
param retentionInDays int = 30

@description('Daily ingestion cap in GB for a new lab workspace. This template bounds it to 1-100 GB/day.')
@minValue(1)
@maxValue(100)
param dailyQuotaGb int = 1

@description('Apply the Sentinel onboarding state to an existing workspace. Leave false to preserve its existing CMK setting and onboarding state.')
param onboardExistingWorkspace bool = false

var resolvedWorkspaceLocation = empty(workspaceLocation)
  ? resourceGroup().location
  : workspaceLocation

resource workspace 'Microsoft.OperationalInsights/workspaces@2023-09-01' = if (createWorkspace) {
  name: workspaceName
  location: resolvedWorkspaceLocation
  properties: {
    features: {
      disableLocalAuth: true
      enableLogAccessUsingOnlyResourcePermissions: true
    }
    publicNetworkAccessForIngestion: 'Enabled'
    publicNetworkAccessForQuery: 'Enabled'
    retentionInDays: retentionInDays
    sku: {
      name: workspaceSkuName
    }
    workspaceCapping: {
      dailyQuotaGb: dailyQuotaGb
    }
  }
}

resource existingWorkspace 'Microsoft.OperationalInsights/workspaces@2023-09-01' existing = if (!createWorkspace) {
  name: workspaceName
}

resource onboardingForNewWorkspace 'Microsoft.SecurityInsights/onboardingStates@2025-09-01' = if (createWorkspace) {
  name: 'default'
  scope: workspace
  properties: {
    customerManagedKey: false
  }
}

resource onboardingForExistingWorkspace 'Microsoft.SecurityInsights/onboardingStates@2025-09-01' = if (!createWorkspace && onboardExistingWorkspace) {
  name: 'default'
  scope: existingWorkspace
  properties: {
    customerManagedKey: false
  }
}

output workspaceResourceId string = createWorkspace
  ? workspace.id
  : existingWorkspace.id
output onboardingStateId string = createWorkspace
  ? onboardingForNewWorkspace.id
  : (onboardExistingWorkspace ? onboardingForExistingWorkspace.id : '')

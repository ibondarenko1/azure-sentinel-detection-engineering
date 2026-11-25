targetScope = 'subscription'

@description('Name of the resource group that already exists. This template does not create or modify the resource group.')
@minLength(1)
param resourceGroupName string

@description('Name of the Log Analytics workspace to create or use.')
@minLength(4)
param workspaceName string

@description('Create the workspace when true. Set false to use the named existing workspace without changing its workspace settings.')
param createWorkspace bool = true

@description('Region for a new workspace. Leave empty to use the existing resource group region.')
param workspaceLocation string = ''

@description('SKU applied only when a new workspace is created. Existing workspace SKU is never changed by this template.')
@allowed([
  'PerGB2018'
])
param workspaceSkuName string = 'PerGB2018'

@description('Interactive retention for a new workspace. Values follow the documented Log Analytics retention choices.')
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

@description('Daily ingestion cap in GB for a new lab workspace. The template bounds this to 1-100 GB/day; the service minimum is 0.023 GB/day and -1 means unlimited, which is not allowed here.')
@minValue(1)
@maxValue(100)
param dailyQuotaGb int = 1

@description('Opt in to exporting all subscription Activity Log categories to this workspace. Disabled by default.')
param enableActivityLogExport bool = false

@description('Apply the Sentinel onboarding state to an existing workspace. Leave false to preserve its existing CMK setting and onboarding state.')
param onboardExistingWorkspace bool = false

@description('Caller-chosen name for the subscription diagnostic setting. There is no default so a deployment cannot silently select a destination name.')
@minLength(1)
param diagnosticSettingName string

resource targetResourceGroup 'Microsoft.Resources/resourceGroups@2022-09-01' existing = {
  name: resourceGroupName
}

module workspaceBootstrap './workspace.bicep' = {
  name: 'sentinel-workspace-${uniqueString(subscription().id, resourceGroupName, workspaceName)}'
  scope: targetResourceGroup
  params: {
    workspaceName: workspaceName
    createWorkspace: createWorkspace
    workspaceLocation: workspaceLocation
    workspaceSkuName: workspaceSkuName
    retentionInDays: retentionInDays
    dailyQuotaGb: dailyQuotaGb
    onboardExistingWorkspace: onboardExistingWorkspace
  }
}

var activityLogCategories = [
  'Administrative'
  'Security'
  'ServiceHealth'
  'Alert'
  'Recommendation'
  'Policy'
  'Autoscale'
  'ResourceHealth'
]

resource subscriptionActivityLog 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = if (enableActivityLogExport) {
  name: diagnosticSettingName
  properties: {
    workspaceId: workspaceBootstrap.outputs.workspaceResourceId
    logs: [for category in activityLogCategories: {
      category: category
      enabled: true
    }]
  }
}

output resourceGroupId string = targetResourceGroup.id
output workspaceResourceId string = workspaceBootstrap.outputs.workspaceResourceId
output onboardingStateId string = workspaceBootstrap.outputs.onboardingStateId
output activityLogDiagnosticSettingId string = enableActivityLogExport
  ? subscriptionActivityLog.id
  : ''

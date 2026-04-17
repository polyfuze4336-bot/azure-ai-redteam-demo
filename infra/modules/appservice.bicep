// App Service module for Backend API

@description('Name of the App Service')
param name string

@description('Location for the resource')
param location string = resourceGroup().location

@description('Tags for the resource')
param tags object = {}

@description('App Service Plan ID')
param appServicePlanId string

@description('Runtime name (python, node, etc)')
param runtimeName string = 'python'

@description('Runtime version')
param runtimeVersion string = '3.11'

@description('Application settings')
param appSettings object = {}

@description('Startup command')
param appCommandLine string = ''

var runtimeStack = '${runtimeName}|${runtimeVersion}'

resource appService 'Microsoft.Web/sites@2022-03-01' = {
  name: name
  location: location
  tags: tags
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    serverFarmId: appServicePlanId
    httpsOnly: true
    siteConfig: {
      linuxFxVersion: runtimeStack
      appCommandLine: appCommandLine
      ftpsState: 'Disabled'
      minTlsVersion: '1.2'
      alwaysOn: true
      cors: {
        allowedOrigins: ['*']
        supportCredentials: false
      }
      appSettings: [for key in objectKeys(appSettings): {
        name: key
        value: appSettings[key]
      }]
    }
  }
}

// Configure diagnostic settings
resource appServiceLogs 'Microsoft.Web/sites/config@2022-03-01' = {
  parent: appService
  name: 'logs'
  properties: {
    applicationLogs: {
      fileSystem: {
        level: 'Information'
      }
    }
    httpLogs: {
      fileSystem: {
        enabled: true
        retentionInDays: 7
        retentionInMb: 35
      }
    }
    detailedErrorMessages: {
      enabled: true
    }
    failedRequestsTracing: {
      enabled: true
    }
  }
}

output id string = appService.id
output name string = appService.name
output uri string = 'https://${appService.properties.defaultHostName}'
output identityPrincipalId string = appService.identity.principalId

// Azure AI Red Team Demo - Infrastructure as Code
// Deploys: App Service (backend), Static Web App (frontend)
// Reuses: Existing Azure AI Foundry resource

targetScope = 'subscription'

@minLength(1)
@maxLength(64)
@description('Name of the environment (e.g., dev, prod)')
param environmentName string

@minLength(1)
@description('Primary location for all resources')
param location string

@description('Name of existing Azure AI Foundry resource to connect to')
param foundryResourceName string = 'mkhalib-4370-resource'

@description('Azure OpenAI deployment name')
param azureOpenAIDeploymentName string = 'gpt-4o'

@description('Azure OpenAI API version')
param azureOpenAIApiVersion string = '2024-02-15-preview'

@description('Existing Azure OpenAI endpoint (optional - will construct from resource name if not provided)')
param azureOpenAIEndpoint string = ''

@description('Existing resource group for AI Foundry (optional)')
param existingAIResourceGroup string = ''

// Tags for all resources
var tags = {
  'azd-env-name': environmentName
  application: 'azure-ai-redteam-demo'
  environment: environmentName
}

// Abbreviations for resource naming
var abbrs = loadJsonContent('./abbreviations.json')

// Resource token for unique naming
var resourceToken = toLower(uniqueString(subscription().id, environmentName, location))

// Construct Azure OpenAI endpoint if not provided
var computedAzureOpenAIEndpoint = empty(azureOpenAIEndpoint) 
  ? 'https://${foundryResourceName}.openai.azure.com' 
  : azureOpenAIEndpoint

// Resource Group for the application
resource rg 'Microsoft.Resources/resourceGroups@2021-04-01' = {
  name: 'rg-${environmentName}'
  location: location
  tags: tags
}

// App Service Plan for backend API
module appServicePlan './modules/appserviceplan.bicep' = {
  name: 'appServicePlan'
  scope: rg
  params: {
    name: '${abbrs.webServerFarms}${resourceToken}'
    location: location
    tags: tags
    sku: {
      name: 'B1'
      tier: 'Basic'
    }
    kind: 'linux'
    reserved: true
  }
}

// App Service for Backend API
module appService './modules/appservice.bicep' = {
  name: 'appService'
  scope: rg
  params: {
    name: '${abbrs.webSitesAppService}api-${resourceToken}'
    location: location
    tags: union(tags, { 'azd-service-name': 'api' })
    appServicePlanId: appServicePlan.outputs.id
    runtimeName: 'python'
    runtimeVersion: '3.11'
    appSettings: {
      // Application mode
      RUN_MODE: 'azure'
      
      // Azure AI Foundry configuration
      FOUNDRY_RESOURCE_NAME: foundryResourceName
      AZURE_OPENAI_ENDPOINT: computedAzureOpenAIEndpoint
      AZURE_OPENAI_DEPLOYMENT_NAME: azureOpenAIDeploymentName
      AZURE_OPENAI_API_VERSION: azureOpenAIApiVersion
      
      // Use managed identity for authentication
      // AZURE_OPENAI_API_KEY will be set via Key Vault reference or azd env
      
      // Application settings
      SAFETY_LAYER_ENABLED: 'true'
      SAFETY_LAYER_FALLBACK_TO_MOCK: 'true'
      TELEMETRY_ENABLED: 'true'
      
      // CORS for frontend
      CORS_ORIGINS: '*'
    }
    appCommandLine: 'gunicorn main:app --workers 4 --worker-class uvicorn.workers.UvicornWorker --bind 0.0.0.0:8000'
  }
}

// Static Web App for Frontend
module staticWebApp './modules/staticwebapp.bicep' = {
  name: 'staticWebApp'
  scope: rg
  params: {
    name: '${abbrs.webStaticSites}web-${resourceToken}'
    location: location
    tags: union(tags, { 'azd-service-name': 'web' })
    // API backend URL will be configured post-deployment
  }
}

// Outputs for azd
output AZURE_LOCATION string = location
output AZURE_TENANT_ID string = tenant().tenantId
output SERVICE_API_URI string = appService.outputs.uri
output SERVICE_WEB_URI string = staticWebApp.outputs.uri
output FOUNDRY_RESOURCE_NAME string = foundryResourceName
output AZURE_OPENAI_ENDPOINT string = computedAzureOpenAIEndpoint

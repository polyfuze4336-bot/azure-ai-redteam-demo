# Azure AI Red Team Demo

A demonstration application for Azure AI red teaming capabilities. This app simulates adversarial testing against AI models protected by Azure AI Content Safety and Prompt Shields.

![Azure AI Red Team Demo](docs/screenshot.png)

## Features

- **Attack Console**: Execute red team scenarios against protected AI models
- **Campaign History**: View historical attack campaigns and results  
- **Comparison Mode**: Side-by-side baseline vs guarded model comparison
- **PyRIT Integration**: Optional automated red teaming with Microsoft PyRIT
- **Real-time Metrics**: Defense rate, attack success tracking, latency monitoring

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     Azure AI Red Team Demo                       │
├─────────────────────────────────────────────────────────────────┤
│  Frontend (React + TypeScript + Tailwind)                        │
│  - Attack Console UI                                             │
│  - Campaign History                                              │
│  - Comparison View                                               │
├─────────────────────────────────────────────────────────────────┤
│  Backend API (FastAPI + Python)                                  │
│  - Attack Runner Pipeline                                        │
│  - Safety Layer (Content Safety + Prompt Shields)                │
│  - Evaluator Service                                             │
│  - Telemetry & Tracing                                           │
├─────────────────────────────────────────────────────────────────┤
│  Azure AI Foundry                                                │
│  - Azure OpenAI (GPT-4o)                                         │
│  - Azure AI Content Safety                                       │
│  - Prompt Shields                                                │
└─────────────────────────────────────────────────────────────────┘
```

## Quick Start

### Prerequisites

- Python 3.11+
- Node.js 18+
- Azure CLI (`az`) - for authentication
- Azure Developer CLI (`azd`) - for deployment
- Access to Azure AI Foundry with a deployed model

### Local Development

1. **Clone the repository**
   ```bash
   git clone https://github.com/YOUR_USERNAME/azure-ai-redteam-demo.git
   cd azure-ai-redteam-demo
   ```

2. **Configure environment**
   ```bash
   # Backend
   cd backend
   cp .env.example .env
   # Edit .env with your Azure AI Foundry details
   ```

3. **Start backend**
   ```bash
   cd backend
   pip install -r requirements.txt
   uvicorn main:app --reload
   ```

4. **Start frontend**
   ```bash
   cd frontend
   npm install
   npm run dev
   ```

5. **Open browser**
   Navigate to http://localhost:5173

### Azure Deployment

Deploy to Azure using Azure Developer CLI:

```bash
# Login to Azure
az login
azd auth login

# Initialize environment
azd init

# Deploy (creates App Service + Static Web App)
azd up
```

This will:
- Create an Azure App Service for the backend API
- Create an Azure Static Web App for the frontend
- Configure environment variables to connect to your Azure AI Foundry resource

## Configuration

### Environment Variables

| Variable | Description | Required |
|----------|-------------|----------|
| `RUN_MODE` | `demo` or `azure` | Yes |
| `FOUNDRY_RESOURCE_NAME` | Azure AI Foundry resource name | Yes (azure mode) |
| `AZURE_OPENAI_ENDPOINT` | Azure OpenAI endpoint URL | Yes (azure mode) |
| `AZURE_OPENAI_DEPLOYMENT_NAME` | Model deployment name | Yes (azure mode) |
| `AZURE_OPENAI_API_KEY` | API key (or use DefaultCredential) | Conditional |

See [backend/.env.example](backend/.env.example) for full configuration options.

### Using Existing Azure AI Foundry Resource

This demo is designed to connect to your existing Azure AI Foundry resource. The default configuration uses:

- **Resource**: `mkhalib-4370-resource`
- **Model**: `gpt-4o`

Update the environment variables or Bicep parameters to use your own resource.

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Health check |
| `/api/attacks` | POST | Run single attack |
| `/api/campaigns` | POST | Run attack campaign |
| `/api/campaigns` | GET | List campaigns |
| `/api/scenarios` | GET | List attack scenarios |
| `/api/comparison` | POST | Run comparison attack |

## Project Structure

```
azure-ai-redteam-demo/
├── azure.yaml              # Azure Developer CLI config
├── infra/                  # Bicep infrastructure
│   ├── main.bicep
│   └── modules/
├── backend/                # FastAPI backend
│   ├── main.py
│   ├── config.py
│   ├── models/
│   ├── routes/
│   ├── services/
│   └── telemetry/
└── frontend/               # React frontend
    ├── src/
    │   ├── components/
    │   ├── pages/
    │   └── services/
    └── package.json
```

## Development

### Running Tests

```bash
# Backend tests
cd backend
pytest

# Frontend tests
cd frontend
npm test
```

### Demo Mode

For local testing without Azure connection:

```bash
# In backend/.env
RUN_MODE=demo
```

This uses mock responses instead of real Azure AI calls.

## Security

- API keys should never be committed to source control
- Use Azure Managed Identity in production
- Content Safety provides input/output filtering
- Prompt Shields detect jailbreak and injection attempts

## License

MIT

## Contributing

1. Fork the repository
2. Create a feature branch
3. Submit a pull request

## Support

For issues and questions, please open a GitHub issue.

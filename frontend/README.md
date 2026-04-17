# Azure AI Red Team Console - Frontend

A modern, demo-grade frontend for adversarial testing of Azure AI applications.

## Features

- **Attack Console**: Configure and execute curated attack scenarios
- **Campaign History**: View past red teaming campaigns and results
- **Comparison Mode**: Side-by-side baseline vs guarded model behavior

## Quick Start

```bash
# Install dependencies
npm install

# Start development server
npm run dev
```

The app will open at http://localhost:3000

## Project Structure

```
frontend/
├── src/
│   ├── components/      # Reusable UI components
│   │   ├── Layout.tsx   # Main layout with navigation
│   │   ├── Panel.tsx    # Glass-panel container
│   │   ├── Select.tsx   # Styled dropdown
│   │   ├── StatusBadge.tsx  # Status indicators
│   │   ├── SummaryBar.tsx   # Top metrics bar
│   │   ├── Toggle.tsx   # Switch component
│   │   └── VerdictCard.tsx  # Verdict display cards
│   ├── pages/
│   │   ├── AttackConsole.tsx    # Main attack interface
│   │   ├── CampaignHistory.tsx  # Historical campaigns
│   │   └── ComparisonView.tsx   # Baseline vs guarded
│   ├── data/
│   │   └── mockData.ts  # Mock scenarios and results
│   ├── types/
│   │   └── index.ts     # TypeScript interfaces
│   ├── App.tsx          # Router setup
│   ├── main.tsx         # Entry point
│   └── index.css        # Tailwind + custom styles
├── public/
│   └── shield.svg       # Favicon
├── index.html
├── package.json
├── tailwind.config.js
├── tsconfig.json
└── vite.config.ts
```

## Design System

- **Colors**: Azure blues, danger reds, success greens, warning oranges
- **Components**: Glass-panel cards with subtle borders
- **Typography**: Segoe UI system font, Cascadia Code for monospace
- **Spacing**: Consistent 4px grid system

## Mock Data

The frontend uses curated attack scenarios for demo purposes. Backend integration will be added in future iterations.

### Attack Categories (9 total)

| Category | Icon | Description |
|----------|------|-------------|
| **Jailbreak** | 🔓 | Bypass model safety guidelines and restrictions |
| **Prompt Injection** | 💉 | Hijack model behavior with malicious instructions |
| **Prompt Extraction** | 🔍 | Reveal hidden system prompts or instructions |
| **Data Exfiltration** | 📤 | Extract sensitive or training data |
| **Credential Theft** | 🔑 | Social engineering to obtain credentials or secrets |
| **Policy Evasion** | 🎭 | Circumvent content policies through obfuscation |
| **Indirect Injection** | 🔀 | Inject prompts via external content or documents |
| **Tool Misuse** | 🔧 | Manipulate AI to misuse connected tools or APIs |
| **Code Vulnerability** | ⚠️ | Trick AI into generating insecure or malicious code |

### Sample Scenarios (27 total)

Each scenario includes:
- **Name**: Human-readable scenario title
- **Category**: Attack classification
- **Sample Prompt**: Curated attack payload
- **Description**: What the attack does
- **Expected Behavior**: How a secure model should respond
- **Narrator Notes**: Demo talking points for presenters

## Tech Stack

- React 18 + TypeScript
- Vite (build tool)
- Tailwind CSS
- React Router
- Lucide React (icons)

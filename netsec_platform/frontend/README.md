# NetSec Platform Frontend

React-based frontend for the NetSec Platform - Network Security Visibility and Traffic Analysis.

## Tech Stack

- **React 18** with TypeScript
- **Vite** - Build tool
- **Material-UI (MUI)** - UI components
- **Zustand** - State management
- **React Router** - Navigation
- **Axios** - HTTP client
- **Recharts** - Charts
- **Cytoscape** - Network visualization (planned)

## Getting Started

### Prerequisites

- Node.js 18+
- npm or yarn

### Installation

```bash
npm install
```

### Development

```bash
npm run dev
```

The app will be available at `http://localhost:3000`

### Build

```bash
npm run build
```

### Preview Production Build

```bash
npm run preview
```

## Project Structure

```
src/
├── components/       # Reusable UI components
│   ├── Layout.tsx           # Main layout with sidebar
│   ├── EmergencyStopDialog.tsx  # ESS dialog
│   ├── StatCard.tsx         # Dashboard stat cards
│   └── TrafficChart.tsx     # Traffic visualization
├── pages/            # Page components
│   ├── Dashboard.tsx        # Main dashboard
│   ├── Login.tsx            # Login page
│   ├── Capture.tsx          # Packet capture control
│   ├── Flows.tsx            # Network flows view
│   ├── Findings.tsx         # Security findings
│   ├── Evidence.tsx         # Evidence viewer
│   └── ...
├── services/         # API client
│   └── api.ts               # Axios-based API service
├── store/            # Zustand stores
│   └── index.ts             # Auth, capture, data, UI stores
├── hooks/            # Custom React hooks
│   └── useWebSocket.ts      # WebSocket hook
├── types/            # TypeScript types
│   └── index.ts             # All type definitions
├── utils/            # Utility functions
├── App.tsx           # Main app component
└── main.tsx          # Entry point
```

## Features

- **Dashboard**: Real-time stats, traffic charts, top talkers
- **Capture Control**: Start/stop packet capture, select interfaces
- **Emergency Security Stop**: One-click emergency shutdown
- **Network Flows**: View and filter network conversations
- **Security Findings**: Browse and manage detected issues
- **Evidence Viewer**: Secure evidence access with controlled reveal
- **Asset Inventory**: Discovered hosts and services
- **DNS Analysis**: Query tracking and anomaly detection
- **Timeline**: Event chronology for investigations
- **Network Graph**: Visual relationship mapping
- **Cases**: Investigation case management
- **Reports**: Generate HTML/PDF/JSON/CSV reports

## API Integration

The frontend connects to the backend API at `/api` (proxied to `http://localhost:8000` in development).

Key endpoints:
- `GET /api/capture/status` - Capture status
- `POST /api/capture/start` - Start capture
- `POST /api/capture/stop` - Stop capture
- `GET /api/ess/status` - ESS status
- `POST /api/ess/activate` - Activate ESS
- `GET /api/dashboard/stats` - Dashboard statistics
- `GET /api/flows` - Network flows
- `GET /api/findings` - Security findings
- `GET /api/evidence` - Evidence list
- `POST /api/evidence/:id/reveal` - Reveal sensitive value

## Authentication

JWT-based authentication with automatic token refresh and logout on 401 errors.

## Security Notes

- Sensitive values are never displayed by default
- Evidence reveal requires explicit authorization and reason
- All actions are audited
- ESS is always accessible from the top bar

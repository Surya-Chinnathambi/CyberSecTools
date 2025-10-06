# CyberSec AI Platform

## Overview
A modern cybersecurity platform with React frontend + FastAPI backend architecture, featuring production-quality animations and comprehensive security tools.

## Tech Stack

### Frontend (Port 5000)
- **React 18+** with TypeScript
- **Vite** for blazing-fast dev experience
- **Tailwind CSS v4** with Vite plugin
- **Framer Motion** for fluid animations
- **Lottie React** for micro-animations
- **React Hot Toast** for notifications
- **Axios** for API communication
- **React Router** for navigation

### Backend (Port 8000)
- **FastAPI** with async/await
- **Uvicorn** ASGI server
- **JWT** authentication with Argon2 password hashing
- **SQLite** database
- **OpenAI** integration for AI chat
- **Stripe** for billing
- **ReportLab** for PDF reports
- **NIST NVD API** for CVE database
- **Shodan API** for intelligence
- **Python-nmap** for port scanning

## Features

### 🔐 Authentication
- JWT-based auth with secure token storage
- Argon2 password hashing
- Role-based access control (Free/Pro tiers)

### 🔍 Security Scanning
- **Port Scanner**: Network port discovery with nmap integration
- **Web Scanner**: Vulnerability detection (headers, SSL, common issues)
- Scan history and result storage

### 🤖 AI Security Assistant
- OpenAI-powered security analysis
- Context-aware recommendations
- Scan result analysis

### 📊 Dashboard
- Real-time activity feed with auto-scroll
- Live metrics with animated counters
- Vulnerability distribution charts

### 🔒 CVE Database
- Search 200,000+ vulnerabilities from NIST NVD
- Real-time CVE details and scoring
- CVSS score display

### 🌐 Shodan Intelligence
- Internet-connected device search
- Geolocation data
- Service fingerprinting

### 💥 Exploit Database
- Exploit-DB integration
- Filter by type and platform
- POC code access

### 📄 Reports
- PDF report generation
- Scan summaries
- Download functionality

### 💳 Billing
- Stripe integration
- Multiple subscription tiers
- Usage tracking

## Advanced Animation Features

### 🌟 GlowingCard Component
- Subtle vertical floating animation
- Rotating neon gradient aura (20s rotation)
- Pulsing glow effect
- 1.03 scale on hover with spring physics
- GPU-accelerated transforms

### 📡 LiveBadge Component
- Pulse animation for live status
- Ripple effect on data updates
- Smooth number counter transitions
- Crossfade for metric updates

### 📺 LiveFeed Component
- Slide-up animation for new entries
- Auto-scroll with "jump to newest" button
- Pause on user scroll
- Color-coded message types

### 🎯 AnimatedIcon Component
- Three hover effects: pop, rotate, colorShift
- Keyboard focus visible
- Spring-based animations
- ARIA labels for accessibility

### 🎊 Toast System
- Spring motion entrance from bottom-right
- Lottie success animations
- Auto-dismiss with smooth exit
- Error, success, and loading states

### 🔄 Page Transitions
- Route-aware fade/slide animations
- Exit animations with AnimatePresence
- Stagger children for list items
- Custom easing curves

### 📈 Progress Loaders
- Top bar with gradient (blue → purple → pink)
- Skeleton loaders with pulse
- Intelligent progress simulation

## Performance & Accessibility

### ⚡ Performance
- Transform and opacity-only animations (GPU-accelerated)
- will-change hints for optimization
- Reduced motion support via media query
- Lazy loading and code splitting

### ♿ Accessibility
- Keyboard navigation support
- Focus-visible states
- ARIA labels on interactive elements
- Screen reader friendly
- Prefers-reduced-motion compliance

## API Endpoints

### Auth
- `POST /api/auth/register` - User registration
- `POST /api/auth/login` - User login
- `GET /api/auth/me` - Get current user
- `GET /api/auth/usage` - Get usage stats

### Scanning
- `POST /api/scan/port` - Port scan
- `POST /api/scan/web` - Web vulnerability scan
- `GET /api/scan/history` - Scan history
- `GET /api/scan/result/{id}` - Get scan result

### AI Chat
- `POST /api/chat/message` - Send chat message
- `POST /api/chat/analyze` - Analyze scan results

### Dashboard
- `GET /api/dashboard/stats` - Dashboard statistics
- `GET /api/dashboard/activity` - Activity feed
- `GET /api/dashboard/vulnerability-distribution` - Vuln distribution

### CVE
- `GET /api/cve/search` - Search CVEs
- `GET /api/cve/details/{cve_id}` - CVE details

### Shodan
- `GET /api/shodan/search` - Search Shodan
- `GET /api/shodan/host/{ip}` - Host details
- `GET /api/shodan/api-info` - API info

### Exploits
- `GET /api/exploits/search` - Search exploits
- `GET /api/exploits/details/{id}` - Exploit details

### Billing
- `GET /api/billing/plans` - Get plans
- `GET /api/billing/subscription` - Get subscription
- `POST /api/billing/create-checkout` - Create checkout

### Reports
- `POST /api/reports/generate` - Generate report
- `GET /api/reports/list` - List reports
- `GET /api/reports/download/{id}` - Download report

## Environment Variables

### Frontend (.env)
```
VITE_API_URL=https://[replit-domain]:8000
```

### Backend (.env)
```
SECRET_KEY=your-secret-key-here
DATABASE_URL=sqlite:///./cybersec.db
OPENAI_API_KEY=your-openai-key
SHODAN_API_KEY=your-shodan-key
STRIPE_SECRET_KEY=your-stripe-key
STRIPE_PUBLISHABLE_KEY=your-stripe-publishable-key
```

## Recent Changes (October 2025)

### Frontend Refactor
- ✅ Migrated from Streamlit to React + TypeScript
- ✅ Implemented Tailwind CSS v4 with Vite plugin
- ✅ Created 6 specialized animation components
- ✅ Built 9 feature pages with animations
- ✅ Integrated Framer Motion for smooth transitions
- ✅ Added toast notification system
- ✅ Implemented responsive navigation

### Backend Updates
- ✅ Complete FastAPI implementation
- ✅ All 9 routers functioning
- ✅ JWT authentication with Argon2
- ✅ Database models and services
- ✅ CORS configuration for React frontend

## Architecture

```
cybersec-platform/
├── frontend/                 # React + TypeScript frontend
│   ├── src/
│   │   ├── components/      # Reusable components
│   │   │   ├── GlowingCard.tsx
│   │   │   ├── LiveBadge.tsx
│   │   │   ├── LiveFeed.tsx
│   │   │   ├── AnimatedIcon.tsx
│   │   │   ├── ProgressLoader.tsx
│   │   │   ├── ToastSystem.tsx
│   │   │   └── Layout.tsx
│   │   ├── pages/           # Page components
│   │   │   ├── Login.tsx
│   │   │   ├── Dashboard.tsx
│   │   │   ├── PortScanner.tsx
│   │   │   ├── WebScanner.tsx
│   │   │   ├── AIChat.tsx
│   │   │   ├── CVEDatabase.tsx
│   │   │   ├── ShodanIntelligence.tsx
│   │   │   ├── ExploitDatabase.tsx
│   │   │   ├── Reports.tsx
│   │   │   └── Billing.tsx
│   │   ├── services/        # API services
│   │   │   └── api.ts
│   │   ├── utils/           # Utilities
│   │   │   └── animations.ts
│   │   ├── App.tsx          # Main app with routing
│   │   └── main.tsx         # Entry point
│   └── vite.config.ts       # Vite configuration
│
├── backend/                  # FastAPI backend
│   ├── routers/             # API route handlers
│   │   ├── auth.py
│   │   ├── scanning.py
│   │   ├── chat.py
│   │   ├── dashboard.py
│   │   ├── cve.py
│   │   ├── shodan.py
│   │   ├── exploits.py
│   │   ├── billing.py
│   │   └── reports.py
│   ├── services/            # Business logic
│   │   ├── port_scanner_service.py
│   │   ├── web_scanner_service.py
│   │   └── report_service.py
│   ├── models/              # Data models
│   │   ├── user.py
│   │   └── scan.py
│   ├── utils/               # Utilities
│   │   └── database.py
│   └── main.py              # FastAPI app entry
│
└── replit.md                # This file
```

## Development

### Running Locally
1. Backend: `cd backend && uvicorn main:app --host 0.0.0.0 --port 8000`
2. Frontend: `cd frontend && npm run dev`

### Building for Production
```bash
cd frontend && npm run build
```

## Workflows
- **Backend API**: Runs on port 8000
- **Frontend**: Runs on port 5000 with webview output

## Notes
- All backend logic and API endpoints preserved from original Streamlit version
- Frontend completely rebuilt with modern React stack
- Production-quality animations with performance optimization
- Accessibility features included (reduced motion, keyboard nav, ARIA labels)
- GPU-accelerated animations using transform/opacity only

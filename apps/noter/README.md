# Noter

AI assistant platform powered by Sui blockchain zkLogin authentication.

## Features

- **zkLogin Authentication**: Privacy-preserving blockchain authentication using OAuth
- **AI Chat**: Conversational AI powered by multiple models (Claude, GPT, etc.)
- **Sui Integration**: Blockchain-based identity without traditional wallets
- **Zero-Knowledge Proofs**: Authenticate without revealing credentials on-chain

## Tech Stack

- **Framework**: Next.js 16 (App Router, Turbopack, React 19)
- **Database**: PostgreSQL + Drizzle ORM
- **State**: Jotai (atomic state management)
- **API**: tRPC (type-safe API layer)
- **AI**: Vercel AI SDK v6
- **Blockchain**: Sui Network (zkLogin)
- **Styling**: Tailwind CSS 4, shadcn/ui
- **Validation**: Zod schemas

## Getting Started

### Prerequisites

- Node.js 22.23.4+ (or 24.22.1+ / 26.12.1+) and pnpm
- PostgreSQL database (Neon, Supabase, or local)
- Google OAuth credentials
- Environment variables configured

### Installation

```bash
# Install dependencies
pnpm install

# Setup environment variables
cp .env.example .env
# Edit .env with your values

# Generate database tables
pnpm db:push

# Run development server
pnpm dev
```

Open [http://localhost:3000](http://localhost:3000) to see the app.

## Environment Variables

Create a `.env` file with:

```bash
# Database
DATABASE_URL=postgresql://...

# Enoki zkLogin (client-side, NEXT_PUBLIC_*)
NEXT_PUBLIC_ENOKI_API_KEY=...
NEXT_PUBLIC_GOOGLE_CLIENT_ID=...
NEXT_PUBLIC_MEMWAL_PACKAGE_ID=0x...
NEXT_PUBLIC_MEMWAL_REGISTRY_ID=0x...
NEXT_PUBLIC_MEMWAL_SERVER_URL=http://localhost:9000

# Sui network
NEXT_PUBLIC_SUI_NETWORK=testnet

# Auth challenge store (server-side, required for Enoki sign-in)
REDIS_URL=redis://localhost:6379

# AI
OPENROUTER_API_KEY=...

# App
NEXT_PUBLIC_APP_URL=http://localhost:3000

# Walrus Memory
MEMWAL_SERVER_URL=http://localhost:8000
```

Enoki is the sign-in flow the app uses; `NEXT_PUBLIC_ENOKI_API_KEY` and
`NEXT_PUBLIC_GOOGLE_CLIENT_ID` come from the Enoki portal / Google Cloud console,
and the `MEMWAL_*` package/registry IDs identify the on-chain account contract.
`REDIS_URL` backs the single-use ownership challenge issued during sign-in — sign-in
fails closed if it is unset or unreachable.

Walrus Memory credentials are registered per authenticated user after wallet
ownership and on-chain account/delegate verification. Shared process-wide delegate
credentials are intentionally unsupported.

### Getting OAuth credentials

`NEXT_PUBLIC_GOOGLE_CLIENT_ID` is the Google OAuth client ID registered with your
Enoki application; follow the Enoki portal's setup for the redirect/origin
configuration. No custom `/auth/callback` route is used — the Enoki wallet handles
the OAuth round-trip client-side.

## Project Structure

```
noter/
├── app/                    # Next.js app router
│   ├── ai/                 # AI chat routes (protected)
│   ├── api/                # API routes (tRPC)
│   └── page.tsx            # Home page
├── package/
│   ├── feature/            # Feature modules
│   │   ├── auth/           # zkLogin authentication
│   │   └── chat/           # AI chat
│   └── shared/             # Shared code
│       ├── components/ui/  # shadcn/ui components
│       ├── db/             # Database schema & types
│       ├── lib/            # Utilities & config
│       └── style/          # Global styles
├── doc/                    # Documentation
│   ├── architecture.md     # System architecture
│   ├── type-flow.md        # Type derivation patterns
│   └── zklogin-integration.md  # zkLogin guide
└── public/                 # Static files
```

## Key Features

### Authentication

Users sign in with Enoki zkLogin (Google), a Sui wallet, or a delegate key, and
receive a Sui blockchain address. Sign-in proves control of the address by signing
a server-issued single-use challenge:

```tsx
import { useAuth, AuthButtonGroup } from "@/feature/auth";

function App() {
  const { isAuthenticated, user, logout } = useAuth();

  if (!isAuthenticated) {
    return <AuthButtonGroup />;
  }

  return (
    <div>
      <p>Sui Address: {user.suiAddress}</p>
      <button onClick={logout}>Sign Out</button>
    </div>
  );
}
```

### Protected Routes

Use `AuthGuard` to protect routes:

```tsx
import { AuthGuard } from "@/feature/auth";

export default function ProtectedLayout({ children }) {
  return (
    <AuthGuard>
      {children}
    </AuthGuard>
  );
}
```

### AI Chat

AI-powered conversations with tool execution:

```tsx
import { ChatContainer } from "@/feature/chat";

function ChatPage() {
  return <ChatContainer chatId={chatId} />;
}
```

## Development

### Database Commands

```bash
# Generate migration
pnpm db:generate

# Push schema to database (dev)
pnpm db:push

# Run migrations (production)
pnpm db:migrate

# Open Drizzle Studio
pnpm db:studio

# One-time deploy step: revoke any legacy custom-zkLogin sessions
pnpm db:purge-legacy-sessions
```

`pnpm db:purge-legacy-sessions` clears leftover rows from `zklogin_sessions`
(leaving `wallet_sessions` untouched). The app no longer reads or trusts that
table for authentication, so this is optional data hygiene rather than a required
security step. It is idempotent and safe to re-run.

### Code Quality

```bash
# Lint
pnpm lint

# Type check
pnpm type-check
```

## Architecture Patterns

### Type Flow

```
schema.ts → type.ts → input.ts → form.ts → component.tsx
```

1. Define tables in `shared/db/schema.ts`
2. Types auto-derived in `shared/db/type.ts`
3. API inputs in `feature/*/api/input.ts` (derived via `.pick().extend()`)
4. Form schemas in `feature/*/api/form.ts`
5. Components use types from `shared/db/type.ts`

### Feature Structure

```
package/feature/[name]/
├── index.ts          # Public API
├── constant.ts       # Static values
├── domain/
│   ├── type.ts       # Feature types
│   └── [name].ts     # Pure domain logic
├── api/
│   ├── input.ts      # API inputs (Zod)
│   └── route.ts      # tRPC routes
├── state/
│   └── atom.ts       # Jotai atoms
├── hook/
│   └── use-*.ts      # React hooks
├── ui/
│   └── *.tsx         # React components
└── lib/
    └── *.ts          # Utilities
```

### Rules

1. **Schema is source of truth** – All tables in `shared/db/schema.ts`
2. **Derive, never redefine** – Use `insertSchema.pick().extend()`
3. **Cross-feature imports via index.ts only** – Never import internal files
4. **Domain functions are pure** – No DB, no async
5. **Types flow down** – schema → type → input → form → UI

## Documentation

- [Architecture](./doc/architecture.md) – System structure and patterns
- [Type Flow](./doc/type-flow.md) – How types are derived
- [zkLogin Integration](./doc/zklogin-integration.md) – Authentication guide

## Deployment

### Build

```bash
pnpm build
```

### Environment

Ensure all environment variables are set in production:

- Database URL
- OAuth credentials
- Sui network configuration
- AI API keys

### Database Migrations

Run migrations before deploying:

```bash
pnpm db:migrate
```

## License

MIT

## Learn More

- [Sui zkLogin Documentation](https://docs.sui.io/guides/developer/cryptography/zklogin-integration)
- [Next.js Documentation](https://nextjs.org/docs)
- [tRPC Documentation](https://trpc.io)
- [Drizzle ORM Documentation](https://orm.drizzle.team)

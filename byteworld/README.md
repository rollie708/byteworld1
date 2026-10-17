# BYTEWORLD

BYTEWORLD is an evidence-led reverse engineering agent MVP for EVM smart contracts. This project is standalone and has no dependency on other workspace projects.

## Run locally

Requires Node.js 18 or newer. No npm packages or database are required.

```sh
cd byteworld
npm start
```

Open <http://localhost:3000>. During development, run `npm run dev` for Node's watch mode.

## Networks and configuration

Ethereum Mainnet, Base, Arbitrum One, and Optimism are supported. The service uses public RPC endpoints by default. For production, use reliable providers and set server-side environment variables:

| Variable | Purpose |
| --- | --- |
| `PORT` | HTTP listening port (default `3000`) |
| `ETHEREUM_RPC_URL` | Ethereum JSON-RPC endpoint |
| `BASE_RPC_URL` | Base JSON-RPC endpoint |
| `ARBITRUM_RPC_URL` | Arbitrum One JSON-RPC endpoint |
| `OPTIMISM_RPC_URL` | Optimism JSON-RPC endpoint |

The application checks Sourcify's public repository for verified metadata. No provider secrets are embedded in browser code. The server applies a 10-second RPC timeout, a bounded request body, input validation, and a 60-second in-memory result cache. Deploy behind a reverse proxy with production rate limiting and TLS.

## Analysis boundaries

Live reports retrieve contract bytecode and attempt verified-source metadata retrieval. When an ABI is available, its function signatures are displayed. Without an ABI, only a small known selector catalog is scanned. An EIP-1967 implementation slot is checked as a proxy indicator. Permission indicators are heuristic; they do not confirm role assignments, access paths, reachability, or exploitability. There is no full decompilation, symbolic execution, transaction trace indexing, or discovered interaction graph in this MVP. Reports label these limitations and unknowns.

Explore Example opens a bundled static example for the public USDC contract and is visibly marked sample data. It is not a live chain response or current security assessment. Live reports and exports use actual provider responses. Reports remain in browser memory and can be exported as JSON; no report database or shareable saved URL is implemented.

## Deployment

### Netlify

This directory includes a Netlify configuration and serverless function. Deploy the **`byteworld` directory itself** as the site root. If the Git repository contains the parent workspace, set Netlify's **Base directory** to `byteworld`, leave the build command empty, and set the publish directory to `.`. Netlify then publishes `index.html` and routes `/api/investigate` to the included function. If using drag-and-drop, upload the contents of this directory (including `netlify.toml` and the `netlify/functions` folder), not the parent workspace. An incorrect base or publish directory is the usual cause of Netlify's Page not found screen.

Optional Netlify environment variables: `ETHEREUM_RPC_URL`, `BASE_RPC_URL`, `ARBITRUM_RPC_URL`, and `OPTIMISM_RPC_URL`. Set these in Site configuration → Environment variables, then redeploy. Public endpoints work as a default but may be rate limited.

### Standalone Node server

For a Node host, run `node server.mjs`, set `PORT` and provider URLs in the hosting environment, and direct requests to the service root. The static HTML, CSS, and JavaScript are served by the same process as `POST /api/investigate`. Use HTTPS, set suitable upstream request limits, and validate your provider's terms and capacity. The app intentionally does not run retrieved contract code.

## Accuracy and use

Contract source, RPC responses, and third-party metadata are treated as untrusted and rendered as escaped text. BYTEWORLD is investigative tooling, not an audit or guarantee of safety. Always review evidence and independently validate conclusions.

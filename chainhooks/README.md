# Passkey DAO Treasury - Chainhooks Integration

This directory contains the Hiro Chainhooks integration for monitoring Passkey DAO Treasury events in real-time.

## Overview

The chainhooks integration monitors the following events:

- **Proposals**: Creation of new treasury proposals
- **Votes**: Approval signatures from signers (using passkeys)
- **Executions**: Execution of approved proposals
- **Treasury Operations**: Deposits and transfers from the treasury
- **Passkey Authentications**: Signature verification events
- **Signer Management**: Adding/removing signers

## Setup

### Prerequisites

- Node.js 16+ installed
- A running Chainhook node (or access to a remote one)
- Deployed contracts on Stacks Testnet

### Installation

1. Install dependencies:
```bash
npm install
```

2. Configure environment:
```bash
cp .env.example .env
# Edit .env with your configuration
```

3. Update `.env` with your settings:
   - `DEPLOYER_ADDRESS`: Your contract deployer address
   - `CHAINHOOK_NODE_URL`: URL of your Chainhook node
   - `WEBHOOK_URL`: Your webhook endpoint URL
   - `WEBHOOK_AUTH`: Authorization token for webhooks

## Running

Start the chainhooks listener:

```bash
npm start
```

For development with auto-reload:

```bash
npm run dev
```

## Monitored Events

### Proposal Created
Triggers when a new proposal is created in the treasury.

### Proposal Approved
Triggers when a signer approves a proposal using their passkey.

### Proposal Executed
Triggers when an approved proposal is executed.

### Treasury Operation
Triggers on STX transfers involving the treasury contract.

### Passkey Authentication
Triggers when a passkey signature is verified.

### Signer Management
Triggers when signers are added, removed, or updated.

## Event Handler

The `handleEvent()` function in `index.js` processes incoming events. Customize this function to:

- Store events in a database
- Send notifications
- Update UI in real-time
- Trigger automated workflows

## Contract Addresses

The chainhooks monitor these contracts:
- Treasury Manager: `${DEPLOYER_ADDRESS}.treasury-manager`
- Proposal Engine: `${DEPLOYER_ADDRESS}.proposal-engine`
- Signer Registry: `${DEPLOYER_ADDRESS}.signer-registry`

## Troubleshooting

- Ensure your Chainhook node is running and accessible
- Verify contract addresses match your deployed contracts
- Check webhook endpoint is reachable
- Review logs for registration errors

## Learn More

- [Hiro Chainhooks Documentation](https://docs.hiro.so/chainhooks)
- [Chainhooks Client SDK](https://github.com/hirosystems/chainhook-client-ts)

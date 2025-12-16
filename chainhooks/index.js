require('dotenv').config();
const { Chainhook } = require('@hirosystems/chainhook-client');

const DEPLOYER_ADDRESS = process.env.DEPLOYER_ADDRESS || 'ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM';
const TREASURY_CONTRACT = `${DEPLOYER_ADDRESS}.treasury-manager`;
const PROPOSAL_CONTRACT = `${DEPLOYER_ADDRESS}.proposal-engine`;
const SIGNER_CONTRACT = `${DEPLOYER_ADDRESS}.signer-registry`;

const chainhook = new Chainhook({
  baseUrl: process.env.CHAINHOOK_NODE_URL || 'http://localhost:20456',
});

// Monitor DAO treasury events
async function monitorTreasuryEvents() {
  console.log('Monitoring Passkey DAO Treasury events...');
  console.log('Treasury Contract:', TREASURY_CONTRACT);
  console.log('Proposal Contract:', PROPOSAL_CONTRACT);
  console.log('Signer Contract:', SIGNER_CONTRACT);

  // Proposal creation hook
  const proposalCreatedHook = {
    uuid: 'passkey-dao-proposal-created',
    name: 'Proposal Created',
    version: 1,
    chains: ['stacks'],
    networks: {
      testnet: {
        'if_this': {
          scope: 'print_event',
          contract_identifier: TREASURY_CONTRACT,
          contains: 'Proposal'
        },
        'then_that': {
          http_post: {
            url: process.env.WEBHOOK_URL || 'http://localhost:3000/events/proposal-created',
            authorization_header: process.env.WEBHOOK_AUTH || 'Bearer secret'
          }
        }
      }
    }
  };

  // Vote/approval hook
  const proposalApprovedHook = {
    uuid: 'passkey-dao-proposal-approved',
    name: 'Proposal Approved',
    version: 1,
    chains: ['stacks'],
    networks: {
      testnet: {
        'if_this': {
          scope: 'print_event',
          contract_identifier: TREASURY_CONTRACT,
          contains: 'Approvals'
        },
        'then_that': {
          http_post: {
            url: process.env.WEBHOOK_URL || 'http://localhost:3000/events/proposal-approved',
            authorization_header: process.env.WEBHOOK_AUTH || 'Bearer secret'
          }
        }
      }
    }
  };

  // Execution hook
  const executionHook = {
    uuid: 'passkey-dao-execution',
    name: 'Proposal Executed',
    version: 1,
    chains: ['stacks'],
    networks: {
      testnet: {
        'if_this': {
          scope: 'print_event',
          contract_identifier: PROPOSAL_CONTRACT,
          contains: 'Execution'
        },
        'then_that': {
          http_post: {
            url: process.env.WEBHOOK_URL || 'http://localhost:3000/events/execution',
            authorization_header: process.env.WEBHOOK_AUTH || 'Bearer secret'
          }
        }
      }
    }
  };

  // Treasury operations (deposits/transfers)
  const treasuryOperationHook = {
    uuid: 'passkey-dao-treasury-operation',
    name: 'Treasury Operation',
    version: 1,
    chains: ['stacks'],
    networks: {
      testnet: {
        'if_this': {
          scope: 'stx_event',
          actions: ['transfer'],
          from: DEPLOYER_ADDRESS,
          to: DEPLOYER_ADDRESS
        },
        'then_that': {
          http_post: {
            url: process.env.WEBHOOK_URL || 'http://localhost:3000/events/treasury-operation',
            authorization_header: process.env.WEBHOOK_AUTH || 'Bearer secret'
          }
        }
      }
    }
  };

  // Passkey authentication hook
  const passkeyAuthHook = {
    uuid: 'passkey-dao-auth',
    name: 'Passkey Authentication',
    version: 1,
    chains: ['stacks'],
    networks: {
      testnet: {
        'if_this': {
          scope: 'contract_call',
          contract_identifier: TREASURY_CONTRACT,
          method: 'approve-proposal'
        },
        'then_that': {
          http_post: {
            url: process.env.WEBHOOK_URL || 'http://localhost:3000/events/passkey-auth',
            authorization_header: process.env.WEBHOOK_AUTH || 'Bearer secret'
          }
        }
      }
    }
  };

  // Signer management hook
  const signerManagementHook = {
    uuid: 'passkey-dao-signer-management',
    name: 'Signer Management',
    version: 1,
    chains: ['stacks'],
    networks: {
      testnet: {
        'if_this': {
          scope: 'print_event',
          contract_identifier: SIGNER_CONTRACT,
          contains: 'signer'
        },
        'then_that': {
          http_post: {
            url: process.env.WEBHOOK_URL || 'http://localhost:3000/events/signer-management',
            authorization_header: process.env.WEBHOOK_AUTH || 'Bearer secret'
          }
        }
      }
    }
  };

  try {
    await chainhook.createPredicate(proposalCreatedHook);
    console.log('Registered: Proposal Created hook');

    await chainhook.createPredicate(proposalApprovedHook);
    console.log('Registered: Proposal Approved hook');

    await chainhook.createPredicate(executionHook);
    console.log('Registered: Execution hook');

    await chainhook.createPredicate(treasuryOperationHook);
    console.log('Registered: Treasury Operation hook');

    await chainhook.createPredicate(passkeyAuthHook);
    console.log('Registered: Passkey Authentication hook');

    await chainhook.createPredicate(signerManagementHook);
    console.log('Registered: Signer Management hook');

    console.log('\nAll hooks registered successfully!');
  } catch (error) {
    console.error('Error registering hooks:', error);
  }
}

// Event handler example
function handleEvent(event) {
  console.log('Received event:', JSON.stringify(event, null, 2));

  switch(event.type) {
    case 'proposal-created':
      console.log(`New proposal created: ${event.data.proposalId}`);
      break;
    case 'proposal-approved':
      console.log(`Proposal approved by signer: ${event.data.signerId}`);
      break;
    case 'execution':
      console.log(`Proposal executed: ${event.data.proposalId}`);
      break;
    case 'treasury-operation':
      console.log(`Treasury operation: ${event.data.amount} STX`);
      break;
    case 'passkey-auth':
      console.log(`Passkey authentication for signer: ${event.data.signerId}`);
      break;
    case 'signer-management':
      console.log(`Signer management event: ${event.data.action}`);
      break;
    default:
      console.log('Unknown event type');
  }
}

// Start monitoring
monitorTreasuryEvents().catch(console.error);

module.exports = { handleEvent };

import { Clarinet, Tx, Chain, Account, types } from 'https://deno.land/x/clarinet@v1.7.1/index.ts';
import { assertEquals, assertExists } from 'https://deno.land/std@0.170.0/testing/asserts.ts';

// Sample passkey public key components (32 bytes each)
const SAMPLE_PUBKEY_X = '0x0000000000000000000000000000000000000000000000000000000000000001';
const SAMPLE_PUBKEY_Y = '0x0000000000000000000000000000000000000000000000000000000000000002';

Clarinet.test({
    name: "Can add initial signer",
    async fn(chain: Chain, accounts: Map<string, Account>) {
        const deployer = accounts.get('deployer')!;
        
        let block = chain.mineBlock([
            Tx.contractCall('treasury-manager', 'add-initial-signer', [
                types.buff(Buffer.alloc(32, 1)),
                types.buff(Buffer.alloc(32, 2)),
                types.ascii("Alice")
            ], deployer.address)
        ]);
        
        block.receipts[0].result.expectOk().expectUint(1);
    }
});

Clarinet.test({
    name: "Only owner can add initial signers",
    async fn(chain: Chain, accounts: Map<string, Account>) {
        const user = accounts.get('wallet_1')!;
        
        let block = chain.mineBlock([
            Tx.contractCall('treasury-manager', 'add-initial-signer', [
                types.buff(Buffer.alloc(32, 1)),
                types.buff(Buffer.alloc(32, 2)),
                types.ascii("Hacker")
            ], user.address)
        ]);
        
        block.receipts[0].result.expectErr().expectUint(17001); // ERR_NOT_AUTHORIZED
    }
});

Clarinet.test({
    name: "Get treasury balance",
    async fn(chain: Chain, accounts: Map<string, Account>) {
        const user = accounts.get('wallet_1')!;
        
        let balance = chain.callReadOnlyFn(
            'treasury-manager',
            'get-treasury-balance',
            [],
            user.address
        );
        
        assertEquals(balance.result, 'u0');
    }
});

Clarinet.test({
    name: "Can deposit to treasury",
    async fn(chain: Chain, accounts: Map<string, Account>) {
        const depositor = accounts.get('wallet_1')!;
        
        let block = chain.mineBlock([
            Tx.contractCall('treasury-manager', 'deposit', [
                types.uint(100000000) // 100 STX
            ], depositor.address)
        ]);
        
        block.receipts[0].result.expectOk().expectBool(true);
    }
});

Clarinet.test({
    name: "Get treasury stats",
    async fn(chain: Chain, accounts: Map<string, Account>) {
        const user = accounts.get('wallet_1')!;
        
        let stats = chain.callReadOnlyFn(
            'treasury-manager',
            'get-treasury-stats',
            [],
            user.address
        );
        
        const data = stats.result.expectTuple();
        assertEquals(data['total-proposals'], types.uint(0));
        assertEquals(data['signer-count'], types.uint(0));
        assertEquals(data['threshold'], types.uint(2));
    }
});

Clarinet.test({
    name: "Can set approval threshold",
    async fn(chain: Chain, accounts: Map<string, Account>) {
        const deployer = accounts.get('deployer')!;
        
        // First add signers
        chain.mineBlock([
            Tx.contractCall('treasury-manager', 'add-initial-signer', [
                types.buff(Buffer.alloc(32, 1)),
                types.buff(Buffer.alloc(32, 2)),
                types.ascii("Alice")
            ], deployer.address),
            Tx.contractCall('treasury-manager', 'add-initial-signer', [
                types.buff(Buffer.alloc(32, 3)),
                types.buff(Buffer.alloc(32, 4)),
                types.ascii("Bob")
            ], deployer.address),
            Tx.contractCall('treasury-manager', 'add-initial-signer', [
                types.buff(Buffer.alloc(32, 5)),
                types.buff(Buffer.alloc(32, 6)),
                types.ascii("Charlie")
            ], deployer.address)
        ]);
        
        // Set threshold
        let block = chain.mineBlock([
            Tx.contractCall('treasury-manager', 'set-threshold', [
                types.uint(2)
            ], deployer.address)
        ]);
        
        block.receipts[0].result.expectOk().expectBool(true);
    }
});

Clarinet.test({
    name: "Threshold cannot exceed signer count",
    async fn(chain: Chain, accounts: Map<string, Account>) {
        const deployer = accounts.get('deployer')!;
        
        // Try to set threshold higher than signer count (0)
        let block = chain.mineBlock([
            Tx.contractCall('treasury-manager', 'set-threshold', [
                types.uint(5)
            ], deployer.address)
        ]);
        
        block.receipts[0].result.expectErr().expectUint(17001); // ERR_NOT_AUTHORIZED
    }
});

Clarinet.test({
    name: "Get signer nonce",
    async fn(chain: Chain, accounts: Map<string, Account>) {
        const deployer = accounts.get('deployer')!;
        
        // Add signer
        chain.mineBlock([
            Tx.contractCall('treasury-manager', 'add-initial-signer', [
                types.buff(Buffer.alloc(32, 1)),
                types.buff(Buffer.alloc(32, 2)),
                types.ascii("Alice")
            ], deployer.address)
        ]);
        
        let nonce = chain.callReadOnlyFn(
            'treasury-manager',
            'get-signer-nonce',
            [types.uint(1)],
            deployer.address
        );
        
        assertEquals(nonce.result, 'u0');
    }
});

// Proposal Engine Tests

Clarinet.test({
    name: "Can verify target contract",
    async fn(chain: Chain, accounts: Map<string, Account>) {
        const deployer = accounts.get('deployer')!;
        
        let block = chain.mineBlock([
            Tx.contractCall('proposal-engine', 'verify-target', [
                types.principal(`${deployer.address}.signer-registry`),
                types.ascii("Signer Registry")
            ], deployer.address)
        ]);
        
        block.receipts[0].result.expectOk().expectBool(true);
    }
});

Clarinet.test({
    name: "Can check if target is verified",
    async fn(chain: Chain, accounts: Map<string, Account>) {
        const deployer = accounts.get('deployer')!;
        
        // Verify target first
        chain.mineBlock([
            Tx.contractCall('proposal-engine', 'verify-target', [
                types.principal(`${deployer.address}.signer-registry`),
                types.ascii("Signer Registry")
            ], deployer.address)
        ]);
        
        let isVerified = chain.callReadOnlyFn(
            'proposal-engine',
            'is-target-verified',
            [types.principal(`${deployer.address}.signer-registry`)],
            deployer.address
        );
        
        isVerified.result.expectBool(true);
    }
});

// Signer Registry Tests

Clarinet.test({
    name: "Can register signer profile",
    async fn(chain: Chain, accounts: Map<string, Account>) {
        const deployer = accounts.get('deployer')!;
        
        let block = chain.mineBlock([
            Tx.contractCall('signer-registry', 'register-signer', [
                types.buff(Buffer.alloc(32, 1)),
                types.ascii("Alice"),
                types.none()
            ], deployer.address)
        ]);
        
        block.receipts[0].result.expectOk().expectUint(1);
    }
});

Clarinet.test({
    name: "New signer has default reputation",
    async fn(chain: Chain, accounts: Map<string, Account>) {
        const deployer = accounts.get('deployer')!;
        
        // Register signer
        chain.mineBlock([
            Tx.contractCall('signer-registry', 'register-signer', [
                types.buff(Buffer.alloc(32, 1)),
                types.ascii("Alice"),
                types.none()
            ], deployer.address)
        ]);
        
        let reputation = chain.callReadOnlyFn(
            'signer-registry',
            'calculate-reputation',
            [types.uint(1)],
            deployer.address
        );
        
        // New signer with 0 activity should have 0 reputation
        assertEquals(reputation.result, 'u0');
    }
});

Clarinet.test({
    name: "Can record signer activity",
    async fn(chain: Chain, accounts: Map<string, Account>) {
        const deployer = accounts.get('deployer')!;
        
        // Register signer
        chain.mineBlock([
            Tx.contractCall('signer-registry', 'register-signer', [
                types.buff(Buffer.alloc(32, 1)),
                types.ascii("Alice"),
                types.none()
            ], deployer.address)
        ]);
        
        // Record activity
        let block = chain.mineBlock([
            Tx.contractCall('signer-registry', 'record-activity', [
                types.uint(1),
                types.ascii("approval"),
                types.some(types.uint(1)),
                types.none()
            ], deployer.address)
        ]);
        
        block.receipts[0].result.expectOk().expectUint(0);
    }
});

Clarinet.test({
    name: "Get registry stats",
    async fn(chain: Chain, accounts: Map<string, Account>) {
        const user = accounts.get('wallet_1')!;
        
        let stats = chain.callReadOnlyFn(
            'signer-registry',
            'get-registry-stats',
            [],
            user.address
        );
        
        const data = stats.result.expectTuple();
        assertEquals(data['total-signers'], types.uint(0));
        assertEquals(data['active-signers'], types.uint(0));
    }
});

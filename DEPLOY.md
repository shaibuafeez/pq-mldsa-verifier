# Deploying

Full ML-DSA-65 verification is ~163M gas — above Ethereum L1's block gas limit —
so deploy to an **L2** (Base, Arbitrum, Optimism) or any high-gas-limit chain.

> Unaudited. Use testnets, or get a security review before mainnet value.

## 1. Get a funded key + a testnet faucet

- Create/choose a deployer key. **Never commit it.**
- Fund it on the target testnet. Base Sepolia faucet:
  https://docs.base.org/docs/tools/network-faucets

## 2. Deploy (Base Sepolia example)

```bash
export PRIVATE_KEY=0x<your funded key>
export BASESCAN_API_KEY=<optional, for verification>

forge script script/Deploy.s.sol \
  --rpc-url https://sepolia.base.org \
  --broadcast \
  --verify --verifier-url https://api-sepolia.basescan.org/api \
  --etherscan-api-key "$BASESCAN_API_KEY"
```

Other chains: swap `--rpc-url` (e.g. `https://sepolia-rollup.arbitrum.io/rpc`)
and the verifier URL.

The script prints the deployed `MLDSAVerifier` and `MLDSAOptimistic` addresses.

## 3. Use it

```solidity
import {IMLDSAVerifier} from "pq-mldsa-verifier/interfaces/IMLDSAVerifier.sol";

bool ok = IMLDSAVerifier(VERIFIER_ADDRESS).verify(publicKey, messageHash, signature);
```

Or, for a post-quantum smart wallet, point the upstream module at it:
`new PQValidatorModule(VERIFIER_ADDRESS)` — see
`test/integration/PQWalletIntegration.t.sol`.

## Free option (no deploy, no gas)

`verify()` is a pure read. To check a signature off-chain without deploying,
call it via `eth_call` against any node — it runs locally for free.

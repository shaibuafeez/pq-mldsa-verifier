# Live deployments

## Base Sepolia (chain id 84532)

| Contract | Address |
|----------|---------|
| `MLDSAVerifier` | [`0xe42C6eF5b71834930faC33780bE730F7112a3a6B`](https://sepolia.basescan.org/address/0xe42C6eF5b71834930faC33780bE730F7112a3a6B) |
| `DemoConsumer` | [`0x96743554BEAf53FfAd4C802F0481f9a4864EE1fB`](https://sepolia.basescan.org/address/0x96743554BEAf53FfAd4C802F0481f9a4864EE1fB) |

Deployment transactions:
- MLDSAVerifier: [`0x0bf6ea8f…2b29d7`](https://sepolia.basescan.org/tx/0x0bf6ea8f60405f34677a26ed21780da53a87a6a37892677c1cd50f1cbe2b29d7)
- DemoConsumer: [`0x23f7ab0f…f24b36`](https://sepolia.basescan.org/tx/0x23f7ab0fa637588e06ac4a0f917382ce7158d9acacd109de8aa5a8bbe2f24b36)

### Verified live, on the deployed bytecode

```
cast call 0xe42C6eF5b71834930faC33780bE730F7112a3a6B \
  "verify(bytes,bytes32,bytes)(bool)" \
  $(cat test/vectors/pk.hex) \
  0x9e4f18281574b474df452cbac5b93cba6a36544a4b4f7c385ac3a928c66a4c84 \
  $(cat test/vectors/sig.hex) \
  --rpc-url https://sepolia.base.org
# -> true   (real @noble ML-DSA-65 signature)

# wrong message -> false
```

The full ML-DSA-65 verification (~163M gas) executed on-chain bytecode via
`eth_call` and returned the correct result for both the valid signature and a
wrong message.

### Real-world finding: per-transaction gas cap

The verifier **deploys** fine and **verifies** correctly via `eth_call`. However,
running the full verification as a **state-changing transaction** was rejected by
the Base Sepolia sequencer:

```
error code -32000: exceeds max transaction gas limit
```

The chain's *block* gas limit is 1.2B, but there is a lower per-*transaction*
cap below ~163M. So on this chain, full verification is usable read-only
(`eth_call`) but not as a single on-chain transaction — which is exactly the
motivation for the optimistic path (submit ~200K, dispute one step at a time).
Chains with a higher per-tx cap can run the full verify in a transaction.

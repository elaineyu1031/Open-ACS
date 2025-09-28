# Architecture Documentation

## Overview

The AI Authentication Toolkit is designed as a layered architecture with clear separation between cryptographic primitives, key management, and service logic.

## System Architecture

```
┌─────────────────────────────────────────────────────────┐
│                   Application Layer                      │
│  (Your Application Using Anonymous Authentication)      │
└────────────────────┬────────────────────────────────────┘
                     │
┌────────────────────▼────────────────────────────────────┐
│                  Service Layer                           │
│  ┌──────────────────────┐  ┌──────────────────────────┐ │
│  │  Client Library      │  │  Server Handler          │ │
│  │  - Token Management  │  │  - Request Processing    │ │
│  │  - Protocol Logic    │  │  - Key Management        │ │
│  │  - Verification      │  │  - Signing Logic         │ │
│  └──────────────────────┘  └──────────────────────────┘ │
└────────────────────┬────────────────────────────────────┘
                     │
┌────────────────────▼────────────────────────────────────┐
│              Cryptographic Core                          │
│  ┌────────────┐ ┌──────────┐ ┌─────────┐ ┌───────────┐ │
│  │   VOPRF    │ │   KDF    │ │  Curve  │ │ DLEQProof │ │
│  └────────────┘ └──────────┘ └─────────┘ └───────────┘ │
└────────────────────┬────────────────────────────────────┘
                     │
┌────────────────────▼────────────────────────────────────┐
│                 libsodium                                │
│  (Low-level Crypto Primitives)                          │
└─────────────────────────────────────────────────────────┘
```

## Component Details

### 1. Curve Abstraction (`src/crypto/curve/`)

Provides a unified interface for elliptic curve operations.

#### Interface (`curve.h`)

```c
typedef struct curve {
    size_t scalar_bytes;   // Size of scalars
    size_t element_bytes;  // Size of curve elements
    
    // Generate random scalar
    void (*scalar_random)(unsigned char* out, size_t len);
    
    // Scalar operations
    int (*scalar_add)(unsigned char* out, ...);
    int (*scalar_sub)(unsigned char* out, ...);
    int (*scalar_mul)(unsigned char* out, ...);
    int (*scalar_invert)(unsigned char* out, ...);
    
    // Element operations
    int (*element_add)(unsigned char* out, ...);
    int (*element_scalarmult)(unsigned char* out, ...);
    int (*element_hash_to_group)(unsigned char* out, ...);
} curve_t;
```

#### Implementations

**Ed25519** (`curve_ed25519.*`)
- Based on Curve25519
- High performance
- Wide adoption
- 32-byte scalars and elements

**Ristretto255** (`curve_ristretto.*`)
- Prime-order group over Curve25519
- No cofactor issues
- Better for advanced protocols
- 32-byte scalars and elements

### 2. VOPRF (Verifiable Oblivious PRF) (`src/crypto/voprf/`)

Implements the core blind signature protocol.

#### Base Protocol (`voprf_twohashdh.*`)

Uses the "Two-Hash Diffie-Hellman" construction:
- `PRF(k, x) = H(x, H(x)^k)`
- Verifiable via DLEQ proofs
- Base for both blinding modes

#### Blinding Modes

**Multiplicative Blinding** (`voprf_mul_twohashdh.*`)
```
Client: blind(x) = H(x) * r
Server: eval(blind) = blind^k = H(x)^k * r^k
Client: unblind(eval) = eval / r^k = H(x)^k
```
- Slightly faster
- Requires modular inversion
- Default choice

**Exponential Blinding** (`voprf_exp_twohashdh.*`)
```
Client: blind(x) = H(x)^r
Server: eval(blind) = blind^k = H(x)^(rk)
Client: unblind(eval) = eval^(1/r) = H(x)^k
```
- No inversion needed
- Slightly slower
- Alternative option

#### VOPRF Flow

```
┌────────┐                           ┌────────┐
│ Client │                           │ Server │
└───┬────┘                           └───┬────┘
    │                                    │
    │ 1. Generate token t               │
    │    Generate random r              │
    │                                    │
    │ 2. Blind: M = H(t) * r            │
    │                                    │
    │ 3. Send M                          │
    │───────────────────────────────────▶│
    │                                    │
    │                        4. Sign: Z = M^k
    │                           Generate proof (c, s)
    │                                    │
    │ 5. Return (Z, c, s)                │
    │◀───────────────────────────────────│
    │                                    │
    │ 6. Verify proof                    │
    │    Unblind: N = Z / r^k            │
    │    Finalize: S = H(t, N)           │
    │                                    │
    │ 7. Redeem: (t, S)                  │
    │───────────────────────────────────▶│
    │                                    │
    │                     8. Compute: N' = H(t)^k
    │                        S' = H(t, N')
    │                        Check: S == S'
    │                                    │
    │ 9. Success/Failure                 │
    │◀───────────────────────────────────│
    │                                    │
```

### 3. Key Derivation Functions (`src/crypto/kdf/`)

Enables attribute-based key generation.

#### Interface (`kdf.h`)

```c
typedef struct kdf {
    curve_t* curve;
    
    // Initialize with master secret
    int (*setup)(kdf_t* kdf, 
                 const unsigned char* master_secret,
                 size_t master_secret_len);
    
    // Derive key pair from attributes
    int (*derive_key_pair)(kdf_t* kdf,
                          unsigned char* sk,
                          size_t sk_len,
                          unsigned char* pk,
                          size_t pk_len,
                          unsigned char* pk_proof,
                          size_t pk_proof_len,
                          const unsigned char** attributes,
                          size_t num_attributes);
} kdf_t;
```

#### Implementations

**SDHI KDF** (`kdf_sdhi.*`)
- Secure Deterministic Hierarchical Instantiation
- Hierarchical key derivation
- Efficient for tree structures
- **Recommended for production**

**Naor-Reingold** (`kdf_naor_reingold.*`)
- Based on Naor-Reingold PRF
- Provable security properties
- Research-oriented

**Default KDF** (`kdf_default.*`)
- Simple hash-based derivation
- General-purpose use
- Suitable for simple cases

#### Key Derivation Flow

```
Master Secret (32 bytes)
       │
       ├─▶ Hash(master_secret || attr1 || attr2 || ...)
       │          │
       │          ├─▶ Derive Scalar (sk)
       │          └─▶ Derive Element: pk = G^sk
       │
       └─▶ Generate DLEQ Proof: Prove(sk, G, pk, master_pk)
```

### 4. DLEQ Proofs (`src/crypto/dleqproof/`)

Proves that two discrete logarithms are equal without revealing them.

#### Construction

Proves: `log_G(Y) = log_H(Z)` (i.e., `Y = G^x` and `Z = H^x` for the same `x`)

**Schnorr-based Non-Interactive Proof:**

```
1. Prover knows: x such that Y = G^x and Z = H^x
2. Generate random r
3. Compute: A = G^r, B = H^r
4. Challenge: c = H(G, H, Y, Z, A, B)  [Fiat-Shamir]
5. Response: s = r + c*x
6. Proof: (c, s)

Verification:
1. Recompute: A' = G^s / Y^c
2. Recompute: B' = H^s / Z^c
3. Check: c == H(G, H, Y, Z, A', B')
```

#### Use Cases

- **Public Key Verification**: Prove derived key is correct
- **Signature Verification**: Prove evaluated token is correctly signed
- **Key Rotation**: Prove new key corresponds to old key

### 5. Service Layer (`src/service/`)

#### Server Handler (`SimpleAnonCredServiceHandler.*`)

**State Management:**
```cpp
class SimpleAnonCredServiceHandler {
private:
    curve_t curve_;              // Curve operations
    voprf_t voprf_;              // VOPRF protocol
    kdf_t kdf_;                  // Key derivation
    vector<unsigned char> primaryKey_;  // Master public key
    
    // Derive key pair for attributes
    void deriveKeyPair(vector<unsigned char>& sk,
                      vector<unsigned char>& pk,
                      vector<unsigned char>& pkProof,
                      const vector<string>& attributes);
};
```

**Request Handlers:**

1. `getPrimaryPublicKey()`: Return master public key
2. `getPublicKeyAndProof()`: Derive and return attribute-specific key
3. `signCredential()`: Sign blinded token, return signature + proof
4. `redeemCredential()`: Verify token and shared secret

#### Client Library (`SimpleAnonCredClient.*`)

**State Management:**
```cpp
class SimpleAnonCredClient {
private:
    curve_t curve_;
    voprf_t voprf_;
    kdf_t kdf_;
    SimpleAnonCredServiceClient thriftClient_;
    
public:
    vector<unsigned char> primaryPublicKey;
    vector<unsigned char> publicKey;
    vector<unsigned char> unBlindedElement;
};
```

**Protocol Methods:**

1. `getPrimaryPublicKey()`: Fetch and store master key
2. `getPublicKey()`: Get attribute-specific key and verify
3. `getCredential()`: Blind, sign, unblind, verify
4. `redeemCredential()`: Finalize and redeem token

## Security Architecture

### Threat Model

**Attacker Goals:**
- Link token issuance to redemption
- Forge valid tokens without issuance
- Extract secret keys from observations
- Compromise unlinkability

**Protections:**
1. **Blindness**: Server cannot see actual tokens
2. **Unlinkability**: No correlation between issuance/redemption
3. **Unforgeability**: VOPRF security prevents forgery
4. **Verifiability**: DLEQ proofs ensure correctness

### Key Management

```
┌─────────────────────────────────────────┐
│          Master Secret Key              │
│         (Stored in HSM/KMS)             │
└──────────────┬──────────────────────────┘
               │
      ┌────────▼────────┐
      │   KDF.setup()   │
      └────────┬────────┘
               │
      ┌────────▼──────────────────────┐
      │  Derive Keys per Attributes   │
      │  (Ephemeral, not stored)      │
      └───────────────────────────────┘
```

**Best Practices:**
- Master key never leaves HSM/KMS
- Attribute keys derived on-demand
- Regular master key rotation
- Audit all key derivations

### Network Security

```
┌────────┐      TLS 1.3       ┌────────┐
│ Client │◀──────────────────▶│ Server │
└────────┘   mTLS Optional    └────────┘
```

**Requirements:**
- TLS 1.3 for all communications
- Certificate pinning recommended
- Mutual TLS for high-security deployments
- Rate limiting at network layer

## Performance Considerations

### Bottlenecks

1. **Cryptographic Operations**: 70% of latency
   - Curve operations (scalar mult, hash-to-group)
   - Proof generation/verification
   
2. **Network I/O**: 20% of latency
   - Round trips for each protocol step
   - Serialization overhead
   
3. **Key Derivation**: 10% of latency
   - Can be cached for hot attributes

### Optimization Strategies

#### 1. Batching

Process multiple requests in parallel:
```cpp
// Bad: Sequential processing
for (auto& request : requests) {
    processRequest(request);
}

// Good: Parallel processing
#pragma omp parallel for
for (size_t i = 0; i < requests.size(); ++i) {
    processRequest(requests[i]);
}
```

#### 2. Key Caching

Cache frequently used derived keys:
```cpp
class KeyCache {
    unordered_map<string, CachedKey> cache_;
    
    CachedKey get(const vector<string>& attrs) {
        string key = hashAttributes(attrs);
        if (cache_.count(key)) {
            return cache_[key];
        }
        auto derived = deriveKey(attrs);
        cache_[key] = derived;
        return derived;
    }
};
```

#### 3. Connection Pooling

Reuse Thrift connections:
```cpp
class ConnectionPool {
    queue<shared_ptr<TTransport>> pool_;
    
    auto getConnection() {
        if (!pool_.empty()) {
            auto conn = pool_.front();
            pool_.pop();
            return conn;
        }
        return createNewConnection();
    }
    
    void returnConnection(shared_ptr<TTransport> conn) {
        pool_.push(conn);
    }
};
```

## Scalability

### Horizontal Scaling

```
                    Load Balancer
                         │
          ┌──────────────┼──────────────┐
          │              │              │
    ┌─────▼─────┐  ┌────▼─────┐  ┌────▼─────┐
    │ Server 1  │  │ Server 2 │  │ Server 3 │
    └───────────┘  └──────────┘  └──────────┘
          │              │              │
          └──────────────┼──────────────┘
                         │
                  Shared State
             (Double-spend Prevention)
```

**Considerations:**
- Stateless service design
- Shared double-spend database
- Consistent master keys across instances
- Session affinity not required

### Vertical Scaling

**CPU-bound**: Cryptographic operations benefit from:
- More cores (parallel processing)
- Modern CPU instructions (AES-NI, AVX)
- Hardware crypto accelerators

**Memory**: Minimal requirements (~100MB base + caches)

## Deployment Patterns

### Pattern 1: Sidecar

```
┌─────────────────────────────┐
│     Application Pod         │
│  ┌──────────┐ ┌──────────┐ │
│  │   App    │ │  ACS     │ │
│  │ Container│◀│ Sidecar  │ │
│  └──────────┘ └──────────┘ │
└─────────────────────────────┘
```

**Pros:**
- Low latency (localhost)
- Simple integration
- Independent scaling

**Cons:**
- Resource overhead per pod
- Duplicate caches

### Pattern 2: Dedicated Service

```
┌──────────┐      ┌────────────────┐
│   App    │─────▶│  ACS Service   │
│ Instance │      │   (Dedicated)  │
└──────────┘      └────────────────┘
```

**Pros:**
- Centralized management
- Shared caches
- Better resource utilization

**Cons:**
- Network hop latency
- Single point of failure (mitigated by HA)

### Pattern 3: Library Integration

```
┌─────────────────────────────┐
│     Application             │
│  ┌──────────────────────┐   │
│  │  ACS Library         │   │
│  │  (Linked directly)   │   │
│  └──────────────────────┘   │
└─────────────────────────────┘
```

**Pros:**
- Minimal latency
- No network overhead
- Maximum flexibility

**Cons:**
- Language binding required
- Harder to update independently
- More complex integration

## Monitoring & Observability

### Key Metrics

**Performance:**
- Request latency (p50, p95, p99)
- Throughput (requests/second)
- CPU and memory usage

**Security:**
- Failed verification attempts
- Double-spend attempts
- Rate limit violations

**Business:**
- Tokens issued per time period
- Tokens redeemed per time period
- Token expiry rate

### Logging

```
INFO: Token issuance - attributes: ["app:mobile", "date:2024-01"]
INFO: Token redemption - valid: true, latency: 45ms
WARN: Verification failed - proof mismatch
ERROR: Double-spend attempt detected - token_hash: abc123...
```

## Future Enhancements

### Roadmap

1. **Post-Quantum Cryptography**
   - Lattice-based signatures
   - Isogeny-based VOPRFs
   
2. **Advanced Features**
   - Batch issuance/redemption
   - Threshold signatures
   - Distributed key generation
   
3. **Performance**
   - GPU acceleration
   - Precomputation tables
   - Hardware security module integration
   
4. **Developer Experience**
   - Language bindings (Python, JavaScript, Go, Rust)
   - Cloud-native integrations (AWS, GCP, Azure)
   - Kubernetes operators

## References

- [VOPRF IETF Specification](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-voprf)
- [Ristretto Group](https://ristretto.group/)
- [Privacy Pass Protocol](https://privacypass.github.io/)
- [Anonymous Credentials from Bilinear Pairings](https://eprint.iacr.org/2008/136.pdf)
- [Oblivious Pseudorandom Functions](https://eprint.iacr.org/2014/650.pdf)

---

**Disclaimer**: This is an independent open-source project and is not affiliated with any organization. It implements standard cryptographic protocols based on public research and IETF specifications.


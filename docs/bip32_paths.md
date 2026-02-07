# BIP-32 Derivation Paths

The VTA derives all cryptographic keys from a single BIP-39 mnemonic seed using
[BIP-32](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki)
hierarchical deterministic derivation. All paths live under the `m/26'` purpose
level, which is reserved for the First Person Network.

## Path Hierarchy

```
m/26'
  |
  +-- 0'/N'          VTA keys
  |
  +-- 1'/N'          Admin keys
  |
  +-- 2'             External applications (reserved)
       |
       +-- 1'/N'     DIDComm Messaging Mediator keys
       |
       +-- 2'/N'     Trust Registry keys (placeholder)
```

## Path Groups

| Base Path        | Constant              | Purpose                                   |
|------------------|-----------------------|-------------------------------------------|
| `m/26'/0'`       | `VTA_KEY_BASE`        | VTA entity: signing, key-agreement, pre-rotation |
| `m/26'/1'`       | `ADMIN_KEY_BASE`      | Admin: signing, key-agreement, did:key     |
| `m/26'/2'`       | `EXTERNAL_APP_BASE`   | External applications (reserved)           |
| `m/26'/2'/1'`    | `MEDIATOR_KEY_BASE`   | DIDComm Messaging Mediator                 |
| `m/26'/2'/2'`    | `TRUST_REGISTRY_KEY_BASE` | Trust Registry (placeholder)           |

## Sequential Allocation

Each path group maintains a **persistent counter** stored in the fjall `keys`
keyspace under the key `path_counter:{base}`. Every key allocation:

1. Reads the current counter value `N` (starting at 0)
2. Derives the key at `{base}/{N}'`
3. Stores the key record
4. Increments the counter to `N + 1`

All key types within a group (signing, key-agreement, pre-rotation) share
**one counter**, so indices are unique and never reused.

```
allocate_path(keys_ks, "m/26'/0'")   ->  m/26'/0'/0'   (counter: 0 -> 1)
allocate_path(keys_ks, "m/26'/0'")   ->  m/26'/0'/1'   (counter: 1 -> 2)
allocate_path(keys_ks, "m/26'/0'")   ->  m/26'/0'/2'   (counter: 2 -> 3)
```

## Typical Setup Allocation

During the setup wizard, keys are allocated in the order they are created. A
typical run produces the following layout:

### VTA keys (`m/26'/0'/N'`)

| Index | Key Type | Label                      |
|-------|----------|----------------------------|
| 0     | Ed25519  | VTA signing key            |
| 1     | X25519   | VTA key-agreement key      |
| 2+    | Ed25519  | VTA pre-rotation key 0, 1, ... |

### Mediator keys (`m/26'/2'/1'/N'`)

| Index | Key Type | Label                          |
|-------|----------|--------------------------------|
| 0     | Ed25519  | Mediator signing key           |
| 1     | X25519   | Mediator key-agreement key     |
| 2+    | Ed25519  | Mediator pre-rotation key 0, 1, ... |

### Admin keys (`m/26'/1'/N'`)

| Index | Key Type | Label                        |
|-------|----------|------------------------------|
| 0     | Ed25519  | Admin signing key            |
| 1     | X25519   | Admin key-agreement key      |
| 2     | Ed25519  | Admin did:key                |
| 3+    | Ed25519  | Admin pre-rotation key 0, 1, ... |

The exact indices depend on which options are chosen during setup. For example,
if the admin uses `did:key` instead of `did:webvh`, only index 0 is allocated
(the `did:key` derivation).

## Server Startup

At startup the server does **not** assume fixed indices. Instead, it looks up
the VTA signing and key-agreement key paths from the stored `KeyRecord` entries
by matching on label and key type. This means the paths are always consistent
with what the setup wizard actually allocated.

## JWT Signing Key

The JWT signing key is **not** derived from BIP-32. It is a random 32-byte
Ed25519 private key generated during setup and stored as a base64url-no-pad
string in the config file at `auth.jwt_signing_key`. This can also be set via
the `VTA_AUTH_JWT_SIGNING_KEY` environment variable.

## Source

Path constants and allocation logic live in
[`vtc-vta-service/src/keys/paths.rs`](../vtc-vta-service/src/keys/paths.rs).

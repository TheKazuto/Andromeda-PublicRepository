# proto/

Place the Ika `.proto` files here so the gRPC client can load them at boot.

Source: https://github.com/dwallet-labs/ika-pre-alpha/tree/main/proto

```bash
git clone --depth=1 https://github.com/dwallet-labs/ika-pre-alpha /tmp/ika
cp /tmp/ika/proto/*.proto .
```

Without these files, `src/engine/grpc-client.ts` raises a clear error on first
gRPC call.

## Files expected

- `ika_dwallet_service.proto` (or whatever upstream names it)

The exact filename used by `grpc-client.ts` is `ika_dwallet_service.proto`.
Adjust the `PROTO_PATH` constant in that file if upstream uses a different name.

## Pinning

Pre-alpha protos may change between commits. Pin to a specific commit and
record it in `proto/.UPSTREAM_COMMIT` so we can audit drift:

```bash
echo "<commit-sha>" > proto/.UPSTREAM_COMMIT
```

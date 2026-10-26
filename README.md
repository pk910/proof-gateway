# proof-gateway

A public front for EIP-8025 execution proof submissions.

- `POST /eth/v1/beacon/execution_proofs` takes 1–4 `SignedExecutionProofEnvelope`s as JSON
  (`application/json`) or SSZ `List[SignedExecutionProofEnvelope, 4]` (`application/octet-stream`)
  and forwards them to every configured beacon node. A proof counts as accepted once one node
  accepted it; the answer is `200` when every proof was accepted somewhere, otherwise `400` with a
  failure per rejected proof index (`502` when no node answered).
- Each node's `execution_proof` event stream is followed; the most recent proofs are kept on disk
  (`-keep`, default 100) together with the most recent submissions.
- `/` is a landing page with the API description and both lists, `/proofs/{key}.json|.ssz` downloads
  a proof envelope, `/api/proofs` and `/api/submissions` return the lists as JSON.

The beacon nodes need the `execution_proof` event stream topic and the proof submission route,
e.g. Lighthouse with `--proof-engine` (eth-act `optional-proofs` plus the event stream patch).

```
docker run -d --name proof-gateway -p 127.0.0.1:18570:8080 -v /srv/proof-gateway:/data \
  pk910/dev-images:proof-gateway \
  -beacon node1=http://10.16.72.102:5052 -beacon node2=http://10.0.0.2:5052 \
  -network Sepolia -public-url https://proofs-sepolia.pk910.de \
  -explorer-url https://dora.sepolia.ethpandaops.io
```

`GET /eth/v1/beacon/execution_proofs/{block_id}` and `GET /eth/v1/events?topics=execution_proof`,
described on the page, are served by the reverse proxy straight from a beacon node.

# EdgeCDN-X cert-manager webhook

DNS01 solver for the EdgeCDN-X API. Solver name: `edgecdnx`; default API group:
`acme.edgecdnx.com`.

The solver creates Simple TXT DNS endpoints, adds challenge values without
overwriting existing values, and removes only the completed challenge's value.
Repeated Present/CleanUp calls are idempotent. Optimistic version checks and
bounded retries protect simultaneous challenges, including across replicas.

## Requirements

- cert-manager installed in the cluster.
- An EdgeCDN-X Project and an existing Zone serving authoritative DNS.
- An API key scoped to that Project with Zone `read` and `update` permissions.
- An API supporting direct DNS endpoint GET, PATCH `resourceVersion`, DELETE
  `resourceVersion` preconditions, and underscore-containing TXT owner names.
  Restart/redeploy the API after installing these changes.
- Go 1.26 or newer (or automatic Go toolchain downloads) for development.

## Credentials and deployment

The API key is read **only** from `EDGECDNX_API_KEY`. The deployment injects it
using `env.valueFrom.secretKeyRef`; no key is included in Helm values, Issuer
configuration, logs, or committed Secret manifests. The webhook does not need
Kubernetes Secret read permissions.

Create `edgecdnx-api-key` in the webhook namespace, with key `api-key`, using your
secret manager. Alternatively, import an existing local key file (containing
only the API key, no trailing newline) without placing the value on the command
line:

```sh
kubectl -n cert-manager create secret generic edgecdnx-api-key \
  --from-file=api-key=/absolute/path/outside-repository/api-key
```

Build and publish the webhook image to your registry, then install the
[Helm chart](deploy/example-webhook):

```sh
helm upgrade --install edgecdnx-webhook deploy/example-webhook \
  --namespace cert-manager \
  --set image.repository=YOUR_REGISTRY/edgecdnx-cert-manager-webhook \
  --set image.tag=YOUR_TAG \
  --set edgecdnx.apiURL=https://YOUR_API_HOST \
  --set edgecdnx.projectID=YOUR_PROJECT_METADATA_NAME \
  --set edgecdnx.apiKeySecretRef.name=edgecdnx-api-key \
  --set edgecdnx.apiKeySecretRef.key=api-key
```

`EDGECDNX_API_URL` is deployment-wide, not issuer-controlled, so an Issuer cannot
redirect the shared API credential to another server. Requests use
`Authorization: ApiKey <key>`, standard TLS verification, a 10-second HTTP
timeout and a 30-second challenge deadline. Redirects are rejected. Use HTTPS
in production; HTTP is supported for trusted local development. A pod cannot
reach your host API via `localhost`; configure an address reachable from the
cluster.

After Secret rotation, restart the deployment to refresh its environment.
All issuers sharing a deployment use the same key; use separate deployments
and distinct API groups for separately credentialed Projects.

`EDGECDNX_PROJECT_ID` is the only solver setting, configured by
`edgecdnx.projectID` in Helm. Every Present and CleanUp request fetches this
Project's zones from the API before accessing DNS records. The request fails
if discovery fails, no zones exist, or the API returns invalid/duplicate zones.
Challenges are matched by their resolved DNS
name against the most specific covering zone, using DNS label boundaries.
Zone lists are request-local, not cached, so API zone changes are picked up on
the next request without restarting the webhook. The API's zone list is
eventually consistent, so changes may still take time to appear there.
New TXT records use a fixed TTL of 60 seconds.

## Issuer

Merge this solver into an existing Issuer/ClusterIssuer's `spec.acme.solvers`:

```yaml
solvers:
  - dns01:
      webhook:
        groupName: acme.edgecdnx.com
        solverName: edgecdnx
```

No per-Issuer `config` is needed or supported. Remove old `projectID`, `zoneID`,
and `recordTTL` config fields and set the Project on the deployment instead.
DNS names come from cert-manager's resolved challenge, including
CNAME delegation (configure cert-manager's `cnameStrategy: Follow` if needed).
The resolved DNS name must be covered by one of the fetched Project zones.

## Tests

```sh
go test -p 1 .
go vet .
```

Unit tests use the actual solver against an HTTP API fixture with version
preconditions: lifecycle, idempotency, concurrent challenges, conflict retries,
configuration errors, authentication errors and redirects.

To run an opt-in lifecycle smoke test against the locally running API, export
the key from a protected file rather than putting it in shell history:

```sh
export EDGECDNX_API_URL=http://localhost:5555
export EDGECDNX_API_KEY="$(cat /absolute/path/outside-repository/api-key)"
export EDGECDNX_PROJECT_ID=YOUR_PROJECT_METADATA_NAME
# Optional: choose a specific available API zone instead of automatic selection.
# export EDGECDNX_TEST_ZONE=example.com.
EDGECDNX_LIVE_TEST=1 go test -v -count=1 -run '^TestLiveAPI$' .
unset EDGECDNX_API_KEY
```

Without `EDGECDNX_TEST_ZONE`, the test chooses the alphabetically first fetched
zone and prints it. The optional override must match an available API zone's
DNS name. `EDGECDNX_TEST_PROJECT_ID` and `EDGECDNX_TEST_ZONE_ID` are no longer
used; use `EDGECDNX_PROJECT_ID` for both the test and deployment.

This explicitly creates TXT values at `_acme-challenge.webhook-test.<zone>` and
cleans up only its own value. Use a dedicated test Project or set the optional
zone override to a dedicated test zone. This tests API
integration, not authoritative DNS propagation or certificate issuance; those
still require an end-to-end ACME staging test against your served zone.

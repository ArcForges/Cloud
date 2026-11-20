# Hosted commerce configuration

Commerce uses Paddle Billing v1. Configure the notification destination for v1 and point it to
`/api/commerce/v1/paddle/webhook` on the official Center ingress. The Center verifies the
original bytes with the secret for that destination. The Paddle API key and the notification
destination must belong to the same provider account and environment.

The `commerce` surface requires the `identity` surface and `ARCFORGES_CENTER_MODE=official-hosted`.
The self-hosted runtime uses its existing operator policy and has no checkout or payment provider.

Paddle returns a default payment link with the exact transaction ID. The approved payment page
must load Paddle.js to open that transaction. Qualify the page and the browser return flow along
with the provider sandbox before enabling sales.

| Setting                                                                                 | Purpose                                                                                                                                                |
| --------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `ARCFORGES_CENTER_HOSTED_CATALOGUE`                                                     | Versioned, price-free hosted entitlement definitions.                                                                                                  |
| `ARCFORGES_CENTER_COMMERCE_CATALOGUE`                                                   | Versioned merchant offers and explicit `sales_open` flag. Each offer binds the entitlement definitions version and the provider product and price IDs. |
| `ARCFORGES_CENTER_PADDLE_ENVIRONMENT`                                                   | The selected `sandbox` or `live` provider environment. Use a separate database for each.                                                               |
| `ARCFORGES_CENTER_PADDLE_API_KEY`                                                       | Secret for the selected Paddle API account and environment.                                                                                            |
| `ARCFORGES_CENTER_PADDLE_WEBHOOK_SECRET`                                                | Secret for that environment's notification destination.                                                                                                |
| `ARCFORGES_CENTER_PADDLE_PREVIOUS_WEBHOOK_SECRET`                                       | Optional previous destination secret during a rotation. Only set it for the same environment and destination.                                          |
| `ARCFORGES_CENTER_PADDLE_CHECKOUT_ORIGINS` and `ARCFORGES_CENTER_PADDLE_PORTAL_ORIGINS` | Comma-separated approved HTTPS origins for links issued by the provider.                                                                               |

Set `sales_open` to false to pause new sales while retaining reconciliation and subscription
remediation. Treat a missing checkout response as an unresolved attempt and keep its original
purchase identity. Local link expiration does not revoke a link on Paddle. Reconcile an
authoritative late payment on the original attempt before closing it.

Keep provider credentials in deployment secret storage. Provider sandbox qualification and the
owner's commercial configuration and activation approval are part of AR-10 and PROD-01.

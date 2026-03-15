# Google Identity-Aware Proxy (IAP) — API Reference

## Libraries

| Library | Install | Purpose |
|---------|---------|---------|
| google-cloud-iap | `pip install google-cloud-iap` | IAP admin and settings management |
| google-cloud-resource-manager | `pip install google-cloud-resource-manager` | GCP project enumeration |

## Key IAP Client Methods

| Method | Description |
|--------|-------------|
| `IdentityAwareProxyAdminServiceClient()` | Create IAP admin client |
| `get_iap_settings(name=)` | Get IAP configuration for a resource |
| `update_iap_settings(iap_settings=, update_mask=)` | Update IAP settings |
| `get_iam_policy(resource=)` | Get IAP IAM bindings |
| `set_iam_policy(resource=, policy=)` | Set IAP IAM bindings |
| `list_tunnel_dest_groups(parent=)` | List TCP forwarding tunnel groups |

## IAP IAM Roles

| Role | Description |
|------|-------------|
| `roles/iap.httpsResourceAccessor` | Access IAP-protected web resources |
| `roles/iap.tunnelResourceAccessor` | Access IAP TCP forwarding tunnels |
| `roles/iap.admin` | Full IAP administration |

## gcloud CLI Commands

```bash
gcloud iap web enable --resource-type=app-engine
gcloud iap tcp enable --resource-type=compute --dest-group=GROUP
gcloud iap web get-iam-policy --project=PROJECT
gcloud compute ssh INSTANCE --tunnel-through-iap
```

## External References

- [Google IAP Documentation](https://cloud.google.com/iap/docs)
- [google-cloud-iap Python Reference](https://cloud.google.com/python/docs/reference/iap/latest)
- [IAP Programmatic Auth](https://cloud.google.com/iap/docs/authentication-howto)

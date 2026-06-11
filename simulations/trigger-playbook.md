# Trigger playbook

Exact, benign actions to fire each detection. Every action is performed against **my own resources** and reverted immediately. Use the cheapest SKUs and clean up right after.

> **Scheduling lag:** these are *scheduled* analytics rules. After you perform the action, the incident appears on the rule's **next run**, not instantly. Give it the rule's query interval before checking the Incidents queue.

---

## DET-001, Failed Activity Log operations spike

Generate ~10+ authorization failures from one caller within an hour.

**Portal:** sign in as a low-privilege / second account and repeatedly attempt an action you lack rights for (e.g. open a Key Vault you can't read, or try to delete a resource you don't own). Repeat ~10 to 12 times.

**CLI alternative:**
```bash
# run as the low-priv account; each call is denied -> a Failure in AzureActivity
for i in $(seq 1 12); do
  az keyvault secret list --vault-name <vault-you-cannot-read> 2>/dev/null
done
```
**Cleanup:** none needed (no resources created).

---

## DET-002, NSG rule modified

**Portal:** Network security groups → *(existing or a new throwaway NSG)* → **Inbound security rules** → **Add** → e.g. Source `Any`, Destination port `3389`, Action `Allow`, name `sim-rdp-open` → **Save** → then open the rule → **Delete**.

**Cleanup:** delete the rule (done above); delete the throwaway NSG if you created one.

---

## DET-003, RBAC role assignment changes

**Portal:** Subscription (or a resource group) → **Access control (IAM)** → **Add → Add role assignment** → role `Reader` → assign to a user / your second account → **Review + assign** → then **Access control (IAM) → Role assignments**, find it, **Remove**.

**Cleanup:** remove the assignment (done above).

---

## DET-004, Mass resource deletion

**Portal:** create resource group `rg-sim-delete` → add 5 cheap resources (e.g. 5× **Public IP address**, Basic SKU, or 5× empty NSGs) → go to the resource group → select all → **Delete**, or delete the whole resource group.

**Cleanup:** the trigger *is* the cleanup (everything is deleted). Confirm `rg-sim-delete` is gone.

---

## DET-005, Suspicious resource deployment by non-owner

**Portal:** sign in as a **non-owner** principal (Contributor or guest) → create a resource, e.g. a **Storage account** (Standard LRS) named `simnonowner<random>` in a test RG.

**Cleanup:** delete the storage account (and test RG) once the incident is captured. Note: this deletion may also feed DET-004, fine, capture both.

---

## After triggering

1. Wait for the rule's scheduled run.
2. Confirm the incident in **Incidents** (`security.microsoft.com/incidents`).
3. Capture the evidence screenshots (see `screenshots/README.md`).
4. Fill the incident specifics into the matching `detections/DET-00N-*.md` card.

"""Request a short-lived token from an existing Azure CLI sign-in."""

import shutil
import subprocess


def access_token(resource, subscription=None):
    az = shutil.which("az")
    if az is None:
        raise RuntimeError("Azure CLI is required for this operation")
    command = [az, "account", "get-access-token", "--resource", resource,
               "--query", "accessToken", "--output", "tsv"]
    if subscription:
        command += ["--subscription", subscription]
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=60, check=False)
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError("Azure CLI timed out while requesting an access token") from exc
    token = result.stdout.strip()
    if result.returncode or not token:
        raise RuntimeError("Azure CLI did not return an access token. Check the Azure sign-in and permissions.")
    return token

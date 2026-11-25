"""Query the Log Analytics data plane with an explicit workspace customer ID."""

import json
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

LOGS_AUDIENCE = "https://api.loganalytics.io"
LOGS_ENDPOINT = "https://api.loganalytics.azure.com"


class WorkspaceQueryError(RuntimeError):
    def __init__(self, message, *, status="query_error"):
        super().__init__(message)
        self.status = status


def missing_source(error):
    while isinstance(error, dict):
        message = str(error.get("message", "")).lower()
        if error.get("code") == "SEM0100" and "failed to resolve table" in message:
            return True
        error = error.get("innererror")
    return False


def query_rows(workspace, token, query):
    request = Request(
        f"{LOGS_ENDPOINT}/v1/workspaces/{workspace}/query",
        method="POST",
        data=json.dumps({"query": query}).encode("utf-8"),
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {token}"},
    )
    try:
        with urlopen(request, timeout=60) as response:
            payload = json.load(response)
    except HTTPError as exc:
        try:
            error = json.load(exc).get("error")
        except (ValueError, AttributeError):
            error = None
        status = "source_unavailable" if missing_source(error) else "query_error"
        raise WorkspaceQueryError(f"Log Analytics HTTP {exc.code}", status=status) from exc
    except (URLError, OSError, ValueError) as exc:
        raise WorkspaceQueryError("Log Analytics request failed") from exc
    if not isinstance(payload, dict) or payload.get("error"):
        raise WorkspaceQueryError("Log Analytics returned an error or partial response")
    try:
        table = next(table for table in payload["tables"] if table["name"] == "PrimaryResult")
        columns = [column["name"] for column in table["columns"]]
        return [dict(zip(columns, row, strict=True)) for row in table["rows"]]
    except (KeyError, StopIteration, TypeError, ValueError) as exc:
        raise WorkspaceQueryError("Log Analytics returned an unexpected result shape") from exc

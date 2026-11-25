"""Exercise the release boundary without Azure credentials or network calls."""

import copy
import io
import json
import tempfile
import unittest
from argparse import Namespace
from contextlib import redirect_stderr, redirect_stdout
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
from unittest.mock import Mock, patch

import yaml

from detection_rules import CatalogError, load_catalog, validate_rule


def script(name):
    spec = spec_from_file_location(name.replace("-", "_"), Path(__file__).with_name(f"{name}.py"))
    module = module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


deploy = script("deploy-detections")
validate = script("validate-detections")
ONBOARDED = {"properties": {"customerManagedKey": False}}


class ReleaseTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.catalog = load_catalog()

    def test_reject_duplicate_guid_case_insensitively(self):
        rule = self.catalog[0].rule
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            (path / "DET-001-one.yaml").write_text(yaml.safe_dump(rule), encoding="utf-8")
            (path / "DET-002-two.yaml").write_text(yaml.safe_dump({**rule, "id": rule["id"].upper()}),
                                                   encoding="utf-8")
            with self.assertRaisesRegex(CatalogError, "DET-002-two.yaml: duplicate rule GUID"):
                load_catalog(path)

    def test_reject_malformed_catalog_values(self):
        self.assertEqual(validate_rule(["unexpected list"]), ["expected a YAML mapping"])
        rule = copy.deepcopy(self.catalog[0].rule)
        rule.update(queryFrequency="PT2H", queryPeriod="PT15M", triggerThreshold=True)
        errors = validate_rule(rule)
        self.assertIn("queryFrequency must not exceed queryPeriod", errors)
        self.assertIn("triggerThreshold must be a nonnegative integer", errors)

    def test_reject_duplicate_yaml_key_before_it_overrides_reviewed_content(self):
        rule = {**self.catalog[0].rule, "enabled": False}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            (path / "DET-001-duplicate.yaml").write_text(yaml.safe_dump(rule) + "enabled: true\n",
                                                        encoding="utf-8")
            with self.assertRaisesRegex(CatalogError, "duplicate YAML key 'enabled'"):
                load_catalog(path)

    def test_offline_validator_ignores_workspace_environment(self):
        with patch.dict("os.environ", {"SENTINEL_WORKSPACE_GUID": "00000000-0000-0000-0000-000000000001"}):
            with patch.object(validate, "access_token") as auth, redirect_stdout(io.StringIO()):
                self.assertEqual(validate.main([]), 0)
        auth.assert_not_called()

    def test_review_plan_is_repeatable_without_azure(self):
        with tempfile.TemporaryDirectory() as directory:
            paths = [Path(directory) / f"plan{number}.json" for number in (1, 2)]
            with patch.object(deploy, "access_token") as auth:
                for path in paths:
                    self.assertEqual(deploy.main(["plan", "--output", str(path)]), 0)
            self.assertEqual(paths[0].read_bytes(), paths[1].read_bytes())
        auth.assert_not_called()
        selected = deploy.deployment_plan(self.catalog, ["DET-006"])["rules"]
        self.assertEqual([item["detectionId"] for item in selected], ["DET-006"])
        props = selected[0]["body"]["properties"]
        self.assertEqual(props["techniques"], ["T1003"])
        self.assertEqual(props["subTechniques"], ["T1003.001"])

    def test_apply_rejects_missing_target_without_authentication(self):
        with patch.dict("os.environ", {}, clear=True):
            with patch.object(deploy, "access_token") as auth, redirect_stderr(io.StringIO()) as error:
                self.assertEqual(deploy.main(["apply"]), 1)
        auth.assert_not_called()
        self.assertIn("set AZURE_SUBSCRIPTION_ID or --subscription", error.getvalue())

    def test_apply_rejects_unknown_rule_before_authentication(self):
        with patch.object(deploy, "access_token") as auth, redirect_stderr(io.StringIO()) as error:
            self.assertEqual(deploy.main(["apply", "--rule", "DET-9999"]), 1)
        auth.assert_not_called()
        self.assertIn("unknown detection IDs: DET-9999", error.getvalue())

    def test_apply_verifies_accepted_rules_and_stops_on_drift(self):
        plan = deploy.deployment_plan(self.catalog, ["DET-001", "DET-002", "DET-003"])
        args = Namespace(subscription="00000000-0000-0000-0000-000000000001",
                         resource_group="test-rg", workspace="test-ws")
        first, second, _ = plan["rules"]
        drifted = copy.deepcopy(second["body"])
        drifted["properties"]["enabled"] = False
        with (
            patch.object(deploy, "access_token", return_value="test-only-token"),
            patch.object(deploy, "verify_watchlists"),
            redirect_stdout(io.StringIO()),
        ):
            absent = deploy.ArmHttpError("GET", 404)
            responses = [ONBOARDED, absent, absent, absent, None, first["body"], None, drifted]
            with patch.object(deploy, "arm_request", side_effect=responses) as client:
                with self.assertRaisesRegex(RuntimeError, r"DET-002: readback differs on: enabled.*Previously verified: 1"):
                    deploy.apply_plan(plan, args)
        self.assertEqual([call.args[0] for call in client.call_args_list], ["GET"] * 4 + ["PUT", "GET", "PUT", "GET"])
        first_url = client.call_args_list[4].args[1]
        self.assertIn("/resourceGroups/test-rg/providers/Microsoft.OperationalInsights/workspaces/test-ws/", first_url)
        self.assertIn(f"/{first['ruleId']}?api-version=", first_url)

    def test_missing_required_watchlist_blocks_all_writes(self):
        plan = deploy.deployment_plan(self.catalog, ["DET-001", "DET-005"])
        args = Namespace(subscription="00000000-0000-0000-0000-000000000001",
                         resource_group="test-rg", workspace="test-ws")
        missing = deploy.ArmHttpError("GET", 404)
        api = Mock(side_effect=[ONBOARDED, missing, missing, missing])
        with patch.object(deploy, "access_token", return_value="test-only-token"):
            with patch.object(deploy, "arm_request", api):
                with self.assertRaisesRegex(RuntimeError, r"soc-deploy-owners: .*No rules were written"):
                    deploy.apply_plan(plan, args)
        self.assertEqual([call.args[0] for call in api.call_args_list], ["GET"] * 4)
        self.assertIn("/watchlists/soc-deploy-owners?", api.call_args.args[1])

    def test_diff_lists_each_action_and_uses_only_gets(self):
        plan = deploy.deployment_plan(self.catalog, ["DET-001", "DET-002", "DET-003"])
        first, second, _ = plan["rules"]
        drifted = copy.deepcopy(second["body"])
        drifted["properties"]["entityMappings"] = []
        drifted["properties"]["incidentConfiguration"]["groupingConfiguration"]["enabled"] = False
        api = Mock(side_effect=[ONBOARDED, first["body"], drifted, deploy.ArmHttpError("GET", 404)])
        output = io.StringIO()
        with patch.object(deploy, "access_token", return_value="fixture"), patch.object(deploy, "arm_request", api):
            with redirect_stdout(output):
                self.assertEqual(deploy.main([
                    "diff", "--subscription", "00000000-0000-0000-0000-000000000001",
                    "--resource-group", "test-rg", "--workspace", "test-ws",
                    "--rule", "DET-001", "--rule", "DET-002", "--rule", "DET-003",
                ]), 0)
        rules = json.loads(output.getvalue())["rules"]
        self.assertEqual([rule["action"] for rule in rules], ["unchanged", "update", "create"])
        self.assertEqual(rules[1]["differences"], ["entityMappings", "incidentConfiguration.groupingConfiguration"])
        self.assertEqual([call.args[0] for call in api.call_args_list], ["GET"] * 4)

    def test_unchanged_rule_is_not_written(self):
        plan = deploy.deployment_plan(self.catalog, ["DET-001"])
        args = Namespace(subscription="00000000-0000-0000-0000-000000000001",
                         resource_group="test-rg", workspace="test-ws")
        observed = copy.deepcopy(plan["rules"][0]["body"])
        props = observed["properties"]
        props["queryFrequency"] = "PT900S"
        props["query"] = props["query"].replace("\n", "\r\n")
        props["incidentConfiguration"]["groupingConfiguration"].pop("reopenClosedIncident")
        props.pop("subTechniques")
        api = Mock(side_effect=[ONBOARDED, observed])
        with patch.object(deploy, "access_token", return_value="fixture"), patch.object(deploy, "arm_request", api):
            with redirect_stdout(io.StringIO()) as output:
                deploy.apply_plan(plan, args)
        self.assertIn("0 change(s)", output.getvalue())
        self.assertEqual([call.args[0] for call in api.call_args_list], ["GET", "GET"])

    def test_onboarding_404_blocks_any_rule_request(self):
        plan = deploy.deployment_plan(self.catalog, ["DET-001"])
        args = Namespace(subscription="00000000-0000-0000-0000-000000000001",
                         resource_group="test-rg", workspace="test-ws")
        api = Mock(side_effect=deploy.ArmHttpError("GET", 404))
        with patch.object(deploy, "access_token", return_value="fixture"), patch.object(deploy, "arm_request", api):
            with self.assertRaisesRegex(RuntimeError, "Sentinel onboarding was not found"):
                deploy.apply_plan(plan, args)
        self.assertEqual(api.call_count, 1)
        self.assertIn("/onboardingStates/default?", api.call_args.args[1])


if __name__ == "__main__":
    unittest.main()

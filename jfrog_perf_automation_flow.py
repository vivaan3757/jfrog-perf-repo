import uuid

from locust import HttpUser, TaskSet, task, between
import json
import os

# Load from config.json
with open("config.json") as f:
    config = json.load(f)

BASE_URL = config["base_url"]
AUTH_HEADER = {
    "Authorization": f"Bearer {config['token']}",
    "Content-Type": "application/json"
}

class PerfTestTasks(TaskSet):


    @task
    def create_repo(self):
        repo_name = f"perf-docker-{uuid.uuid4().hex[:6]}"
        data = {
            "key": repo_name,
            "projectKey": "",
            "packageType": "docker",
            "rclass": "local",
            "xrayIndex": True
        }
        try:
            with self.client.put(
                    f"/artifactory/api/repositories/{repo_name}",
                    headers=AUTH_HEADER,
                    json=data,
                    name="Create Repo",
                    catch_response=True
            ) as response:
                if response.status_code not in [200, 201]:
                    response.failure(f"Create Repo failed: {response.status_code} {response.text}")
        except Exception as e:
            print(f"Error in create_repo: {e}")


    @task
    def verify_repo(self):
        try:
            with self.client.get(
                    "/artifactory/api/repositories",
                    headers=AUTH_HEADER,
                    name="Verify Repo",
                    catch_response=True
            ) as response:
                if response.status_code != 200:
                    response.failure(f"Failed to verify repo: {response.status_code} {response.text}")
        except Exception as e:
            print(f"Error in verify_repo: {e}")

    @task
    def scan_status(self):
        data = {
            "repo": "perf-test-docker-local",
            "path": "/alpine/3.9/manifest.json"
        }
        try:
            with self.client.post(
                    "/xray/api/v1/artifact/status",
                    headers=AUTH_HEADER,
                    json=data,
                    name="Scan Status",
                    catch_response=True
            ) as response:
                if response.status_code != 200:
                    response.failure(f"Scan Status failed: {response.status_code} {response.text}")
        except Exception as e:
            print(f"Error in scan_status: {e}")

    @task
    def create_policy(self):
        policy_name = f"perf-policy-{uuid.uuid4().hex[:6]}"
        data = {
            "name": policy_name,
            "description": "This is a specific CVEs security policy",
            "type": "security",
            "rules": [
                {
                    "name": "some_rule",
                    "criteria": {
                        "malicious_package": False,
                        "fix_version_dependant": False,
                        "min_severity": "high"
                    },
                    "actions": {
                        "mails": [],
                        "webhooks": [],
                        "fail_build": False,
                        "block_release_bundle_distribution": False,
                        "block_release_bundle_promotion": False,
                        "notify_deployer": False,
                        "notify_watch_recipients": False,
                        "create_ticket_enabled": False,
                        "block_download": {
                            "active": False,
                            "unscanned": False
                        }
                    },
                    "priority": 1
                }
            ]
        }
        try:
            with self.client.post(
                    "/xray/api/v2/policies",
                    headers=AUTH_HEADER,
                    json=data,
                    name="Create Policy",
                    catch_response=True
            ) as response:
                if response.status_code != 201:
                    response.failure(f"Create Policy failed: {response.status_code} {response.text}")
        except Exception as e:
            print(f"Error in create_policy: {e}")

    @task
    def create_watch(self):
        watch_name = f"perf-watch-{uuid.uuid4().hex[:6]}"
        data = {
            "general_data": {
                "name": watch_name,
                "description": "This watch is for the perf test",
                "active": True
            },
            "project_resources": {
                "resources": [
                    {
                        "type": "repository",
                        "bin_mgr_id": "default",
                        "name": "perf-test-docker-local",
                        "filters": [
                            {"type": "regex", "value": ".*"}
                        ]
                    }
                ]
            },
            "assigned_policies": [
                {
                    "name": "perf-test-policy_1",
                    "type": "security"
                }
            ]
        }
        try:
            with self.client.post(
                    "/xray/api/v2/watches",
                    headers=AUTH_HEADER,
                    json=data,
                    name="Create Watch",
                    catch_response=True
            ) as response:
                if response.status_code != 201:
                    response.failure(f"Create Watch failed: {response.status_code} {response.text}")
        except Exception as e:
            print(f"Error in create_watch: {e}")

    @task
    def apply_watch(self):
        data = {
            "watch_names": ["perf-test-watch-1"],
            "date_range": {
                "start_date": "2025-05-19T16:55:37+00:00",
                "end_date": "2025-06-30T16:19:37+00:00"
            }
        }
        try:
            with self.client.post(
                    "/xray/api/v1/applyWatch",
                    headers=AUTH_HEADER,
                    json=data,
                    name="Apply Watch",
                    catch_response=True
            ) as response:
                if response.status_code != 202:
                    response.failure(f"Apply Watch failed: {response.status_code} {response.text}")
        except Exception as e:
            print(f"Error in apply_watch: {e}")

    @task
    def get_violations(self):
        data = {
            "filters": {
                "watch_name": "perf-test-watch-1",
                "violation_type": "Security",
                "min_severity": "High",
                "resources": {
                    "artifacts": [
                        {
                            "repo": "perf-test-docker-local",
                            "path": "/perf-alpine/1.0"
                        },
                        {
                            "repo": "perf-test-docker-local",
                            "path": "/alpine/3.9/manifest.json"
                        }
                    ]
                }
            },
            "pagination": {
                "order_by": "created",
                "direction": "asc",
                "limit": 100,
                "offset": 1
            }
        }
        try:
            with self.client.post(
                    "/xray/api/v1/violations",
                    headers=AUTH_HEADER,
                    json=data,
                    name="Get Violations",
                    catch_response=True
            ) as response:
                if response.status_code != 200:
                    response.failure(f"Get Violations failed: {response.status_code} {response.text}")
        except Exception as e:
            print(f"Error in get_violations: {e}")


class WebsiteUser(HttpUser):
    tasks = [PerfTestTasks]
    wait_time = between(1, 2)

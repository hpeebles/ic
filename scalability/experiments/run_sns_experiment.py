#!/usr/bin/env python3
"""Benchmark the SNS."""
import json
import os
import re
import shlex
import subprocess
import sys

import gflags
import requests
from ic.candid import encode
from ic.candid import Types

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from common import misc  # noqa
from common import base_experiment  # noqa

FLAGS = gflags.FLAGS
gflags.DEFINE_boolean("interactive", True, "Confirm some steps before continuing the script")
gflags.DEFINE_boolean("deploy", True, "Should the NNS be deployed")

TMPDIR = "/tmp"
DFX_VERSION = "0.11.0-beta.1"
SNS_BRANCH = "origin/main"


class SnsExperiment(base_experiment.BaseExperiment):
    """Logic for experiment 2."""

    def get_canister_ids(self):
        with open(os.path.join(self.nns_dapp_dir, "canister_ids.json")) as f:
            return {key: value[FLAGS.testnet] for key, value in json.loads(f.read()).items()}

    def ensure_install_dfx(self):
        current_version = subprocess.check_output(["dfx", "--version"]).decode().split()
        if len(current_version) == 2 and current_version[1] == DFX_VERSION:
            return
        subprocess.check_output(
            f'DFX_VERSION={DFX_VERSION} sh -ci "$(curl -fsSL https://smartcontracts.org/install.sh)"', shell=True
        )

    def get_idl2json(self):
        self.idl2json_dir = os.path.join(TMPDIR, "idl2json")
        if not os.path.exists(self.idl2json_dir):
            subprocess.check_output(
                ["git", "clone", "https://github.com/dfinity/idl2json.git", self.idl2json_dir],
                cwd=TMPDIR,
            )
            subprocess.check_output(
                shlex.split("cargo build --release"),
                cwd=self.idl2json_dir,
            )

    def ensure_checkout_nns_dapp(self):
        self.nns_dapp_dir = os.path.join(TMPDIR, "nns-dapp")
        if not os.path.exists(self.nns_dapp_dir):
            print("NNS dapp not checked out yet, checking out")
            subprocess.check_output(
                ["git", "clone", "https://github.com/dfinity/nns-dapp/", self.nns_dapp_dir],
                cwd=TMPDIR,
            )
            subprocess.check_output(
                ["git", "reset", "--hard", SNS_BRANCH],
                cwd=self.nns_dapp_dir,
            )

    def deploy_sns(self):
        # XXX git clean -fdx here
        subprocess.run(["rm", "canister_ids.json"], cwd=self.nns_dapp_dir)
        deploy_env = os.environ.copy()
        deploy_env["PATH"] = str(
            ":".join(
                [
                    os.path.abspath(self.artifacts_path),
                    os.path.join(os.path.abspath(self.idl2json_dir), "target/release/"),
                    deploy_env["PATH"],
                ]
            )
        )
        print(deploy_env["PATH"])
        subprocess.check_output(["./deploy.sh", "--sns", FLAGS.testnet], cwd=self.nns_dapp_dir, env=deploy_env)

    def generate_dfx_json(self, testnet, nns_url):

        curr_git_revision = (
            subprocess.check_output(
                [
                    "./gitlab-ci/src/artifacts/newest_sha_with_disk_image.sh",
                    "HEAD",
                ],
                cwd="..",
            )
            .decode()
            .replace("\n", "")
        )

        dfx_json_file = os.path.join(self.nns_dapp_dir, "dfx.json")
        print(f"Reading existing dfx.json file from {dfx_json_file}")

        old_dfx_json = {}
        with open(dfx_json_file) as dfx_file:
            old_dfx_json = json.loads(dfx_file.read())
            if testnet not in old_dfx_json["networks"]:
                old_dfx_json["networks"][testnet] = {
                    "config": {
                        "BUILD": "dev",
                        "FETCH_ROOT_KEY": True,
                        "REDIRECT_TO_LEGACY": "both",
                        "HOST": f"https://{testnet}.dfinity.network",
                        "IDENTITY_SERVICE_URL": f"https://qjdve-lqaaa-aaaaa-aaaeq-cai.{testnet}.dfinity.network",
                    },
                    "providers": [nns_url],
                    "type": "persistent",
                }
            old_dfx_json["defaults"]["build"]["config"]["IC_COMMIT"] = str(curr_git_revision)
            print("Generated new content for dfx.json file")

        with open(dfx_json_file, "w") as dfx_file:
            dfx_file.write(json.dumps(old_dfx_json, indent=2))
            print("Wrote new content for dfx.json file")

        # Sanity check
        print(subprocess.check_output(["git", "diff"], cwd=self.nns_dapp_dir).decode())

        if FLAGS.interactive:
            input("Confirm content of dfx json file .. ")
            print("")

    def run_experiment_internal(self, config):
        raise Exception("Not yet implemented")

    def run_iterations(self, iterations=None):
        raise Exception("Not yet implemented")

    def check_root_canister(self, nns_url):
        canister_id = self.get_canister_ids()["sns_root"]
        print(f"Canister ID of root caniter is: {canister_id}")
        agent = misc.get_anonymous_agent(self._get_nns_ip())
        params = [
            {"type": Types.Vec(Types.Principal), "value": []},
        ]
        response = agent.update_raw(canister_id, "canister_status", encode(params))
        print("Response is:", response)

    def check_canisters_installed(self, nns_url, canister_name, fn_name):
        found = False
        num_lines_left = 0
        for line in requests.get(nns_url).text.split("\n"):
            if re.match(f".*summary.*{canister_name}.*", line):
                num_lines_left = 20
            if num_lines_left > 0:
                num_lines_left -= 1
                if re.match(f".*ExportedFunctions.*{fn_name}.*", line):
                    print(line)
                    found = True
        return found

    def check_correctness(self, canisters):
        cmd = [
            "dfx",
            "canister",
            "--network",
            FLAGS.testnet,
            "call",
            "wasm_canister",
            "list_deployed_snses",
            "( record { } )",
        ]
        print("Calling", cmd)
        out = subprocess.check_output(cmd, cwd=self.nns_dapp_dir).decode()
        print("Result", out, " - looking for", canisters["sns_root"])
        return canisters["sns_root"] in out


if __name__ == "__main__":
    exp = SnsExperiment()
    nns_url = exp._get_nns_url()
    sns_subnet = exp.get_subnets()[1]
    print(f"SNS subnet ID is: {sns_subnet}")

    exp.ensure_checkout_nns_dapp()
    if FLAGS.deploy:
        print(exp.get_subnets())
        res = subprocess.check_output(
            [exp._get_ic_admin_path(), "--nns-url", nns_url, "get-subnet", exp.get_subnets()[0]],
            encoding="utf-8",
        )

        nns_subnet_json = json.loads(res)["records"][0]["value"]
        res = subprocess.check_output(
            [
                exp._get_ic_admin_path(),
                "--nns-url",
                nns_url,
                "propose-to-update-subnet",
                "--subnet",
                sns_subnet,
                "--test-neuron-proposer",
                "--initial-notary-delay-millis",
                str(nns_subnet_json["initial_notary_delay_mills"]),
                "--unit-delay-millis",
                str(nns_subnet_json["unit_delay_millis"]),
                "--max-ingress-bytes-per-message",
                str(nns_subnet_json["max_ingress_bytes_per_message"]),
                "--dkg-interval-length",
                str(nns_subnet_json["dkg_interval_length"]),
            ],
            encoding="utf-8",
        )
        print(f"Result of ic-admin call to update subnet: {res}")

        exp.get_idl2json()
        exp.ensure_install_dfx()
        exp.generate_dfx_json(FLAGS.testnet, nns_url)
        exp.deploy_sns()

    exp.check_root_canister(nns_url)  # Doesn't work yet ..
    assert exp.check_canisters_installed(nns_url, exp.get_canister_ids()["sns_root"], "get_sns_canisters_summary")
    assert exp.check_canisters_installed(nns_url, exp.get_canister_ids()["sns_governance"], "get_root_canister_status")
    assert exp.check_correctness(exp.get_canister_ids())
    print(f"Done, check if canisters are installed at: {nns_url}")

#!/usr/bin/env python
"""
Purpose: Measure IC performance give a complex workload.

The workload configuration to use is being read from a seperate workload description file.
"""
import os
import shutil
import sys

import gflags
import toml

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import common.misc as misc  # noqa
import common.workload_experiment as workload_experiment  # noqa
import common.workload as workload  # noqa
import common.report as report  # noqa

FLAGS = gflags.FLAGS
gflags.DEFINE_string("workload", None, "Workload description to execute")
gflags.MarkFlagAsRequired("workload")

gflags.DEFINE_integer("initial_rps", 100, "Starting number for requests per second.")
gflags.DEFINE_integer("increment_rps", 50, "Increment of requests per second per round.")
gflags.DEFINE_integer(
    "max_rps", 40000, "Maximum requests per second to be sent. Experiment will wrap up beyond this number."
)


class MixedWorkloadExperiment(workload_experiment.WorkloadExperiment):
    """Logic for mixed workload experiments."""

    def init_experiment(self):
        """Install canisters."""
        super().init_experiment()
        self.workload_description = None
        shutil.copy(FLAGS.workload, self.out_dir)
        with open(FLAGS.workload) as f:
            self.raw_description = toml.loads(f.read())
            self.install_canister_from_workload_description(self.raw_description)
            self.workload_description = workload.workload_description_from_dict(self.raw_description, self.canister_ids)

    def install_canister_from_workload_description(self, description):
        """Install all canisters required to run the given workload description."""
        for wl in description["workload"]:
            canister = wl["canister"]
            if canister not in self.canister_ids:
                self.install_canister(self.target_nodes[0], canister)

    def run_experiment_internal(self, config):
        """Run workload generator with the load specified in config."""
        f_stdout = os.path.join(self.iter_outdir, "workload-generator-{}.stdout.txt")
        f_stderr = os.path.join(self.iter_outdir, "workload-generator-{}.stderr.txt")

        results = {}
        threads = []
        curr_workload_generator_index = 0
        NUM_MACHINES_PER_WORKLOAD = 1  # TODO - make configurable in toml
        for wl in self.workload_description:
            print(wl)
            timeout = max(2 * wl.duration, 300)
            rps = int(config["load_total"] * wl.rps_ratio)
            if wl.rps < 0:
                wl = wl._replace(rps=rps)
            load_generators = []
            if len(self.machines) < 1:
                raise Exception("No machines for load generation, aborting")
            for _ in range(NUM_MACHINES_PER_WORKLOAD):
                load_generators.append(self.machines[curr_workload_generator_index])
                curr_workload_generator_index = (curr_workload_generator_index + 1) % len(self.machines)

            print(f"Generating workload for machines {load_generators}")
            load = workload.Workload(
                load_generators,
                self.target_nodes,
                wl,
                f_stdout,
                f_stderr,
                timeout,
            )
            commands, _ = load.get_commands()
            n = 0
            while True:
                n += 1
                try:
                    filename = os.path.join(self.iter_outdir, f"workload-generator-cmd-{n}")
                    # Try to open file in exclusive mode
                    with open(filename, "x") as cmd_file:
                        for cmd in commands:
                            cmd_file.write(cmd + "\n")
                    break
                except FileExistsError:
                    print("Failed to open - file already exists")

            load.start()
            threads.append(load)

        all_destinations = []
        for num, thread in enumerate(threads):
            thread.join()
            destinations = [
                "{}/summary_workload_{}_{}_machine_{}".format(
                    self.iter_outdir, num, idx, load_generator.replace(":", "_")
                )
                for idx, load_generator in enumerate(thread.load_generators)
            ]
            thread.fetch_results(destinations, self.iter_outdir)
            print("Evaluating results from machines: {}".format(destinations))
            all_destinations += destinations
            results[num] = report.evaluate_summaries(destinations)

        aggregated = report.evaluate_summaries(all_destinations)
        return (results, aggregated)

    def run_iterations(self, iterations=None):
        """Exercise the experiment with specified iterations."""
        results = []
        for d in iterations:
            print(f"🚀 Running with total load {d}")
            config = {"load_total": d}
            res, aggregated = self.run_experiment(config)
            results.append((config, res, aggregated))
        data = [workloads for _, workloads, _ in results]
        num_workloads = len(self.workload_description)
        print(results)
        self.write_summary_file(
            "run_mixed_workload_experiment",
            {
                "rps_base": [rate for rate, _, _ in results],
                "failure_rate": [[d[i].failure_rate for d in data] for i in range(num_workloads)],
                "latency": [[d[i].percentiles[95] for d in data] for i in range(num_workloads)],
                "labels": [
                    f"{d.get('canister', '')} - "
                    f"{d.get('rps_ratio', '')}% rps with "
                    f"{d.get('arguments', '')} @"
                    f"{d.get('start_delay', 0)}s for {d.get('duration', '')}s"
                    for d in self.raw_description["workload"]
                ],
                "description": self.raw_description["description"],
                "title": self.raw_description["title"],
            },
            iterations,
            "base requests / s",
            "mixed",
        )


if __name__ == "__main__":
    exp = MixedWorkloadExperiment()
    iterations = misc.get_iterations(FLAGS.target_rps, FLAGS.initial_rps, FLAGS.max_rps, FLAGS.increment_rps, 2)
    print(f"🚀 Running with iterations: {iterations}")
    exp.init_experiment()
    exp.run_iterations(iterations)
    exp.end_experiment()

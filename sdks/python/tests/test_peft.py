from __future__ import annotations

import unittest
from unittest import mock

from smolvm_rollout import peft_lora_tensors, publish_peft_adapter


class Parameter:
    def __init__(self, identity):
        self.identity = identity

    def detach(self):
        return self


class Configuration:
    peft_type = "LORA"
    bias = "none"
    use_dora = False
    modules_to_save = None
    trainable_token_indices = None

    def to_dict(self):
        return {"peft_type": self.peft_type, "r": 16}


class Model:
    active_adapter = "default"
    _tp_plan = None

    def __init__(self, configuration=None):
        self.peft_config = {"default": configuration or Configuration()}
        self.parameters = [
            ("base.weight", Parameter("base")),
            ("model.q_proj.lora_B.other.weight", Parameter("other")),
            ("model.q_proj.lora_B.default.weight", Parameter("b")),
            ("model.q_proj.lora_A.default.weight", Parameter("a")),
        ]

    def named_parameters(self):
        return iter(self.parameters)

    def modules(self):
        return iter(())


class PeftTests(unittest.TestCase):
    def test_extracts_only_the_active_lora_without_base_state(self):
        model = Model()
        tensors = peft_lora_tensors(model)
        self.assertEqual(
            list(tensors),
            ["model.q_proj.lora_A.weight", "model.q_proj.lora_B.weight"],
        )
        self.assertEqual(tensors["model.q_proj.lora_A.weight"].identity, "a")
        self.assertEqual(tensors["model.q_proj.lora_B.weight"].identity, "b")

    def test_publishes_the_extracted_tensors_and_configuration(self):
        model = Model()
        with mock.patch("smolvm_rollout.peft.publish_device_adapter") as publish:
            publish.return_value = bytes(range(32))
            token = publish_peft_adapter(
                model,
                shim_path="/shim.so",
                synchronize=lambda: None,
            )
        self.assertEqual(token, bytes(range(32)))
        tensors, configuration = publish.call_args.args
        self.assertEqual(
            list(tensors),
            ["model.q_proj.lora_A.weight", "model.q_proj.lora_B.weight"],
        )
        self.assertEqual(configuration, {"peft_type": "LORA", "r": 16})
        self.assertEqual(publish.call_args.kwargs["shim_path"], "/shim.so")
        self.assertIsNotNone(publish.call_args.kwargs["synchronize"])

    def test_explicit_adapter_name_selects_and_normalizes_that_adapter(self):
        model = Model()
        model.peft_config["experiment"] = Configuration()
        model.parameters.append(
            ("model.q_proj.lora_A.experiment.weight", Parameter("experiment"))
        )
        tensors = peft_lora_tensors(model, adapter_name="experiment")
        self.assertEqual(list(tensors), ["model.q_proj.lora_A.weight"])
        self.assertEqual(tensors["model.q_proj.lora_A.weight"].identity, "experiment")

    def test_ignores_a_model_plan_without_tensor_parallel_module_state(self):
        model = Model()
        model._tp_plan = {"model.q_proj": "local"}
        self.assertEqual(len(peft_lora_tensors(model)), 2)

    def test_requires_one_active_adapter(self):
        model = Model()
        model.active_adapter = ["default"]
        with self.assertRaisesRegex(ValueError, "single active"):
            peft_lora_tensors(model)

    def test_rejects_semantics_not_represented_by_vllm_lora(self):
        for attribute, value, message in [
            ("peft_type", "ADALORA", "LoRA and QLoRA"),
            ("bias", "all", "biases"),
            ("use_dora", True, "DoRA"),
            ("modules_to_save", ["lm_head"], "modules_to_save"),
            ("trainable_token_indices", [1], "trainable tokens"),
        ]:
            with self.subTest(attribute=attribute):
                configuration = Configuration()
                setattr(configuration, attribute, value)
                with self.assertRaisesRegex(ValueError, message):
                    peft_lora_tensors(Model(configuration))

    def test_rejects_sharded_models_and_empty_adapters(self):
        model = Model()
        model._tp_plan = {"model.q_proj": "colwise"}
        tp_info = type("TpInfo", (), {"tp_plan": model._tp_plan})()
        module = type("TensorParallelModule", (), {"_tp_info": tp_info})()
        model.modules = lambda: iter((module,))
        with self.assertRaisesRegex(ValueError, "unsharded"):
            peft_lora_tensors(model)

        model = Model()
        model.parameters = [("base.weight", Parameter("base"))]
        with self.assertRaisesRegex(ValueError, "no LoRA tensors"):
            peft_lora_tensors(model)

    def test_rejects_duplicate_normalized_tensor_names(self):
        model = Model()
        duplicate = Parameter("duplicate")
        model.parameters.append(
            ("model.q_proj.lora_A.default.weight", duplicate)
        )
        with self.assertRaisesRegex(ValueError, "duplicate PEFT adapter tensor"):
            peft_lora_tensors(model)


if __name__ == "__main__":
    unittest.main()

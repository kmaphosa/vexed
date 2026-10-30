"""Smoke-test your Nebius setup:  python -m vexed.check"""

from .llm import Nemotron

if __name__ == "__main__":
    llm = Nemotron()
    print(f"Model: {llm.model}")
    print(llm._ask('Return {"ok": true, "model_family": "<your model family>"}', max_tokens=800))

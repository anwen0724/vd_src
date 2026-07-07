from scripts.batch_build_permission_chain_graphs import resolve_repo_root


def test_resolve_repo_root():
    assert str(resolve_repo_root("hackatdac21__h21_access_lock_scope", __import__("pathlib").Path("experiments"))).endswith(
        "experiments\\baseline_hackatdac21\\agent_input\\h21_access_lock_scope"
    ) or str(resolve_repo_root("hackatdac21__h21_access_lock_scope", __import__("pathlib").Path("experiments"))).endswith(
        "experiments/baseline_hackatdac21/agent_input/h21_access_lock_scope"
    )

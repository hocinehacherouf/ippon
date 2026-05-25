"""Shared pytest fixtures.

Integration tests (marked ``integration``) require the docker-compose stack.
K8s tests (marked ``k8s``) require a kind/k3d cluster. Both are excluded from
the default ``just test`` run.
"""

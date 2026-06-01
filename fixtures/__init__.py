"""Shared, version-controlled test fixtures for MCP-Poison-Bench.

Imported by both `servers/` (to render poisoned metadata) and `harness/` (to know
which payloads to sweep). This is the single source of truth for attack payloads;
servers MUST NOT inline injection strings of their own. See `fixtures/payloads.py`.
"""

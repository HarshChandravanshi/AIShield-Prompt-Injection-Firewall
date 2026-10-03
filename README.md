# AIShield — Agentic Prompt Injection Firewall

AIShield is a cybersecurity prototype that protects AI agents from prompt injection attacks.

It analyzes user and external content, detects malicious instructions, calculates a risk score, and applies an ALLOW, SANITIZE, or BLOCK decision.

## Problem

AI agents can consume untrusted content from users, websites, documents, APIs, and RAG systems. Attackers can hide malicious instructions in this content to manipulate the AI agent.

## Solution

AIShield acts as a security layer between untrusted content and the downstream AI agent.

The system:

1. Receives and normalizes input.
2. Detects prompt injection attacks.
3. Identifies security findings.
4. Calculates a risk score.
5. Applies security policies.
6. Provides an explainable decision.
7. Records the security event.

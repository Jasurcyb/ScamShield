# Security Policy

## Credential Safety

This project does not store real credentials. 

To run this project, follow these security instructions:
1. Copy `.env.example` to `.env` and fill in your own API keys.
2. Copy `agent_config.yaml.example` to `agent_config.yaml` and configure your credentials.

> [!WARNING]
> **Никогда не коммитьте `.env` или `agent_config.yaml`!**
> Never commit `.env` or `agent_config.yaml` to public repositories. These files contain sensitive access keys and are ignored by default via `.gitignore`.

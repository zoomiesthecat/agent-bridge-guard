import os
from pathlib import Path

import pytest

from agent_bridge_guard.config import ConfigError, load_config


def write_config(
    path: Path,
    *,
    mode: int = 0o600,
    rpc: str = "https://rpc.example",
    secondary_rpc: str = "https://rpc-secondary.example",
) -> None:
    path.write_text(
        f"""
[database]
path = "{path.parent / "operations.sqlite3"}"

[provider.debridge]
create_tx_url = "https://dln.debridge.finance/v1.0/dln/order/create-tx"
tracking_url = "https://dln-api.debridge.finance/api"

[chains.arbitrum]
chain_id = 42161
primary_rpc = "{rpc}"
secondary_rpc = "{secondary_rpc}"

[chains.robinhood]
chain_id = 4663
primary_rpc = "https://rpc.mainnet.chain.robinhood.com"
secondary_rpc = "https://rpc-secondary-robinhood.example"
""".strip()
        + "\n"
    )
    path.chmod(mode)


def test_load_config_requires_private_regular_file_and_redacts_urls(tmp_path: Path) -> None:
    config_path = tmp_path / "config.toml"
    write_config(config_path)

    config = load_config(config_path)

    assert config.chains["arbitrum"].chain_id == 42161
    assert config.chains["arbitrum"].primary_rpc.reveal() == "https://rpc.example"
    assert "rpc.example" not in repr(config)

    config_path.chmod(0o644)
    with pytest.raises(ConfigError, match="mode 0600"):
        load_config(config_path)


def test_load_config_rejects_symlink_and_url_credentials(tmp_path: Path) -> None:
    real = tmp_path / "real.toml"
    link = tmp_path / "link.toml"
    write_config(real)
    link.symlink_to(real)

    with pytest.raises(ConfigError, match="symlink"):
        load_config(link)

    link.unlink()
    write_config(real, rpc="https://user:secret@rpc.example")
    with pytest.raises(ConfigError) as error:
        load_config(real)

    assert "secret" not in str(error.value)
    assert os.fspath(real) not in repr(error.value)


def test_load_config_requires_distinct_rpc_endpoints(tmp_path: Path) -> None:
    config_path = tmp_path / "config.toml"
    write_config(
        config_path,
        rpc="https://same-rpc.example/private-token",
        secondary_rpc="https://same-rpc.example/private-token",
    )

    with pytest.raises(ConfigError, match="distinct"):
        load_config(config_path)

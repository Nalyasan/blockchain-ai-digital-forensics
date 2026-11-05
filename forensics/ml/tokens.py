"""Token Decimals and Canonical Valuation Registry for Unit-Safe Asset Handling.

Normalizes heterogeneous token transfers across EVM chains (18-decimal ETH/DAI,
6-decimal USDC, 8-decimal WBTC) into reference economic units.
"""
from __future__ import annotations

import math
from typing import Final

# Canonical token decimals registry (normalized lowercase address -> decimals)
KNOWN_TOKEN_DECIMALS: Final[dict[str, int]] = {
    "native": 18,
    "0x6b175474e89094c44da98b954eedeac495271d0f": 18,  # DAI
    "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2": 18,  # WETH
    "0xae7ab96520de3a18e5e111b5eaab095312d7fe84": 18,  # stETH
    "0x7f39c581f595b53c5cb19bd0b3f8da6c935e2ca0": 18,  # wstETH
    "0x0100546f2cd4c9d97f798ffc9755e47865ff7ee6": 18,  # alETH-ETH
    "0x0275b156cd77c5ed82d44bcc5f9e93eecff20138": 18,  # eDAI (Euler DAI)
    "0x436548baab5ec4d79f669d1b9506d67e98927af7": 18,  # dDAI (Euler debt DAI)
    "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48": 6,   # USDC
    "0xdac17f958d2ee523a2206206994597c13d831ec7": 6,   # USDT
    "0xbcca60bb61934080951369a648fb03df4f96263c": 6,   # aUSDC
    "0x1b808f49add4b8c6b5117d9681cf7312fcf0dc1d": 6,   # eUSDC (Euler USDC)
    "0x84721a3db22eb852233aeae74f9bc8477f8bcc42": 6,   # dUSDC (Euler debt USDC)
    "0x2260fac5e5542a773aa44fbcfedf7c193bc2c599": 8,   # WBTC
    "0x36c4a49f624342225ba45fcfc2e1a4bcbcdce557": 8,   # eWBTC (Euler WBTC)
    "0x6085bc95f506c326dcbcd7a6dd6c79fbc18d4686": 8,   # dWBTC (Euler debt WBTC)
}

DEFAULT_TOKEN_DECIMALS: Final[int] = 18

# Canonical reference USD prices for cross-asset volumetric aggregation
REFERENCE_USD_PRICES: Final[dict[str, float]] = {
    "native": 2000.0,
    "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2": 2000.0,
    "0xae7ab96520de3a18e5e111b5eaab095312d7fe84": 2000.0,
    "0x7f39c581f595b53c5cb19bd0b3f8da6c935e2ca0": 2200.0,
    "0x0100546f2cd4c9d97f798ffc9755e47865ff7ee6": 2000.0,
    "0x2260fac5e5542a773aa44fbcfedf7c193bc2c599": 30000.0,
    "0x36c4a49f624342225ba45fcfc2e1a4bcbcdce557": 30000.0,
    "0x6085bc95f506c326dcbcd7a6dd6c79fbc18d4686": 30000.0,
    "0x6b175474e89094c44da98b954eedeac495271d0f": 1.0,
    "0x0275b156cd77c5ed82d44bcc5f9e93eecff20138": 1.0,
    "0x436548baab5ec4d79f669d1b9506d67e98927af7": 1.0,
    "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48": 1.0,
    "0xdac17f958d2ee523a2206206994597c13d831ec7": 1.0,
    "0xbcca60bb61934080951369a648fb03df4f96263c": 1.0,
    "0x1b808f49add4b8c6b5117d9681cf7312fcf0dc1d": 1.0,
    "0x84721a3db22eb852233aeae74f9bc8477f8bcc42": 1.0,
}

DEFAULT_USD_PRICE: Final[float] = 1.0


def get_token_decimals(asset_id: str) -> int:
    """Returns integer decimals for asset_id with case-insensitive lookup."""
    norm = str(asset_id or "").strip().lower()
    return KNOWN_TOKEN_DECIMALS.get(norm, DEFAULT_TOKEN_DECIMALS)


def get_reference_usd_price(asset_id: str) -> float:
    """Returns reference USD price for asset_id with case-insensitive lookup."""
    norm = str(asset_id or "").strip().lower()
    return REFERENCE_USD_PRICES.get(norm, DEFAULT_USD_PRICE)


def normalize_token_amount_raw(amount_raw: int | str, asset_id: str) -> float:
    """Normalizes raw token integer amount by dividing by 10^decimals."""
    try:
        raw_int = int(amount_raw)
    except (ValueError, TypeError):
        return 0.0
    if raw_int <= 0:
        return 0.0

    decimals = get_token_decimals(asset_id)
    return float(raw_int) / (10.0 ** decimals)


def compute_transfer_usd_value(amount_raw: int | str, asset_id: str) -> float:
    """Computes reference USD valuation for a transfer: (amount_raw / 10^decimals) * price_usd."""
    normalized_units = normalize_token_amount_raw(amount_raw, asset_id)
    price_usd = get_reference_usd_price(asset_id)
    return normalized_units * price_usd

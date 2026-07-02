"""
Scambait Research Suite - Wallet Honeypot

Fake cryptocurrency wallet display for research purposes.
NO REAL FUNDS - purely for studying scammer behavior.
"""

import random
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional
import uuid
import json

import config
from core.models import WalletDisplay
from core.database import get_db_context


# =============================================================================
# Wallet Data Generator
# =============================================================================

def generate_fake_wallet_address(prefix: str = "7") -> str:
    """
    Generate a fake Solana-style wallet address.
    These are NOT real addresses and cannot receive funds.

    Args:
        prefix: Address prefix

    Returns:
        Fake wallet address
    """
    chars = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    address = prefix
    address += ''.join(random.choice(chars) for _ in range(43))
    return address


def generate_fake_transactions(count: int = 10) -> List[Dict[str, Any]]:
    """
    Generate fake transaction history.
    These are NOT real transactions.

    Args:
        count: Number of transactions to generate

    Returns:
        List of fake transactions
    """
    transactions = []
    current_time = datetime.utcnow()

    transaction_types = [
        ("Received", "+"),
        ("Staking Reward", "+"),
        ("Airdrop", "+"),
        ("Transfer", "-")
    ]

    for i in range(count):
        tx_type, sign = random.choice(transaction_types[:3])  # Mostly receives

        # Generate varying amounts
        if tx_type == "Staking Reward":
            amount = round(random.uniform(0.5, 5.0), 4)
        elif tx_type == "Airdrop":
            amount = round(random.uniform(100, 1000), 2)
        else:
            amount = round(random.uniform(10, 500), 4)

        tx_time = current_time - timedelta(
            days=random.randint(0, 30),
            hours=random.randint(0, 23),
            minutes=random.randint(0, 59)
        )

        transactions.append({
            "id": f"tx_{uuid.uuid4().hex[:16]}",
            "type": tx_type,
            "amount": f"{sign}{amount} SOL",
            "usd_value": f"${amount * 100:.2f}",
            "timestamp": tx_time.isoformat(),
            "status": "Confirmed",
            "confirmations": random.randint(100, 10000),
            "from_address": generate_fake_wallet_address() if sign == "+" else config.HONEYPOT_WALLET["address"],
            "to_address": config.HONEYPOT_WALLET["address"] if sign == "+" else generate_fake_wallet_address()
        })

    # Sort by timestamp descending
    transactions.sort(key=lambda x: x["timestamp"], reverse=True)

    return transactions


def generate_token_balances() -> List[Dict[str, Any]]:
    """
    Generate fake token balances.

    Returns:
        List of fake token balances
    """
    tokens = [
        {
            "symbol": "SOL",
            "name": "Solana",
            "balance": config.HONEYPOT_WALLET["balance_sol"],
            "usd_value": config.HONEYPOT_WALLET["balance_usd"],
            # Kept empty on purpose: this tool guarantees zero outbound network
            # calls, so the honeypot page must not reference remote asset URLs.
            "logo": ""
        },
        {
            "symbol": "USDC",
            "name": "USD Coin",
            "balance": round(random.uniform(10000, 50000), 2),
            "usd_value": None,  # 1:1 with USD
            "logo": ""
        },
        {
            "symbol": "BONK",
            "name": "Bonk",
            "balance": random.randint(10000000, 100000000),
            "usd_value": round(random.uniform(1000, 5000), 2),
            "logo": ""
        }
    ]

    # Set USDC value
    tokens[1]["usd_value"] = tokens[1]["balance"]

    return tokens


# =============================================================================
# Wallet Display
# =============================================================================

def get_wallet_display() -> WalletDisplay:
    """
    Get wallet display data for the honeypot.

    Returns:
        WalletDisplay with fake data
    """
    transactions = generate_fake_transactions(15)

    return WalletDisplay(
        address=config.HONEYPOT_WALLET["address"],
        balance_sol=config.HONEYPOT_WALLET["balance_sol"],
        balance_usd=config.HONEYPOT_WALLET["balance_usd"],
        network=config.HONEYPOT_WALLET["network"],
        recent_transactions=transactions,
        disclaimer=config.HONEYPOT_WALLET["disclaimer"]
    )


def get_wallet_details() -> Dict[str, Any]:
    """
    Get detailed wallet information.

    Returns:
        Complete wallet details
    """
    return {
        "wallet": {
            "address": config.HONEYPOT_WALLET["address"],
            "network": config.HONEYPOT_WALLET["network"],
            "created": (datetime.utcnow() - timedelta(days=random.randint(180, 365))).isoformat()
        },
        "balances": {
            "sol": {
                "amount": config.HONEYPOT_WALLET["balance_sol"],
                "usd_value": config.HONEYPOT_WALLET["balance_usd"]
            },
            "tokens": generate_token_balances()
        },
        "transactions": generate_fake_transactions(20),
        "staking": {
            "active_stakes": random.randint(1, 5),
            "total_staked": round(config.HONEYPOT_WALLET["balance_sol"] * 0.3, 2),
            "rewards_earned": round(random.uniform(100, 500), 4)
        },
        "nfts": {
            "count": random.randint(5, 20),
            "estimated_value": round(random.uniform(5000, 20000), 2)
        },
        "disclaimer": config.HONEYPOT_WALLET["disclaimer"],
        "warning": "RESEARCH HONEYPOT - THIS IS NOT A REAL WALLET"
    }


# =============================================================================
# Interaction Logging
# =============================================================================

async def log_interaction(
    session_id: Optional[str],
    action: str,
    details: Dict[str, Any] = None,
    ip_address: str = None
):
    """
    Log wallet interaction for research.

    Args:
        session_id: Optional session ID
        action: Action performed
        details: Additional details
        ip_address: Client IP
    """
    async with get_db_context() as db:
        interaction_id = str(uuid.uuid4())

        await db.execute("""
            INSERT INTO wallet_interactions
            (id, session_id, action, details, ip_address)
            VALUES (?, ?, ?, ?, ?)
        """, (
            interaction_id,
            session_id,
            action,
            json.dumps(details) if details else None,
            ip_address
        ))
        await db.commit()


async def get_wallet_interactions(session_id: str = None) -> List[Dict[str, Any]]:
    """
    Get wallet interactions.

    Args:
        session_id: Optional session filter

    Returns:
        List of interactions
    """
    async with get_db_context() as db:
        if session_id:
            cursor = await db.execute("""
                SELECT * FROM wallet_interactions
                WHERE session_id = ?
                ORDER BY timestamp DESC
            """, (session_id,))
        else:
            cursor = await db.execute("""
                SELECT * FROM wallet_interactions
                ORDER BY timestamp DESC
                LIMIT 100
            """)

        rows = await cursor.fetchall()
        return [dict(row) for row in rows]


# =============================================================================
# Connection Simulation
# =============================================================================

def simulate_wallet_connection() -> Dict[str, Any]:
    """
    Simulate wallet connection process with delays.

    Returns:
        Connection simulation steps
    """
    return {
        "steps": [
            {
                "step": 1,
                "message": "Initializing secure connection...",
                "delay_ms": 2000
            },
            {
                "step": 2,
                "message": "Verifying wallet signature...",
                "delay_ms": 3000
            },
            {
                "step": 3,
                "message": "Fetching account balance...",
                "delay_ms": 2500
            },
            {
                "step": 4,
                "message": "Loading transaction history...",
                "delay_ms": 2000
            },
            {
                "step": 5,
                "message": "Connection established!",
                "delay_ms": 1000
            }
        ],
        "total_delay_ms": 10500,
        "note": "Delays designed to waste scammer time"
    }


def simulate_transaction_preparation() -> Dict[str, Any]:
    """
    Simulate transaction preparation with more delays.

    Returns:
        Transaction simulation steps
    """
    return {
        "steps": [
            {
                "step": 1,
                "message": "Validating recipient address...",
                "delay_ms": 3000
            },
            {
                "step": 2,
                "message": "Checking account balance...",
                "delay_ms": 2000
            },
            {
                "step": 3,
                "message": "Calculating network fees...",
                "delay_ms": 2500
            },
            {
                "step": 4,
                "message": "Preparing transaction...",
                "delay_ms": 4000
            },
            {
                "step": 5,
                "message": "Waiting for confirmation...",
                "delay_ms": 5000
            },
            {
                "step": 6,
                "message": "Error: Network timeout. Please try again.",
                "delay_ms": 1000,
                "error": True
            }
        ],
        "total_delay_ms": 17500,
        "note": "Transaction will always fail - no real funds"
    }


# =============================================================================
# Error Messages (for failed "transactions")
# =============================================================================

TRANSACTION_ERRORS = [
    "Network congestion detected. Please try again in a few minutes.",
    "Transaction validation failed. Please verify the recipient address.",
    "Insufficient network fee. Please ensure you have enough SOL for gas.",
    "RPC node timeout. Connecting to backup node...",
    "Signature verification failed. Please reconnect your wallet.",
    "Transaction simulation failed. The network may be experiencing issues.",
    "Rate limit exceeded. Please wait 60 seconds before trying again.",
    "Account not found on-chain. Please verify your connection.",
    "Block height mismatch. Refreshing connection...",
    "Websocket connection interrupted. Reconnecting..."
]


def get_random_error() -> str:
    """Get a random transaction error message."""
    return random.choice(TRANSACTION_ERRORS)


# =============================================================================
# Wallet Page Data
# =============================================================================

def get_wallet_page_data() -> Dict[str, Any]:
    """
    Get all data needed for the wallet honeypot page.

    Returns:
        Complete page data
    """
    sol_price = round(config.HONEYPOT_WALLET["balance_usd"] / config.HONEYPOT_WALLET["balance_sol"], 2)

    return {
        "wallet": get_wallet_details(),
        "connection_sim": simulate_wallet_connection(),
        "transaction_sim": simulate_transaction_preparation(),
        "market_data": {
            "sol_price_usd": sol_price,
            "24h_change": round(random.uniform(-5, 8), 2),
            "last_updated": datetime.utcnow().isoformat()
        },
        "ui_config": {
            "theme": "dark",
            "show_disclaimer": True,
            "connection_timeout_ms": 30000
        },
        "disclaimer": config.HONEYPOT_WALLET["disclaimer"]
    }

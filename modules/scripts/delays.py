"""
Scambait Research Suite - Delay Patterns

Time-wasting delay mechanisms for baiting interactions.
Simulates realistic human behavior to maximize engagement.
"""

import random
from typing import Tuple
from datetime import datetime, timedelta

import config


# =============================================================================
# Delay Patterns
# =============================================================================

DELAY_PATTERNS = {
    "random": {
        "description": "Random delay within configured range",
        "min_multiplier": 1.0,
        "max_multiplier": 1.0
    },
    "phone_call": {
        "description": "Simulates receiving a phone call",
        "min_multiplier": 2.0,
        "max_multiplier": 5.0,
        "reason": "Sorry, I had to take a phone call from my [relative]."
    },
    "technical_difficulty": {
        "description": "Computer/technical issues",
        "min_multiplier": 1.5,
        "max_multiplier": 4.0,
        "reason": "My computer was doing something strange. Had to restart."
    },
    "spouse_consultation": {
        "description": "Need to ask spouse/family member",
        "min_multiplier": 3.0,
        "max_multiplier": 10.0,
        "reason": "I needed to ask my [spouse] about this first."
    },
    "bathroom_break": {
        "description": "Bathroom break",
        "min_multiplier": 1.0,
        "max_multiplier": 3.0,
        "reason": "Sorry, I had to step away for a moment."
    },
    "doorbell": {
        "description": "Someone at the door",
        "min_multiplier": 2.0,
        "max_multiplier": 6.0,
        "reason": "Someone was at the door. It was just [visitor]."
    },
    "reading_carefully": {
        "description": "Reading instructions carefully",
        "min_multiplier": 1.0,
        "max_multiplier": 2.0,
        "reason": "I was reading everything carefully. I don't want to make a mistake."
    },
    "finding_glasses": {
        "description": "Looking for reading glasses",
        "min_multiplier": 1.5,
        "max_multiplier": 4.0,
        "reason": "I couldn't find my reading glasses. They were on my head the whole time!"
    },
    "typing_slowly": {
        "description": "Typing slowly",
        "min_multiplier": 0.5,
        "max_multiplier": 1.5,
        "reason": "I'm not very good at typing. It takes me a while."
    }
}


# Visitor/relative placeholders for reasons
VISITORS = ["the mailman", "my neighbor", "a delivery person", "someone selling something"]
RELATIVES = ["daughter", "son", "grandson", "neighbor", "friend from church"]
SPOUSES = ["wife", "husband", "partner"]


def calculate_delay(
    pattern: str = "random",
    min_delay: int = None,
    max_delay: int = None
) -> int:
    """
    Calculate delay based on pattern.

    Args:
        pattern: Name of delay pattern
        min_delay: Optional minimum delay override
        max_delay: Optional maximum delay override

    Returns:
        Delay in seconds
    """
    min_delay = min_delay or config.MIN_DELAY_SECONDS
    max_delay = max_delay or config.MAX_DELAY_SECONDS

    pattern_config = DELAY_PATTERNS.get(pattern, DELAY_PATTERNS["random"])

    adjusted_min = int(min_delay * pattern_config["min_multiplier"])
    adjusted_max = int(max_delay * pattern_config["max_multiplier"])

    # Add some randomness
    delay = random.randint(adjusted_min, adjusted_max)

    # Occasionally add extra "distraction" time
    if random.random() < 0.15:
        delay += random.randint(30, 180)

    return delay


def get_delay_reason(pattern: str) -> str:
    """
    Get a reason text for the delay.

    Args:
        pattern: Delay pattern name

    Returns:
        Human-readable reason for the delay
    """
    pattern_config = DELAY_PATTERNS.get(pattern)
    if not pattern_config or "reason" not in pattern_config:
        return ""

    reason = pattern_config["reason"]

    # Fill in placeholders
    reason = reason.replace("[visitor]", random.choice(VISITORS))
    reason = reason.replace("[relative]", random.choice(RELATIVES))
    reason = reason.replace("[spouse]", random.choice(SPOUSES))

    return reason


def get_random_delay_pattern() -> str:
    """
    Get a random delay pattern name.

    Returns:
        Pattern name
    """
    # Weight towards more common patterns
    weights = {
        "random": 30,
        "typing_slowly": 25,
        "reading_carefully": 20,
        "phone_call": 5,
        "technical_difficulty": 5,
        "spouse_consultation": 5,
        "bathroom_break": 5,
        "doorbell": 3,
        "finding_glasses": 2
    }

    patterns = list(weights.keys())
    pattern_weights = list(weights.values())

    return random.choices(patterns, weights=pattern_weights, k=1)[0]


def simulate_typing_delay(text: str, typing_speed: float = None) -> int:
    """
    Simulate typing delay for a given text.

    Args:
        text: Text that would be typed
        typing_speed: Characters per second (defaults to config)

    Returns:
        Typing delay in seconds
    """
    typing_speed = typing_speed or config.TYPING_SPEED_CPS

    # Base typing time
    char_count = len(text)
    base_time = char_count / typing_speed

    # Add variation for "thinking" between sentences
    sentence_count = text.count('.') + text.count('!') + text.count('?')
    thinking_time = sentence_count * random.uniform(2, 8)

    # Add occasional "backspace" delays
    typo_corrections = random.randint(0, 3)
    correction_time = typo_corrections * random.uniform(5, 15)

    total_time = base_time + thinking_time + correction_time

    return int(total_time)


def calculate_progressive_delay(message_count: int, base_delay: int = 60) -> int:
    """
    Calculate delay that increases as conversation progresses.
    Simulates victim getting more cautious or tired.

    Args:
        message_count: Number of messages in conversation
        base_delay: Base delay in seconds

    Returns:
        Progressive delay in seconds
    """
    # Increase delay as conversation goes on
    progression_factor = 1 + (message_count * 0.1)

    # Cap at 3x original delay
    progression_factor = min(progression_factor, 3.0)

    delay = int(base_delay * progression_factor)

    # Add random variation
    delay += random.randint(-15, 45)

    return max(delay, 30)  # Minimum 30 seconds


def get_interruption_sequence() -> Tuple[int, str, int]:
    """
    Get an interruption sequence (pre-delay, message, post-delay).

    Returns:
        Tuple of (pre_delay_seconds, interruption_message, post_delay_seconds)
    """
    interruptions = [
        (30, "Hold on, someone's at the door...", 120),
        (20, "Let me just answer this other call...", 180),
        (45, "Sorry, my [spouse] is asking me something...", 90),
        (15, "Oh the cat is meowing, just a second...", 60),
        (60, "I need to take my medication, one moment...", 150),
        (30, "The doorbell just rang, be right back...", 240),
        (20, "My computer is doing something, hold on...", 90),
        (40, "I think the oven timer went off...", 180)
    ]

    pre_delay, message, post_delay = random.choice(interruptions)

    # Fill placeholders
    message = message.replace("[spouse]", random.choice(SPOUSES))

    # Add variation
    pre_delay += random.randint(-10, 30)
    post_delay += random.randint(-30, 60)

    return (max(pre_delay, 10), message, max(post_delay, 30))


def format_delay_for_display(seconds: int) -> str:
    """
    Format delay for human-readable display.

    Args:
        seconds: Delay in seconds

    Returns:
        Formatted string
    """
    if seconds < 60:
        return f"{seconds} seconds"
    elif seconds < 3600:
        minutes = seconds // 60
        remaining_seconds = seconds % 60
        if remaining_seconds > 0:
            return f"{minutes} min {remaining_seconds} sec"
        return f"{minutes} minutes"
    else:
        hours = seconds // 3600
        remaining_minutes = (seconds % 3600) // 60
        return f"{hours} hr {remaining_minutes} min"


def get_delay_schedule(
    num_responses: int,
    total_target_time: int = 3600  # 1 hour default target
) -> list:
    """
    Generate a schedule of delays for multiple responses.

    Args:
        num_responses: Number of responses to schedule
        total_target_time: Target total time in seconds

    Returns:
        List of delay values in seconds
    """
    if num_responses <= 0:
        return []

    # Calculate average delay needed
    avg_delay = total_target_time // num_responses

    schedule = []
    remaining_time = total_target_time

    for i in range(num_responses):
        # More variation early, more consistent later
        variation = 0.5 - (0.3 * (i / num_responses))

        delay = int(avg_delay * (1 + random.uniform(-variation, variation)))

        # Ensure we don't exceed remaining time
        delay = min(delay, remaining_time - (num_responses - i - 1) * 30)
        delay = max(delay, 30)  # Minimum 30 seconds

        schedule.append(delay)
        remaining_time -= delay

    return schedule

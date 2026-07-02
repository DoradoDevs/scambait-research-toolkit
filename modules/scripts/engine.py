"""
Scambait Research Suite - Scripts Engine

Manages pre-written baiting scripts and response suggestions.
Helps researchers maintain consistent personas while wasting scammer time.
"""

import json
import random
from typing import Dict, Any, List, Optional
from datetime import datetime

import config
from core.models import SuggestedResponse
from modules.scripts.delays import calculate_delay, get_delay_reason


# =============================================================================
# Default Scripts (loaded into DB on init)
# =============================================================================

DEFAULT_SCRIPTS = [
    {
        "id": "confused_elderly",
        "name": "Confused Elderly",
        "description": "A confused older person who struggles with technology and often misunderstands instructions",
        "persona": "elderly",
        "responses": [
            {
                "triggers": ["hello", "hi", "good morning", "good afternoon"],
                "responses": [
                    "Oh hello dear! Is this the computer repair people? My grandson said someone would call...",
                    "Yes? Who is this? Speak up please, I can't hear very well.",
                    "Hello? Is someone there? This darn phone..."
                ],
                "follow_up_hints": ["Ask them to repeat themselves", "Mention grandchildren"]
            },
            {
                "triggers": ["wallet", "crypto", "bitcoin", "money", "transfer"],
                "responses": [
                    "Wallet? I keep my wallet in my purse dear, why do you need to know about that?",
                    "Bit-what? Is that like the coins I use for the laundry machine?",
                    "Oh the money thing! My grandson mentioned something about that. Let me find my reading glasses...",
                    "Transfer? Like a bus transfer? I don't take the bus anymore, my hip you know..."
                ],
                "follow_up_hints": ["Pretend to look for glasses", "Ask them to explain simply"]
            },
            {
                "triggers": ["click", "download", "install", "link"],
                "responses": [
                    "Click what? The TV remote? This one has too many buttons...",
                    "Down-load? Is that when the computer gets slow? It does that a lot.",
                    "Oh I need to find where my grandson wrote down the password... just a moment dear...",
                    "A link? Like a chain link? I don't understand these computer words..."
                ],
                "follow_up_hints": ["Pretend to struggle with mouse", "Ask what button to press"]
            },
            {
                "triggers": ["urgent", "immediately", "now", "hurry", "quick"],
                "responses": [
                    "Oh dear, let me just finish my tea first. It's getting cold.",
                    "Urgent? Well I need to let the cat in first, she's scratching at the door.",
                    "Just a moment, I need to take my pills. Doctor says I can't skip them.",
                    "Hold on dear, someone's at the door... *long pause* ...sorry, it was just the mailman."
                ],
                "follow_up_hints": ["Mention needing to do something else", "Take long pauses"]
            },
            {
                "triggers": ["account", "password", "login", "username"],
                "responses": [
                    "Password? Oh I wrote it down somewhere... let me check my little book...",
                    "Account? Is that like a bank account? I should call my son first...",
                    "Login? I think my grandson set that up. He's at work right now though.",
                    "I have the password somewhere... is it the one with the dog's name or the grandchildren's birthdays?"
                ],
                "follow_up_hints": ["Pretend to search for written passwords", "Mention needing to ask family"]
            }
        ],
        "delay_config": {
            "min_delay": 60,
            "max_delay": 300,
            "typing_speed": 1.5,
            "interruption_chance": 0.3
        }
    },
    {
        "id": "tech_illiterate",
        "name": "Tech Illiterate",
        "description": "Someone who is completely lost with technology and needs everything explained multiple times",
        "persona": "tech_illiterate",
        "responses": [
            {
                "triggers": ["hello", "hi", "support", "help"],
                "responses": [
                    "Oh thank goodness you called! My computer has been making weird noises.",
                    "Hi! Are you the tech people? I really need help, nothing is working.",
                    "Hello! I'm so glad you're here. I accidentally clicked something and now everything is different."
                ],
                "follow_up_hints": ["Describe vague computer problems", "Ask basic questions"]
            },
            {
                "triggers": ["browser", "chrome", "firefox", "internet", "edge"],
                "responses": [
                    "Browser? Is that the blue E thing or the colorful circle?",
                    "I think I use... the internet? Is that the same thing?",
                    "Chrome? Like the shiny metal? I don't understand.",
                    "Oh the internet! Yes I have that. My nephew set it up."
                ],
                "follow_up_hints": ["Confuse browser with search engine", "Ask which icon to click"]
            },
            {
                "triggers": ["right click", "double click", "click"],
                "responses": [
                    "Right click? Which one is the right one? There's two buttons here.",
                    "Double click? I clicked it twice but nothing happened. Should I click faster?",
                    "Click... okay I'm clicking... *click* *click* *click* ... is something supposed to happen?",
                    "I clicked but now there's like 15 windows open. What do I do?"
                ],
                "follow_up_hints": ["Describe clicking wrong things", "Open multiple windows accidentally"]
            },
            {
                "triggers": ["download", "install", "run", "execute"],
                "responses": [
                    "Download? Where does it go? I can't find anything.",
                    "It says 'Save' or 'Open' - which one do I pick?",
                    "Install? It's asking me something about 'administrator'. Is that bad?",
                    "Something popped up but I closed it. Was that important?"
                ],
                "follow_up_hints": ["Close important dialogs accidentally", "Ask what every option means"]
            },
            {
                "triggers": ["email", "address", "send"],
                "responses": [
                    "Email? I think my email is... gmail dot com? No wait, that's not right...",
                    "Can you send it to my Yahoo? Or is it Hotmail? I forget which one I use.",
                    "My email address is... hold on let me ask my daughter. She set it up.",
                    "Send to where? I don't know how to check my email on this computer."
                ],
                "follow_up_hints": ["Be confused about email address", "Mention multiple unused accounts"]
            }
        ],
        "delay_config": {
            "min_delay": 45,
            "max_delay": 180,
            "typing_speed": 2.0,
            "interruption_chance": 0.2
        }
    },
    {
        "id": "overly_eager",
        "name": "Overly Eager",
        "description": "Enthusiastic and willing but keeps making mistakes and asking for clarification",
        "persona": "eager",
        "responses": [
            {
                "triggers": ["hello", "hi", "good"],
                "responses": [
                    "Oh hi!! I'm SO glad you called! I've been waiting for this!",
                    "Hello! Yes yes yes! I'm ready! What do I do first?!",
                    "Hi there! Okay I'm at my computer, everything is on, I'm ready to go!"
                ],
                "follow_up_hints": ["Show excessive enthusiasm", "Be too quick to agree"]
            },
            {
                "triggers": ["wallet", "crypto", "bitcoin", "investment"],
                "responses": [
                    "Ooh crypto! Yes I've heard about this! My friend made a lot of money! I want to try!",
                    "Investment opportunity?! This is exactly what I've been looking for! Tell me everything!",
                    "Bitcoin! Yes! I've been wanting to get into this! What do I need to do?!",
                    "A wallet? Like a digital wallet? That sounds so cool! How do I get one?!"
                ],
                "follow_up_hints": ["Ask lots of excited questions", "Mention wanting to invest more"]
            },
            {
                "triggers": ["click", "link", "open", "download"],
                "responses": [
                    "Okay I clicked it! ... wait, nothing happened. Should I click again?",
                    "I opened it! There's a lot of text... should I read all of this?",
                    "Done! Wait no, I think I clicked the wrong thing. Let me try again...",
                    "Okay downloading! It says 47%... 48%... should I wait or can I click something else?"
                ],
                "follow_up_hints": ["Report wrong actions", "Ask if every step is correct"]
            },
            {
                "triggers": ["amount", "money", "pay", "send", "transfer"],
                "responses": [
                    "How much do I need to send? I want to do this right!",
                    "Okay! I'm looking at my bank app right now! What's the amount again?",
                    "Money? Sure! But wait, where exactly do I send it? I want to make sure!",
                    "Transfer? Like a wire transfer? I've never done that before but I can figure it out!"
                ],
                "follow_up_hints": ["Seem willing but ask for confirmation", "Make small 'mistakes'"]
            },
            {
                "triggers": ["code", "verification", "confirm"],
                "responses": [
                    "Ooh I got a code! Is it... let me read it... 8-4-7-... wait is that a 1 or a 7?",
                    "Verification? Yes! Where do I put it? There's like three different boxes here.",
                    "Got it! But wait, it says 'Do not share this code'. Is it okay to tell you?",
                    "The code expires in 5 minutes it says! Quick, where do I type it?!"
                ],
                "follow_up_hints": ["Read codes slowly", "Question whether sharing is okay"]
            }
        ],
        "delay_config": {
            "min_delay": 20,
            "max_delay": 90,
            "typing_speed": 4.0,
            "interruption_chance": 0.15
        }
    },
    {
        "id": "suspicious_curious",
        "name": "Suspicious but Curious",
        "description": "Skeptical about everything but stays engaged asking probing questions",
        "persona": "suspicious",
        "responses": [
            {
                "triggers": ["hello", "hi", "calling"],
                "responses": [
                    "Who is this? How did you get my number?",
                    "Hello... and you are? I don't remember signing up for anything.",
                    "Hi. Before we go any further, how do I know this is legitimate?"
                ],
                "follow_up_hints": ["Question their identity", "Ask for proof"]
            },
            {
                "triggers": ["opportunity", "offer", "special", "exclusive"],
                "responses": [
                    "Hmm, sounds interesting... but how do I know this isn't a scam?",
                    "Why me specifically? That seems suspicious.",
                    "Okay but I need to verify this first. What's your company name again?",
                    "My friend told me about scams like this... can you prove you're legitimate?"
                ],
                "follow_up_hints": ["Ask for verification", "Mention knowing about scams"]
            },
            {
                "triggers": ["wallet", "crypto", "bitcoin", "money"],
                "responses": [
                    "Crypto? I've heard those can be scams. How do I know you're real?",
                    "Before I do anything with money, I need some kind of proof.",
                    "Can you send me documentation? I want to have my lawyer look at it.",
                    "Interesting... but I'd want to do some research first. What's your website?"
                ],
                "follow_up_hints": ["Request documentation", "Mention wanting to research"]
            },
            {
                "triggers": ["urgent", "now", "limited", "expire"],
                "responses": [
                    "Why the rush? Legitimate offers don't usually pressure people like this.",
                    "That's exactly what scammers say - 'act now or lose out'. Nice try.",
                    "If this is real, it can wait until I verify everything.",
                    "Pressure tactics? That's a red flag. Convince me this is legitimate first."
                ],
                "follow_up_hints": ["Call out pressure tactics", "Refuse to rush"]
            },
            {
                "triggers": ["trust", "safe", "secure", "guarantee"],
                "responses": [
                    "Trust you? I don't even know you. How can you guarantee anything?",
                    "Safe and secure? That's what everyone says. Show me proof.",
                    "Guarantee? Put it in writing then. And I'll need your full legal name.",
                    "Hmm, I want to believe you but I've been burned before. What evidence do you have?"
                ],
                "follow_up_hints": ["Demand written guarantees", "Share skepticism"]
            }
        ],
        "delay_config": {
            "min_delay": 30,
            "max_delay": 120,
            "typing_speed": 3.0,
            "interruption_chance": 0.1
        }
    }
]


# =============================================================================
# Script Engine Functions
# =============================================================================

async def get_suggested_response(
    session_id: str,
    context: str,
    script_id: Optional[str] = None
) -> SuggestedResponse:
    """
    Get a suggested response based on context and script.

    Args:
        session_id: Session ID
        context: Recent context/message from scammer
        script_id: Optional script ID to use

    Returns:
        SuggestedResponse with text and delay
    """
    from core.database import SessionDB, ScriptDB

    # Get session to find script
    if not script_id:
        session = await SessionDB.get(session_id)
        if session:
            script_id = session.get("script_id")

    # Get script
    script = None
    if script_id:
        script = await ScriptDB.get(script_id)

    if not script:
        # Use a random default script
        script = random.choice(DEFAULT_SCRIPTS)

    # Parse script responses
    responses = script.get("responses", [])
    if isinstance(responses, str):
        responses = json.loads(responses)

    # Find matching response based on context
    context_lower = context.lower() if context else ""
    matched_response = None
    follow_up_hints = []

    for response_set in responses:
        triggers = response_set.get("triggers", [])
        for trigger in triggers:
            if trigger.lower() in context_lower:
                possible_responses = response_set.get("responses", [])
                if possible_responses:
                    matched_response = random.choice(possible_responses)
                    follow_up_hints = response_set.get("follow_up_hints", [])
                break
        if matched_response:
            break

    # Fallback if no match
    if not matched_response:
        fallback_responses = [
            "I'm sorry, can you repeat that? I didn't quite understand.",
            "Hmm, what do you mean exactly?",
            "Could you explain that in simpler terms?",
            "I'm not sure I follow... can you go slower?"
        ]
        matched_response = random.choice(fallback_responses)

    # Calculate delay
    delay_config = script.get("delay_config", {})
    if isinstance(delay_config, str):
        delay_config = json.loads(delay_config)

    delay = calculate_delay(
        pattern="random",
        min_delay=delay_config.get("min_delay", config.MIN_DELAY_SECONDS),
        max_delay=delay_config.get("max_delay", config.MAX_DELAY_SECONDS)
    )

    # Maybe add interruption
    if random.random() < delay_config.get("interruption_chance", 0.2):
        interruption = get_interruption_text(script.get("persona", "default"))
        matched_response = f"{interruption}\n\n{matched_response}"
        delay += random.randint(30, 120)

    return SuggestedResponse(
        text=matched_response,
        delay_seconds=delay,
        persona=script.get("persona", "unknown"),
        follow_up_hints=follow_up_hints
    )


def get_delay_for_message(script_id: Optional[str], message_length: int) -> int:
    """
    Calculate appropriate delay based on script and message.

    Args:
        script_id: Optional script ID
        message_length: Length of the message

    Returns:
        Delay in seconds
    """
    base_delay = calculate_delay("random")

    # Add typing time simulation
    typing_speed = config.TYPING_SPEED_CPS
    typing_time = int(message_length / typing_speed)

    return base_delay + typing_time


def get_interruption_text(persona: str) -> str:
    """
    Get interruption text for a persona.

    Args:
        persona: Persona type

    Returns:
        Interruption text
    """
    interruptions = {
        "elderly": [
            "Oh hold on, someone's at the door...\n*3 minutes later*\n...sorry about that, it was just the neighbor.",
            "Just a moment dear, I need to take my medication...\n*long pause*\n...okay I'm back.",
            "The cat just knocked something over, let me clean that up...",
            "Oh my show is on! Can you hold for just a minute?\n*5 minutes later*\n...okay where were we?"
        ],
        "tech_illiterate": [
            "Wait, something popped up on my screen... it says 'Update Available'... should I click it?",
            "Hold on, my computer is making a noise... *fan sounds*... is that bad?",
            "Sorry, I accidentally minimized everything. How do I get it back?",
            "My screen just went black! Oh wait, it's the screensaver..."
        ],
        "eager": [
            "Oh! I just got another call coming in - let me ignore that. Okay back to you!",
            "Sorry! I got excited and clicked too many things. Let me close these windows...",
            "Wait wait wait - I want to take notes! Let me find a pen...",
            "Hold on, I want to tell my spouse about this! *yelling in background* ...okay they're excited too!"
        ],
        "suspicious": [
            "Hold on, I'm going to record this call... you don't mind right?",
            "Let me write down everything you're saying... for my records.",
            "I'm going to have my tech-savvy friend listen in... give me a moment.",
            "Wait, I need to take a screenshot of this. For evidence. Just in case."
        ]
    }

    persona_interruptions = interruptions.get(persona, interruptions.get("elderly"))
    return random.choice(persona_interruptions)


def get_script_suggestions(scam_type: str) -> List[Dict[str, str]]:
    """
    Get script suggestions based on scam type.

    Args:
        scam_type: Type of scam

    Returns:
        List of suggested scripts
    """
    suggestions = {
        "crypto": ["confused_elderly", "overly_eager", "suspicious_curious"],
        "tech_support": ["confused_elderly", "tech_illiterate"],
        "romance": ["suspicious_curious", "overly_eager"],
        "investment": ["overly_eager", "suspicious_curious"],
        "phishing": ["tech_illiterate", "confused_elderly"]
    }

    suggested_ids = suggestions.get(scam_type, ["confused_elderly", "tech_illiterate"])

    return [
        {"id": script["id"], "name": script["name"], "description": script["description"]}
        for script in DEFAULT_SCRIPTS
        if script["id"] in suggested_ids
    ]

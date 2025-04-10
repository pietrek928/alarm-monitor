from dataclasses import dataclass
import logging
from typing import Tuple
from datetime import datetime
from httpx import AsyncClient, HTTPError


logger = logging.getLogger('fb')
logger.setLevel(logging.INFO)


@dataclass
class InputMessage:
    id: str
    timestamp: datetime
    content: str
    sender_id: str


async def get_fb_user_id(access_token):
    url = "https://graph.facebook.com/v22.0/me"
    params = {
        "access_token": access_token,
        "fields": "id",
    }

    async with AsyncClient() as client:
        try:
            response = await client.get(url, params=params)
            response.raise_for_status()
            data = response.json()
            return data.get("id")

        except HTTPError as http_err:
            logger.exception(f"HTTP error occurred: {http_err} {response.text}")
            return False
        except Exception as e:
            logger.exception(f"Error sending Facebook message: {e}")
            return False

async def send_fb_message(recipient_id, message_text, access_token):
    url = "https://graph.facebook.com/v22.0/me/messages"
    headers = {"Content-Type": "application/json"}
    payload = {
        "recipient": {"id": recipient_id},
        "message": {"text": message_text},
    }
    params = {"access_token": access_token}

    logger.info(f'{message_text} -> {recipient_id}')
    async with AsyncClient() as client:
        try:
            response = await client.post(url, headers=headers, params=params, json=payload)
            response.raise_for_status()  # Raise an exception for bad status codes (4xx or 5xx)
            return True

        except HTTPError as http_err:
            logger.exception(f"HTTP error occurred: {http_err} {response.text}")
            return False
        except Exception as e:
            logger.exception(f"Error sending Facebook message: {e}")
            return False

async def receive_fb_messages(access_token) -> Tuple[InputMessage, ...]:
    url = "https://graph.facebook.com/v22.0/me/conversations"
    params = {
        "access_token": access_token,
        "fields": "messages{message,created_time,from}",
    }

    async with AsyncClient() as client:
        try:
            response = await client.get(url, params=params)
            response.raise_for_status()
            data = response.json()
            messages = []
            if "data" in data:
                for conversation in data["data"]:
                    if "messages" in conversation and "data" in conversation["messages"]:
                        for message_data in conversation["messages"]["data"]:
                            messages.append(InputMessage(
                                id=message_data["id"],
                                timestamp=datetime.strptime(message_data["created_time"], '%Y-%m-%dT%H:%M:%S%z'),
                                content=message_data["message"],
                                sender_id=message_data["from"]["id"]
                            ))
            return messages

        except HTTPError as http_err:
            logger.exception(f"HTTP error occurred: {http_err} {response.text}")
            return ()
        except Exception as e:
            logger.exception(f"Error receiving Facebook messages: {e}")
            return ()


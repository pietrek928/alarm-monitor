import logging
from dataclasses import dataclass
from datetime import datetime

from httpx import AsyncClient, HTTPStatusError, RequestError, Response

logger = logging.getLogger("fb")
logger.setLevel(logging.INFO)

GRAPH_API = "https://graph.facebook.com/v22.0"
REQUEST_TIMEOUT = 30.0


@dataclass
class InputMessage:
    id: str
    timestamp: datetime
    content: str
    sender_id: str


async def _request(
    method: str,
    url: str,
    *,
    params: dict | None = None,
    headers: dict | None = None,
    json: dict | None = None,
) -> Response | None:
    async with AsyncClient(timeout=REQUEST_TIMEOUT) as client:
        try:
            response = await client.request(
                method, url, params=params, headers=headers, json=json
            )
            response.raise_for_status()
            return response
        except HTTPStatusError as exc:
            logger.exception(
                "HTTP %s for %s: %s",
                exc.response.status_code,
                exc.request.url,
                exc.response.text,
            )
            return None
        except RequestError as exc:
            url_repr = exc.request.url if exc.request else url
            logger.exception("Request failed for %s: %s", url_repr, exc)
            return None


async def get_fb_user_id(access_token) -> str | None:
    response = await _request(
        "GET",
        f"{GRAPH_API}/me",
        params={"access_token": access_token, "fields": "id"},
    )
    if response is None:
        return None
    try:
        return response.json().get("id")
    except Exception as e:
        logger.exception("Error parsing Facebook user id: %s", e)
        return None


async def send_fb_message(recipient_id, message_text, access_token) -> bool:
    logger.info("%s -> %s", message_text, recipient_id)
    response = await _request(
        "POST",
        f"{GRAPH_API}/me/messages",
        headers={"Content-Type": "application/json"},
        params={"access_token": access_token},
        json={
            "recipient": {"id": recipient_id},
            "message": {"text": message_text},
        },
    )
    return response is not None


async def receive_fb_messages(access_token) -> tuple[InputMessage, ...]:
    response = await _request(
        "GET",
        f"{GRAPH_API}/me/conversations",
        params={
            "access_token": access_token,
            "fields": "messages{message,created_time,from}",
        },
    )
    if response is None:
        return ()

    try:
        data = response.json()
    except Exception as e:
        logger.exception("Error parsing Facebook conversations: %s", e)
        return ()

    messages: list[InputMessage] = []
    for conversation in data.get("data", []):
        for message_data in conversation.get("messages", {}).get("data", []):
            msg_id = message_data.get("id")
            content = message_data.get("message")
            created_time = message_data.get("created_time")
            sender = message_data.get("from") or {}
            sender_id = sender.get("id")
            if not all((msg_id, content is not None, created_time, sender_id)):
                logger.warning("Skipping incomplete Facebook message: %s", message_data)
                continue
            try:
                messages.append(
                    InputMessage(
                        id=msg_id,
                        timestamp=datetime.strptime(
                            created_time, "%Y-%m-%dT%H:%M:%S%z"
                        ),
                        content=content,
                        sender_id=sender_id,
                    )
                )
            except (ValueError, TypeError) as e:
                logger.warning(
                    "Skipping unparseable Facebook message %s: %s", msg_id, e
                )

    return tuple(messages)

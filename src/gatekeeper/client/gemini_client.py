import asyncio
import logging
import os
from collections.abc import Callable

from dotenv import load_dotenv
from google import genai
from google.genai import types

load_dotenv()

DEFAULT_MODEL = "gemini-3.5-flash-lite"
TIMEOUT_MS = 10_000
LOCAL_TIMEOUT_SECONDS = 8
RETRIES = 1
_LOGGER = logging.getLogger(__name__)

def new_client() -> genai.Client | None:
	"""Create the shared Gemini client, or return None when no API key is set."""
	api_key = os.environ.get("GOOGLE_API_KEY")
	if not api_key:
		return None
	return genai.Client(
		api_key=api_key,
		http_options=types.HttpOptions(timeout=TIMEOUT_MS),
	)


async def close_client(client: genai.Client | None) -> None:
	if client is None:
		return
	try:
		await client.aio.aclose()
	except Exception:
		_LOGGER.debug("Could not close Gemini client", exc_info=True)


async def generate_structured_response[ResponseT](
	client: genai.Client,
	contents: str,
	response_schema: types.Schema,
	validator: Callable[[str], ResponseT],
	*,
	model: str | None = None,
) -> ResponseT:
	"""Generate structured content through the shared client and validate it."""
	if client is None:
		raise RuntimeError("GOOGLE_API_KEY is not configured")
	selected_model = model or os.environ.get("GEMINI_MODEL", DEFAULT_MODEL)
	return await _generate_with_retry(
		client, selected_model, contents, response_schema, validator
	)


async def _generate_with_retry[ResponseT](
	client: genai.Client,
	model: str,
	contents: str,
	response_schema: types.Schema,
	validator: Callable[[str], ResponseT],
) -> ResponseT:
	last_error: Exception | None = None
	for attempt in range(RETRIES + 1):
		try:
			async with asyncio.timeout(LOCAL_TIMEOUT_SECONDS):
				response = await client.aio.models.generate_content(
					model=model,
					contents=contents,
					config=types.GenerateContentConfig(
						response_mime_type="application/json",
						response_schema=response_schema,
					),
				)
				if not response.text:
					raise ValueError("Gemini returned an empty response")
				return validator(response.text)
		except Exception as error:  # noqa: BLE001
			last_error = error
			if attempt == RETRIES:
				break
	if last_error is not None:
		raise RuntimeError(
			f"Gemini request failed after {RETRIES + 1} attempts"
		) from last_error
	raise RuntimeError("Gemini request failed without an error")

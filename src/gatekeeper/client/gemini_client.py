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
_client: genai.Client | None = None

async def generate_structured_response[ResponseT](
	contents: str,
	response_schema: types.Schema,
	validator: Callable[[str], ResponseT],
	*,
	model: str | None = None,
) -> ResponseT:
	"""Generate structured content and validate it, retrying failures once."""
	selected_model = model or os.environ.get("GEMINI_MODEL", DEFAULT_MODEL)
	api_key = os.environ.get("GOOGLE_API_KEY")
	if not api_key:
		raise RuntimeError("GOOGLE_API_KEY is not configured")
	return await _generate_with_retry(
		_get_client(api_key), selected_model, contents, response_schema, validator
	)


def _get_client(api_key: str) -> genai.Client:
	global _client
	if _client is None:
		_client = genai.Client(
			api_key=api_key,
			http_options=types.HttpOptions(timeout=TIMEOUT_MS),
		)
	return _client


async def close_gemini_client() -> None:
	global _client
	client, _client = _client, None
	if client is None:
		return
	try:
		await client.aio.aclose()
	except Exception:
		_LOGGER.debug("Could not close Gemini client", exc_info=True)


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

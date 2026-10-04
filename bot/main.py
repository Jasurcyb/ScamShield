"""Run ScamShield as a Telegram polling bot."""

from __future__ import annotations

import asyncio
import logging
import os
from concurrent.futures import ThreadPoolExecutor

from aiogram import Bot, Dispatcher
from aiogram.client.default import DefaultBotProperties
from aiogram.enums import ParseMode
from dotenv import load_dotenv

# Environment must be loaded before importing handlers: they expose the public
# support contact in the /privacy notice.
load_dotenv()

from bot.handlers import router


async def main() -> None:
    token = os.getenv("TELEGRAM_BOT_TOKEN")
    if not token or token.startswith("your_"):
        raise RuntimeError("TELEGRAM_BOT_TOKEN is not configured.")

    # The sync pipeline (LLM calls, PIL, forensics) runs in the default thread
    # pool; the conservative stdlib default is too small for bursts.
    loop = asyncio.get_running_loop()
    loop.set_default_executor(
        ThreadPoolExecutor(max_workers=int(os.getenv("THREAD_POOL_SIZE", "32")))
    )

    bot = Bot(token=token, default=DefaultBotProperties(parse_mode=ParseMode.HTML))
    dispatcher = Dispatcher()
    dispatcher.include_router(router)
    await dispatcher.start_polling(bot, allowed_updates=dispatcher.resolve_used_update_types())


if __name__ == "__main__":
    logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))
    asyncio.run(main())

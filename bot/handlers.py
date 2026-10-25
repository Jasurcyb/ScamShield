"""Telegram command and message handlers."""

from __future__ import annotations

import os

from aiogram import Bot, F, Router
from aiogram.enums import ChatAction
from aiogram.filters import Command, CommandStart
from aiogram.types import CallbackQuery, InlineKeyboardButton, InlineKeyboardMarkup, Message
from fastapi import HTTPException

from app import db
from app.security import MAX_UPLOAD_BYTES
from bot.localization import LANGUAGES, MODES, text
from bot.service import analyze_telegram_file, analyze_text_content, format_result
from bot.state import ChatState, check_rate, get_chat_state


router = Router(name="scamshield")
SUPPORT_CONTACT = os.getenv("SUPPORT_CONTACT", "не указан")
ANALYSES_PER_MINUTE = int(os.getenv("BOT_MAX_ANALYSES_PER_MINUTE", "10"))


def _language(message: Message) -> str:
    return get_chat_state(message.chat.id).language


def _language_keyboard() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [InlineKeyboardButton(text=label, callback_data=f"language:{code}")]
            for code, label in LANGUAGES.items()
        ]
    )


def _mode_keyboard(language: str) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [InlineKeyboardButton(text=text(language, f"mode_{code}"), callback_data=f"mode:{code}")]
            for code in MODES
        ]
    )


def _accept_keyboard(language: str) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        inline_keyboard=[[InlineKeyboardButton(text=text(language, "accept_terms"), callback_data="terms:accept")]]
    )


def _feedback_keyboard(scan_id: int, language: str) -> InlineKeyboardMarkup | None:
    """Feedback buttons under a result; None when persistence is off."""
    if not db.db_enabled():
        return None
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [
                InlineKeyboardButton(text=text(language, "fb_scam"), callback_data=f"fb:{scan_id}:scam"),
                InlineKeyboardButton(text=text(language, "fb_clean"), callback_data=f"fb:{scan_id}:clean"),
            ]
        ]
    )


async def _show_main_menu(message: Message, language: str) -> None:
    """Send the post-acceptance menu: mode keyboard plus the command reference."""
    await message.answer(
        f"{text(language, 'welcome')}\n\n{text(language, 'help')}\n\n"
        f"<i>{text(language, 'start_notice')}</i>",
        reply_markup=_mode_keyboard(language),
    )


async def _ensure_terms(message: Message) -> ChatState | None:
    """Return the chat state when terms are accepted; otherwise prompt and return None."""
    state = get_chat_state(message.chat.id)
    if not state.accepted_terms:
        await message.answer(
            text(state.language, "terms_required"),
            reply_markup=_accept_keyboard(state.language),
        )
        return None
    return state


@router.message(CommandStart())
async def start(message: Message) -> None:
    state = get_chat_state(message.chat.id)
    language = state.language
    if not state.accepted_terms:
        await message.answer(
            f"{text(language, 'welcome')}\n\n{text(language, 'terms_short')}",
            reply_markup=_accept_keyboard(language),
        )
        return
    await _show_main_menu(message, language)


@router.message(Command("help"))
async def help_command(message: Message) -> None:
    await message.answer(text(_language(message), "help"))


@router.message(Command("terms"))
async def terms_command(message: Message) -> None:
    state = get_chat_state(message.chat.id)
    language = state.language
    if state.accepted_terms:
        await message.answer(text(language, "terms"))
    else:
        await message.answer(text(language, "terms"), reply_markup=_accept_keyboard(language))


@router.message(Command("privacy"))
async def privacy_command(message: Message) -> None:
    """Show the pilot privacy notice before a user sends potentially sensitive content."""
    await message.answer(
        text(_language(message), "privacy", support_contact=SUPPORT_CONTACT)
    )


@router.message(Command("mode"))
async def mode_command(message: Message) -> None:
    state = await _ensure_terms(message)
    if state is None:
        return
    await message.answer(text(state.language, "choose_mode"), reply_markup=_mode_keyboard(state.language))


@router.message(Command("language"))
async def language_command(message: Message) -> None:
    state = get_chat_state(message.chat.id)
    await message.answer(text(state.language, "choose_language"), reply_markup=_language_keyboard())


@router.callback_query(F.data == "terms:accept")
async def accept_terms(callback: CallbackQuery) -> None:
    if callback.message is None:
        await callback.answer()
        return
    state = get_chat_state(callback.message.chat.id)
    state.accepted_terms = True
    language = state.language
    await callback.message.edit_text(text(language, "terms_accepted"))
    await _show_main_menu(callback.message, language)
    await callback.answer()


@router.callback_query(F.data.startswith("fb:"))
async def record_scan_feedback(callback: CallbackQuery) -> None:
    """Store the user's scam/not-scam feedback for the reported scan."""
    if callback.message is None or callback.data is None:
        await callback.answer()
        return
    try:
        _, scan_id_raw, verdict = callback.data.split(":", maxsplit=2)
        scan_id = int(scan_id_raw)
    except ValueError:
        await callback.answer()
        return

    language = get_chat_state(callback.message.chat.id).language
    if db.record_feedback(scan_id, verdict):
        await callback.message.edit_reply_markup(reply_markup=None)
        await callback.message.answer(text(language, "fb_saved"))
        await callback.answer()
    else:
        await callback.answer(text(language, "fb_failed"), show_alert=False)


@router.callback_query(F.data.startswith("language:"))
async def choose_language(callback: CallbackQuery) -> None:
    language = callback.data.split(":", maxsplit=1)[1]
    if language not in LANGUAGES or callback.message is None:
        await callback.answer()
        return
    state = get_chat_state(callback.message.chat.id)
    state.language = language
    await callback.message.edit_text(text(language, "language_saved", language=LANGUAGES[language]))
    await callback.message.answer(text(language, "choose_mode"), reply_markup=_mode_keyboard(language))
    await callback.answer()


@router.callback_query(F.data.startswith("mode:"))
async def choose_mode(callback: CallbackQuery) -> None:
    mode = callback.data.split(":", maxsplit=1)[1]
    if mode not in MODES or callback.message is None:
        await callback.answer()
        return
    state = get_chat_state(callback.message.chat.id)
    state.mode = mode
    language = state.language
    await callback.message.edit_text(
        text(language, "mode_selected", mode=text(language, f"mode_{mode}"))
        + "\n"
        + text(language, f"mode_hint_{mode}")
    )
    await callback.answer()


async def _send_analysis(message: Message, analysis) -> None:
    state = get_chat_state(message.chat.id)
    language = state.language
    if not check_rate(message.chat.id, ANALYSES_PER_MINUTE):
        await message.answer(text(language, "too_fast"))
        return
    await message.bot.send_chat_action(message.chat.id, ChatAction.TYPING)
    await message.answer(text(language, "processing"))
    try:
        result = await analysis
        keyboard = _feedback_keyboard(result.get("scan_id") or 0, language)
        await message.answer(format_result(result, language), reply_markup=keyboard)
    except ValueError as error:
        if str(error) == "unsupported_format":
            await message.answer(text(language, "unsupported"))
        elif str(error) == "file_too_large":
            await message.answer(text(language, "too_large", limit_mb=str(MAX_UPLOAD_BYTES // (1024 * 1024))))
        elif str(error) == "text_too_long":
            await message.answer(text(language, "too_long"))
        elif str(error) == "wrong_mode":
            await message.answer(
                text(language, "mode_mismatch", mode=text(language, f"mode_{state.mode}"))
                + " "
                + text(language, f"mode_hint_{state.mode}")
            )
        elif str(error) == "server_busy":
            await message.answer(text(language, "server_busy"))
        else:
            await message.answer(text(language, "failed"))
    except HTTPException as error:
        if error.status_code == 413:
            await message.answer(text(language, "too_large", limit_mb=str(MAX_UPLOAD_BYTES // (1024 * 1024))))
        else:
            await message.answer(text(language, "failed"))
    except Exception:
        await message.answer(text(language, "failed"))


@router.message(F.text & ~F.text.startswith("/"))
async def analyze_text(message: Message) -> None:
    state = await _ensure_terms(message)
    if state is None:
        return
    await _send_analysis(
        message,
        analyze_text_content(message.text, chat_id=message.chat.id, language=state.language, mode=state.mode),
    )


@router.message(F.photo)
async def analyze_photo(message: Message, bot: Bot) -> None:
    state = await _ensure_terms(message)
    if state is None:
        return
    largest_photo = message.photo[-1]
    await _send_analysis(
        message,
        analyze_telegram_file(
            bot,
            file_id=largest_photo.file_id,
            filename="telegram_photo.jpg",
            caption=message.caption,
            chat_id=message.chat.id,
            language=state.language,
            mode=state.mode,
        ),
    )


@router.message(F.document)
async def analyze_document(message: Message, bot: Bot) -> None:
    state = await _ensure_terms(message)
    if state is None:
        return
    document = message.document
    if document.file_size and document.file_size > MAX_UPLOAD_BYTES:
        language = state.language
        await message.answer(text(language, "too_large", limit_mb=str(MAX_UPLOAD_BYTES // (1024 * 1024))))
        return
    await _send_analysis(
        message,
        analyze_telegram_file(
            bot,
            file_id=document.file_id,
            filename=document.file_name or "uploaded_file",
            caption=message.caption,
            chat_id=message.chat.id,
            language=state.language,
            mode=state.mode,
        ),
    )


@router.message(F.audio)
async def analyze_audio(message: Message, bot: Bot) -> None:
    state = await _ensure_terms(message)
    if state is None:
        return
    audio = message.audio
    if audio.file_size and audio.file_size > MAX_UPLOAD_BYTES:
        language = state.language
        await message.answer(text(language, "too_large", limit_mb=str(MAX_UPLOAD_BYTES // (1024 * 1024))))
        return
    await _send_analysis(
        message,
        analyze_telegram_file(
            bot,
            file_id=audio.file_id,
            filename=audio.file_name or "telegram_audio.mp3",
            caption=message.caption,
            chat_id=message.chat.id,
            language=state.language,
            mode=state.mode,
        ),
    )


@router.message(F.voice)
async def analyze_voice(message: Message, bot: Bot) -> None:
    """Voice notes arrive as OGG/Opus; store under the supported .ogg extension."""
    state = await _ensure_terms(message)
    if state is None:
        return
    voice = message.voice
    if voice.file_size and voice.file_size > MAX_UPLOAD_BYTES:
        language = state.language
        await message.answer(text(language, "too_large", limit_mb=str(MAX_UPLOAD_BYTES // (1024 * 1024))))
        return
    await _send_analysis(
        message,
        analyze_telegram_file(
            bot,
            file_id=voice.file_id,
            filename="telegram_voice.ogg",
            caption=None,
            chat_id=message.chat.id,
            language=state.language,
            mode=state.mode,
        ),
    )


@router.message()
async def unsupported_content(message: Message) -> None:
    await message.answer(text(_language(message), "unsupported"))

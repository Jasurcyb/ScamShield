import os
import math
import zipfile
import rarfile
from PIL import Image
from mutagen import File
from mutagen.mp3 import MP3
from mutagen.id3 import ID3
from oletools.olevba import VBA_Parser
from PyPDF2 import PdfReader
import numpy as np
from scipy import signal
from pydub import AudioSegment
import re
import database

def check_metadata(file_path: str) -> dict:
# ... (keeping existing functions)
    """
    Ищет подозрительные теги (длинные строки > 150 символов) через Pillow.
    """
    try:
        with Image.open(file_path) as img:
            exif_data = img.getexif()
            if not exif_data:
                return {
                    "status": "ok",
                    "details": "Проверка метаданных: EXIF не найден, чисто."
                }
            
            anomalies = []
            for tag_id, value in exif_data.items():
                if isinstance(value, str) and len(value) > 150:
                    anomalies.append(f"Тег {tag_id} превышает 150 символов ({len(value)})")
                    
            if anomalies:
                return {
                    "status": "warning",
                    "details": f"Обнаружены аномалии в метаданных: {'; '.join(anomalies)}"
                }
            else:
                return {
                    "status": "ok",
                    "details": "Проверка метаданных завершена. Аномалий не обнаружено."
                }
    except IOError:
         return {
             "status": "ok",
             "details": "Файл не является изображением или не поддерживается PIL. Метаданные не проверены."
         }
    except Exception as e:
        return {"status": "error", "details": f"Ошибка при проверке метаданных: {e}"}

def check_audio_metadata(file_path: str) -> dict:
    """
    Проверяет аудио метаданные (MP3/WAV/etc) через mutagen.
    Если текстовое поле > 300 символов — подозрительно.
    """
    try:
        audio = File(file_path)
        if audio is None:
            return {
                "status": "ok",
                "details": "Аудиофайл не содержит стандартных тегов или формат не распознан. Метаданные не проверены."
            }

        anomalies = []
        # Проверяем все теги (в mutagen это обычно словарь)
        for tag in audio.tags or {}:
            # mutagen может возвращать списки значений для тега
            values = audio.tags[tag]
            if not isinstance(values, list):
                values = [values]
            
            for val in values:
                # Нас интересуют только строковые значения (текстовые теги)
                str_val = str(val)
                if len(str_val) > 300:
                    anomalies.append(f"Тег '{tag}' слишком длинный ({len(str_val)} симв.)")
        
        if anomalies:
            return {
                "status": "warning",
                "details": f"Обнаружены аномалии в аудио-тегах: {'; '.join(anomalies)}"
            }
        else:
            return {
                "status": "ok",
                "details": "Проверка аудио-метаданных завершена. Аномалий не обнаружено."
            }
    except Exception as e:
        return {"status": "error", "details": f"Ошибка при проверке аудио-метаданных: {e}"}

def check_word_macros(file_path: str) -> dict:
    """
    Анализирует Word-документы на наличие VBA-макросов через oletools.
    """
    if not file_path.lower().endswith(('.doc', '.docx')):
        return {"status": "ok", "details": "Не применимо для данного формата"}
    
    try:
        with open(file_path, "rb") as f:
            parser = VBA_Parser(file_path, data=f.read())
            if parser.detect_vba_macros():
                results = parser.analyze_macros()
                suspicious = []
                for kw_type, keyword, description in results:
                    if kw_type in ['Suspicious', 'AutoExec']:
                        suspicious.append(f"{keyword} ({description})")
                
                parser.close()
                if suspicious:
                    return {
                        "status": "warning",
                        "details": f"Обнаружены макросы/автозапуск: {'; '.join(suspicious[:3])}..."
                    }
                else:
                    return {
                        "status": "warning",
                        "details": "В документе есть VBA-макросы, но явных угроз не найдено. Будьте осторожны."
                    }
            parser.close()
            return {"status": "ok", "details": "Макросы не обнаружены."}
    except Exception as e:
        return {"status": "error", "details": f"Ошибка при анализе Word: {e}"}

def check_pdf_scripts(file_path: str) -> dict:
    """
    Ищет JavaScript и автоматические действия в PDF через PyPDF2.
    """
    if not file_path.lower().endswith('.pdf'):
        return {"status": "ok", "details": "Не применимо для данного формата"}
    
    try:
        with open(file_path, "rb") as f:
            reader = PdfReader(f)
            suspicious_keys = ['/JS', '/JavaScript', '/OpenAction', '/EmbeddedFiles']
            found = []
    
            # Проверяем структуру документа
            catalog = reader.trailer.get('/Root', {})
            for key in suspicious_keys:
                if key in catalog:
                    found.append(key)
            
            # Проверяем дополнительные вложения/имена
            names = catalog.get('/Names', {})
            if '/EmbeddedFiles' in names:
                found.append('/EmbeddedFiles')

        if found:
            return {
                "status": "warning",
                "details": f"Найдены активные элементы в PDF: {', '.join(found)}"
            }
        
        return {"status": "ok", "details": "Активные скрипты или вложения не обнаружены."}
    except Exception as e:
        return {"status": "error", "details": f"Ошибка при анализе PDF: {e}"}

def check_lsb_anomaly(file_path: str) -> dict:
    """
    Математический анализ LSB (младших битов) в синем канале изображения.
    """
    try:
        with Image.open(file_path) as img:
            img = img.convert('RGB')
            pixels = np.array(img)
            blue_channel = pixels[:, :, 2]
            lsbs = blue_channel % 2
            bits_count = lsbs.size
            ones_ratio = np.sum(lsbs) / bits_count
            is_suspicious = 0.499 < ones_ratio < 0.501 and bits_count > 10000
            
            if is_suspicious:
                return {
                    "status": "warning",
                    "details": f"LSB-аномалия: обнаружен неестественно равномерный шум ({round(ones_ratio*100, 2)}% бит)"
                }
            return {"status": "ok", "details": "LSB-анализ: аномалий не обнаружено."}
    except Exception as e:
        return {"status": "ok", "details": f"LSB-анализ пропущен: {e}"}

def calculate_entropy(file_path: str) -> dict:
    """
    Считает энтропию файла (если > 7.5 бит/байт — флаг опасности).
    """
    try:
        with open(file_path, "rb") as f:
            data = f.read()
        if not data:
            return {"status": "ok", "entropy": 0.0, "details": "Пустой файл"}

        byte_counts = [0] * 256
        for byte in data:
            byte_counts[byte] += 1
            
        entropy = 0.0
        for count in byte_counts:
            if count == 0:
                continue
            p = count / len(data)
            entropy -= p * math.log2(p)
            
        is_audio_stream = file_path.lower().endswith(('.ogg', '.mp3'))
        threshold = 7.99 if is_audio_stream else 7.5
        is_suspicious = entropy > threshold
        return {
            "status": "warning" if is_suspicious else "ok",
            "entropy": round(entropy, 2),
            "details": f"Энтропия: {round(entropy, 2)}. {'Высокая: риск наличия шифрованных/сжатых стегано-контейнеров' if is_suspicious else 'В норме'}"
        }
    except Exception as e:
        return {"status": "error", "error": str(e), "details": "Ошибка при вычислении энтропии"}

def check_trailing_data(file_path: str) -> dict:
    """
    Проверяет наличие данных после маркера конца файла (EOF).
    """
    try:
        with open(file_path, "rb") as f:
            data = f.read()

        has_trailing = False
        trailing_size = 0
        details = "Чисто"
        file_len = len(data)

        jpeg_eof = b'\xff\xd9'
        png_eof = b'\x49\x45\x4E\x44\xAE\x42\x60\x82'

        if jpeg_eof in data:
            pos = data.rfind(jpeg_eof)
            if file_len > pos + 2:
                has_trailing = True
                trailing_size = file_len - (pos + 2)
                details = f"Найдены данные после EOF ({trailing_size} байт)."
        elif png_eof in data:
            pos = data.rfind(png_eof)
            if file_len > pos + 8:
                has_trailing = True
                trailing_size = file_len - (pos + 8)
                details = f"Найдены данные после IEND ({trailing_size} байт)."
        elif data.startswith(b'OggS'):
            details = "OGG контейнер ок."
        else:
            details = "EOF не найден или формат не определен."

        # Исключение для технического шлейфа
        is_media = file_path.lower().endswith(('.ogg', '.mp3', '.wav', '.mp4', '.mov', '.jpg', '.jpeg', '.png'))
        has_technical_tail = False
        if has_trailing and is_media and trailing_size < 4096:
            has_trailing = False
            has_technical_tail = True
            details = f"Технический шум (ОК) - {trailing_size} байт."

        status = "warning" if has_trailing else "ok"
        return {"status": status, "details": details, "has_trailing": has_trailing, "has_technical_tail": has_technical_tail, "trailing_size": trailing_size}
    except Exception as e:
        return {"status": "error", "details": f"Ошибка EOF: {e}"}

def check_audio_spectrum(file_path: str) -> dict:
    """
    Спектральный анализ аудио: поиск ультразвуковых аномалий (> 16 кГц).
    """
    if not file_path.lower().endswith(('.mp3', '.ogg', '.wav')):
        return {"status": "ok", "details": "N/A"}
    
    try:
        # Загружаем аудио (придется временно декодировать в wav если это офф/мп3)
        audio = AudioSegment.from_file(file_path)
        samples = np.array(audio.get_array_of_samples())
        fs = audio.frame_rate
        
        # Вычисляем спектрограмму
        frequencies, times, Sxx = signal.spectrogram(samples, fs)
        
        # Ищем энергию выше 16000 Гц
        high_freq_mask = frequencies > 16000
        if np.any(high_freq_mask):
            high_freq_energy = np.mean(Sxx[high_freq_mask, :])
            total_energy = np.mean(Sxx)
            
            # Если энергия на высоких частотах значительно превышает фон
            if high_freq_energy > total_energy * 0.1: # Порог чувствительности
                return {
                    "status": "warning",
                    "details": "Спектральная аномалия: обнаружен подозрительный шум в ультразвуке (>16кГц)."
                }
        
        return {"status": "ok", "details": "Спектр чист."}
    except Exception as e:
        return {"status": "ok", "details": f"Спектральный анализ пропущен: {e}"}

def check_histogram_anomaly(file_path: str) -> dict:
    """
    Анализ гистограмм: поиск эффекта 'гребенки' (разрывы после LSB).
    """
    try:
        with Image.open(file_path) as img:
            hist = img.histogram() # Возвращает [R0..R255, G0..G255, B0..B255]
            
            # Проверяем каналы на наличие пустых ячеек между заполненными (гребенка)
            def find_gaps(channel_data):
                gaps = 0
                for i in range(1, len(channel_data)-1):
                    if channel_data[i] == 0 and channel_data[i-1] > 0 and channel_data[i+1] > 0:
                        gaps += 1
                return gaps

            r_gaps = find_gaps(hist[0:256])
            g_gaps = find_gaps(hist[256:512])
            b_gaps = find_gaps(hist[512:768])
            
            if r_gaps > 10 or g_gaps > 10 or b_gaps > 10:
                return {
                    "status": "warning",
                    "details": f"Гистограммная аномалия: обнаружен эффект 'гребенки' ({r_gaps+g_gaps+b_gaps} разрывов)."
                }
        return {"status": "ok", "details": "Гистограмма без разрывов."}
    except Exception:
        return {"status": "ok", "details": "N/A"}

def check_archive_contents(file_path: str) -> dict:
    """
    Анализ архивов (ZIP, RAR): поиск исполняемых вложений и двойных расширений.
    """
    ext = file_path.lower()
    
    # 1. Проверка неподдерживаемых форматов
    if ext.endswith(('.7z', '.tar', '.gz', '.bz2', '.xz')):
         return {
             "status": "warning", 
             "danger_level": 5, 
             "details": "⚠️ ВНИМАНИЕ: Формат архива не поддерживается для вскрытия. Внутри могут быть скрытые угрозы"
         }
         
    # 2. Определение доступности
    is_zip = zipfile.is_zipfile(file_path)
    is_rar = False
    
    # Пытаемся понять, RAR ли это (если расширение .rar)
    if ext.endswith('.rar'):
        try:
            is_rar = rarfile.is_rarfile(file_path)
        except Exception:
            pass

    if not is_zip and not is_rar:
        return {"status": "ok", "danger_level": 0, "details": "N/A - не поддерживаемый архив"}

    try:
        files = []
        if is_zip:
            with zipfile.ZipFile(file_path, 'r') as z:
                files = z.namelist()
        elif is_rar:
            with rarfile.RarFile(file_path, 'r') as r:
                files = r.namelist()

        danger_level = 0
        details_msgs = []
        status = "ok"

        # Ищем исполняемые файлы
        threats = [f for f in files if f.lower().endswith(('.exe', '.bat', '.scr', '.vbs', '.js', '.cmd', '.msi'))]
        if threats:
            danger_level += 10
            status = "danger"
            details_msgs.append(f"Исполняемый файл ({', '.join(threats)})")

        # Ищем двойные расширения (напр. photo.jpg.exe)
        double_ext_files = []
        for f in files:
            filename = os.path.basename(f)
            parts = filename.split('.')
            if len(parts) >= 3:
                if parts[-1].lower() in ('exe', 'bat', 'scr', 'cmd', 'vbs', 'js', 'msi', 'com', 'pif'):
                    double_ext_files.append(filename)

        if double_ext_files:
            danger_level += 10
            status = "danger"
            details_msgs.append(f"Двойное расширение ({', '.join(double_ext_files)})")

        if danger_level > 0:
             return {
                 "status": status,
                 "danger_level": danger_level,
                 "details": f"❌ КРИТИЧЕСКИ ОПАСНО: {'; '.join(details_msgs)}"
             }

        return {"status": "ok", "danger_level": 0, "details": f"Архив проверен ({len(files)} файлов), угроз нет."}

    except rarfile.NeedFirstVolume:
         return {"status": "error", "danger_level": 0, "details": "Это не первый том многотомного RAR-архива."}
    except rarfile.RarCannotExec:
         return {"status": "warning", "danger_level": 5, "details": "⚠️ Не удалось вскрыть RAR: требуется системный плагин (unrar)."}
    except Exception as e:
         return {"status": "error", "danger_level": 0, "details": f"Ошибка архива: {e}"}

def extract_lsb_payload(file_path: str) -> bytes:
    try:
        img = Image.open(file_path).convert('RGB')
        bits = np.array(img).flatten() & 1
        
        valid_len = (len(bits) // 8) * 8
        bits_clean = bits[:valid_len]
        
        # Вариант 1 (Прямой порядок битов MSB-first)
        bytes_normal = np.packbits(bits_clean).tobytes()
        
        # Вариант 2 (Обратный порядок битов LSB-first)
        bits_reshaped = bits_clean.reshape(-1, 8)
        bytes_reversed = np.packbits(np.fliplr(bits_reshaped)).tobytes()
        
        return bytes_normal + b" ||| " + bytes_reversed
    except Exception as e:
        return b""

def scan_artifacts(file_path: str) -> dict:
    """
    Глубокий поиск артефактов (CTF-флагов и триггер-слов) по массиву данных.
    """
    # Триггер-слова приходят из БД как bytes (из-за предыдущих фиксов), поэтому декодируем их в строки
    THREAT_WORDS_BYTES = database.get_trigger_words()
    threat_words_str = [w.decode('utf-8', errors='ignore') for w in THREAT_WORDS_BYTES]
    
    # Теперь ищем текстовые паттерны
    flag_pattern = re.compile(r'(?i)(?:flag|ctf|picoctf|htb|thm)(?:\{[^}]+\}|[:\-\s]+[a-zA-Z0-9_\@\!\?\$\-]+)')
    
    try:
        with open(file_path, "rb") as f:
            data = f.read(100 * 1024 * 1024).decode('utf-8', errors='ignore')

        lsb_text = ""
        if file_path.lower().endswith(('.png', '.bmp')):
            lsb_bytes = extract_lsb_payload(file_path)
            if lsb_bytes:
                lsb_text = lsb_bytes.decode('utf-8', errors='ignore')

        all_data = data + " ||| " + lsb_text
        
        ctf_flags = flag_pattern.findall(all_data)
        all_data_lower = all_data.lower()
        threats_found = [w for w in threat_words_str if w in all_data_lower]
        
        all_flags = list(set(ctf_flags))
        all_threats = list(set(threats_found))

        danger_level = 0
        details_msgs = []
        status = "ok"

        if all_flags:
            danger_level += 15
            status = "danger"
            details_msgs.append("CTF-флаги")
            
        if all_threats:
            danger_level += 20
            status = "danger"
            details_msgs.append("Критические ключевые слова")

        if lsb_text and (all_flags or all_threats):
            details_msgs.append("КРИТИЧЕСКИ: Найдены скрытые артефакты!")

        return {
            "status": status,
            "danger_level": danger_level,
            "details": f"Найдено: {', '.join(details_msgs)}" if details_msgs else "Артефактов не обнаружено.",
            "ctf_flags": all_flags,
            "threat_words": all_threats
        }
    except Exception as e:
        return {"status": "error", "danger_level": 0, "details": f"Ошибка сканирования артефактов: {e}"}


def calculate_final_verdict(lsb_res: dict, macro_res: dict, trailing_res: dict, entropy_res: dict, 
                            spectrum_res: dict = None, hist_res: dict = None, archive_res: dict = None, strings_res: dict = None) -> tuple:
    danger_score = 0
    
    # Базовые тесты
    if lsb_res.get('status') != 'ok': danger_score += 5
    if macro_res.get('status') != 'ok': danger_score += 10
    if trailing_res.get('status') != 'ok': danger_score += 4
    if entropy_res.get('status') != 'ok': danger_score += 1
    
    # Новые тесты (Форензика)
    if spectrum_res and spectrum_res.get('status') != 'ok': danger_score += 3
    if hist_res and hist_res.get('status') != 'ok': danger_score += 4
    if archive_res: danger_score += archive_res.get('danger_level', 0)
    if strings_res: danger_score += strings_res.get('danger_level', 0)
    
    # Критические угрозы
    is_critical = False
    critical_msg = ""
    if archive_res and archive_res.get('status') == 'danger':
        is_critical = True
        critical_msg = archive_res['details']
    if strings_res and strings_res.get('status') == 'danger':
        is_critical = True
        critical_msg = "❌ ОПАСНО. Обнаружен критический контент или флаги."
    if macro_res.get('status') != 'ok' and "AutoExec" in macro_res.get('details', ''):
        is_critical = True
        critical_msg = "❌ ОПАСНО. Обнаружен автозапуск кода."

    if is_critical:
        return "ОПАСНО", critical_msg, danger_score
    elif danger_score < 3:
        return "БЕЗОПАСЕН", "✅ БЕЗОПАСЕН. Файл прошел глубокую проверку.", danger_score
    else:
        return "АНОМАЛИЯ", f"⚠️ ОБНАРУЖЕНЫ АНОМАЛИИ ({danger_score} баллов). Требуется осторожность.", danger_score

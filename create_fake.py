from PIL import Image, ImageDraw, ImageFont

def _make_suspicious_screenshot(path: str) -> None:
    width, height = 480, 640
    img = Image.new("RGB", (width, height), color=(245, 245, 245))
    draw = ImageDraw.Draw(img)

    try:
        font_normal = ImageFont.truetype("arial.ttf", 16)
        font_bold = ImageFont.truetype("arialbd.ttf", 18)
        font_large = ImageFont.truetype("times.ttf", 32)
        font_small = ImageFont.truetype("arial.ttf", 11)
    except (OSError, IOError):
        font_normal = ImageFont.load_default()
        font_bold = font_normal
        font_large = font_normal
        font_small = font_normal

    draw.rectangle([(0, 0), (width, 56)], fill=(25, 118, 210))
    draw.text((20, 16), "✓ Transfer Confirmation", fill="white", font=font_bold)

    y = 80
    fields = [
        ("From:", "John A. Smith"),
        ("Account:", "4276 **** **** 8901"),
        ("To:", "UNKNOWN RECIPIENT"),
        ("Bank:", "ShadowBank International"),
        ("Date:", "06/12/2026"),
        ("Reference:", "TX-00000001"),
    ]
    for label, value in fields:
        draw.text((20, y), label, fill=(100, 100, 100), font=font_small)
        draw.text((120, y), value, fill=(30, 30, 30), font=font_normal)
        y += 34

    amount_y = y + 20
    draw.rectangle([(110, amount_y - 5), (440, amount_y + 40)], fill=(255, 255, 255))
    draw.text((20, amount_y + 4), "Amount:", fill=(100, 100, 100), font=font_small)
    draw.text((125, amount_y - 2), "$999,999.00", fill=(200, 30, 30), font=font_large)

    y2 = amount_y + 60
    draw.text((20, y2), "Processed:", fill=(100, 100, 100), font=font_small)
    draw.text((120, y2), "2025-13-45 28:99", fill=(30, 30, 30), font=font_normal)

    qr_x, qr_y = 320, y2 + 40
    draw.rectangle([(qr_x, qr_y), (qr_x + 100, qr_y + 100)], fill="black")
    
    import random
    random.seed(42)
    for _ in range(200):
        px = random.randint(qr_x + 2, qr_x + 98)
        py = random.randint(qr_y + 2, qr_y + 98)
        sz = random.randint(2, 6)
        draw.rectangle([(px, py), (px + sz, py + sz)], fill="white")

    draw.rectangle([(0, height - 50), (width, height)], fill=(240, 240, 240))
    draw.text(
        (20, height - 35),
        "⚠ This is NOT an official bank document",
        fill=(180, 50, 50),
        font=font_small,
    )

    img.save(path, format="PNG")

_make_suspicious_screenshot('fake_screenshot.png')
print('Done')

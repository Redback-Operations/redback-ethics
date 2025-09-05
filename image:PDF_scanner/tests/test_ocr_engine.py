from PIL import Image, ImageDraw
from ocr_engine import ocr_image, OCRConfig

def _make_test_img(text: str = "Hello OCR"):
    img = Image.new("RGB", (600, 200), "white")
    d = ImageDraw.Draw(img)
    d.text((50, 80), text, fill="black")
    return img

def test_basic_ocr():
    img = _make_test_img("Secret Key: ABCD")
    out = ocr_image(img, OCRConfig())
    assert "Secret" in out

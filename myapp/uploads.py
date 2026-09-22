"""Re-encode public images to discard active content and metadata."""

from io import BytesIO
from uuid import uuid4
from PIL import Image
from django.core.files.base import ContentFile


def clean_image(upload):
    if upload.size > 5 * 1024 * 1024:
        raise ValueError("Image exceeds 5 MB.")
    try:
        image = Image.open(upload)
        if (
            image.format not in {"PNG", "JPEG", "WEBP"}
            or image.width * image.height > 16_000_000
        ):
            raise ValueError("Unsupported image dimensions or type.")
        image.load()
        image = image.convert("RGB")
        out = BytesIO()
        image.save(out, format="JPEG", quality=90)
        return ContentFile(out.getvalue(), name=uuid4().hex + ".jpg")
    except (OSError, Image.DecompressionBombError) as exc:
        raise ValueError("Invalid image.") from exc

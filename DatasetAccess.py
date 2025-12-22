import zipfile

DATASET_ZIP = "dataset.zip"

def load_encrypted_image(image_id):
    with zipfile.ZipFile(DATASET_ZIP, "r") as z:
        ciphertext = z.read(f"image_{image_id}.bin")
        meta = z.read(f"image_{image_id}.meta").decode()

    lines = meta.splitlines()
    iv = bytes.fromhex(lines[0].split(":")[1].strip())
    mac = bytes.fromhex(lines[1].split(":")[1].strip())

    return ciphertext, iv, mac
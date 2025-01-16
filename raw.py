'script in Python che utilizza la libreria pytsk3 per analizzare un file in formato raw e cercare informazioni, inclusi file cancellati'

import pytsk3
import pyewf
import sys

def open_image(image_path):
    try:
        ewf_handle = pyewf.handle()
        ewf_handle.open(image_path)
        return ewf_handle
    except IOError as e:
        print(f"Errore nell'apertura dell'immagine: {e}")
        sys.exit(1)

def analyze_filesystem(image_handle):
    img_info = pytsk3.Img_Info(image_handle)
    fs_info = pytsk3.FS_Info(img_info)
    root_dir = fs_info.open_dir(path="/")

    for entry in root_dir:
        if entry.info.name.name in [b'.', b'..']:
            continue
        print(f"Nome: {entry.info.name.name.decode('utf-8')}")
        print(f"Tipo: {entry.info.meta.type}")
        print(f"Dimensione: {entry.info.meta.size}")
        print(f"Stato: {'Cancellato' if entry.info.meta.flags & pytsk3.TSK_FS_META_FLAG_UNALLOC else 'Allocato'}")
        print("-" * 40)

def main(image_path):
    image_handle = open_image(image_path)
    analyze_filesystem(image_handle)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Uso: python script.py <percorso_immagine>")
        sys.exit(1)
    image_path = sys.argv[1]
    main(image_path)

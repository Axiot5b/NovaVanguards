import os
import requests

# Configuración
SPELLS_URL = "https://ddragon.leagueoflegends.com/cdn/{version}/data/en_US/summoner.json"
SPELLS_IMAGE_BASE_URL = "https://ddragon.leagueoflegends.com/cdn/{version}/img/spell/"
VERSION = "15.2.1"  # Cambia esto por la versión actual del juego
OUTPUT_DIR = "spells_images"

# Crear el directorio para las imágenes si no existe
os.makedirs(OUTPUT_DIR, exist_ok=True)

def download_spell_images():
    # Descargar la lista de hechizos
    response = requests.get(SPELLS_URL.format(version=VERSION))
    if response.status_code != 200:
        print("Error al obtener los datos de los hechizos.")
        return

    spells_data = response.json()["data"]
    
    for spell_id, spell in spells_data.items():
        spell_image_url = SPELLS_IMAGE_BASE_URL.format(version=VERSION) + f"{spell['id']}.png"
        image_path = os.path.join(OUTPUT_DIR, f"{spell['id']}.png")

        # Descargar la imagen del hechizo
        img_response = requests.get(spell_image_url)
        if img_response.status_code == 200:
            with open(image_path, 'wb') as img_file:
                img_file.write(img_response.content)
            print(f"Descargada la imagen del hechizo {spell['id']}")
        else:
            print(f"Error al descargar la imagen del hechizo {spell['id']}")

if __name__ == "__main__":
    download_spell_images()
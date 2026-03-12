import pdfplumber
import os

# --- KONFIGURATION ---
# WICHTIG: Gib hier den exakten Namen des Ordners an,
# in dem die entpackten PDF-Dateien liegen.
dossier_pdf = 'Bericht' # <-- ÜBERPRÜFE DIESEN NAMEN!

# Wir erstellen einen neuen Ordner, um die extrahierten Texte zu speichern.
dossier_output = 'raw_texts'

# Erstelle den Output-Ordner, falls er noch nicht existiert.
if not os.path.exists(dossier_output):
    os.makedirs(dossier_output)
    print(f"Ordner '{dossier_output}' wurde erfolgreich erstellt.")

print(f"--- START DER INGESTION-PHASE ---")
print(f"Lese PDF-Dateien aus dem Ordner: '{dossier_pdf}'")

# Versuche, alle Dateien im PDF-Ordner aufzulisten.
try:
    dateien_im_ordner = os.listdir(dossier_pdf)
except FileNotFoundError:
    print(f"FEHLER: Der Ordner '{dossier_pdf}' wurde nicht gefunden. Bitte überprüfe den Namen und den Pfad.")
    exit() # Beendet das Skript, wenn der Ordner falsch ist.

# Gehe jede Datei im Ordner durch.
for dateiname in dateien_im_ordner:
    # Stelle sicher, dass es sich wirklich um eine PDF-Datei handelt.
    if dateiname.lower().endswith('.pdf'):
        # Baue den vollständigen Pfad zur PDF-Datei zusammen.
        kompletter_pfad_pdf = os.path.join(dossier_pdf, dateiname)
        print(f"Verarbeite Datei: {dateiname}...")

        try:
            # Öffne die PDF-Datei mit pdfplumber.
            with pdfplumber.open(kompletter_pfad_pdf) as pdf:
                gesamter_text = ""
                # Gehe jede Seite in der PDF durch.
                for seite in pdf.pages:
                    # Extrahiere den Text von der aktuellen Seite.
                    text_der_seite = seite.extract_text()
                    if text_der_seite:
                        gesamter_text += text_der_seite + "\n"

            # Erstelle den Namen für die neue Textdatei (z.B. datei.pdf -> datei.txt).
            output_dateiname = dateiname.replace('.pdf', '.txt').replace('.PDF', '.txt')
            kompletter_pfad_output = os.path.join(dossier_output, output_dateiname)

            # Speichere den gesamten extrahierten Text in der neuen .txt-Datei.
            with open(kompletter_pfad_output, 'w', encoding='utf-8') as f:
                f.write(gesamter_text)
            
            print(f" -> Text extrahiert und gespeichert in: {kompletter_pfad_output}")

        except Exception as e:
            print(f" !!! FEHLER bei der Verarbeitung von {dateiname}: {e}")

print(f"--- INGESTION-PHASE BEENDET ---")
print(f"Alle PDF-Dateien wurden verarbeitet. Der Rohtext befindet sich im Ordner '{dossier_output}'.")
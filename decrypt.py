import typer, os, time
from rich import print
from typing_extensions import Annotated
from pathlib import Path
from utils import get_vault_path,  decrypt_file_aes, decrypt_message_rsa

app = typer.Typer()

@app.command()
def asymmetric(
    file: Annotated[Path, typer.Argument(..., help="path to input encrypted file")],
    key: Annotated[Path, typer.Argument(..., help="PATH or ALIAS of private key file")],
    output: Annotated[Path, typer.Argument(..., help="path to save decrypted file")],
):
    """
    Decrypts a file encrypted using AES + RSA.
    """
    try:
        # get key path
        key_path = Path(get_vault_path("keys")).joinpath(f"PRIVKEY_{key}.pem")
        if(not key_path.exists()): key_path = Path(key)
        if(not key_path.exists()): raise typer.BadParameter(f"Key file {key} not found.")

        # Decrypt AES key using RSA private key
        aes_key_path = Path(file).with_name("aes.key")
        decrypted_aes_key_path = Path(file).with_name("aes_decrypted.key")
        with open(aes_key_path, "rb") as f:
            ciphertext = f.read()
        aes_key = decrypt_message_rsa(ciphertext, key_path, decrypted_aes_key_path)

        # Decrypt file using decrypted AES key
        decrypt_file_aes(file, aes_key_path.read_bytes(), output)
        print(f":white_check_mark: Decryption successful. File saved to {output}")

    except Exception as e:
        print(f":no_entry: [bold red]Error:[/bold red] Could not decrypt file.\n{e}")
        raise typer.Exit("Exited with status code 1.")

if __name__ == "__main__":
    app()

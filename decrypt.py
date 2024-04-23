import typer, os, time, json
from rich import print
from typing_extensions import Annotated
from pathlib import Path
import utils

app = typer.Typer()

@app.command()
def rsa(
    file: Annotated[Path, typer.Argument(..., help="path to received ZIP archive")],
    key: Annotated[Path, typer.Argument(..., help="PATH or ALIAS of private key file")],
    out: Annotated[Path, typer.Argument(..., help="path to directory for output file")],
):
    """
    decrypts hybrid encrypted file, AES + RSA
    """
    try:
        # get key path
        key_path = Path(utils.get_vault_path("keys")).joinpath(key).joinpath(f"PRIVKEY_{key}.pem")
        if(not key_path.exists()): key_path = Path(key)
        if(not key_path.exists()): raise typer.BadParameter(f"Key file {key} not found.")

        # unpack export contents
        if(file.suffix != ".zip"): raise typer.BadParameter("File must be a ZIP archive.")
        alias = file.stem
        project_path = Path(utils.get_vault_path("imports")).joinpath(alias)
        utils.decompress_folder(file, project_path)
        print(f":white_check_mark: 1/3 unpacked archive and saved to vault")

        # Decrypt AES key using RSA private key
        aes_key_path = Path(project_path).joinpath(f"AESKEY_{alias}.key")
        ciphertext = aes_key_path.read_bytes()
        aes_key = utils.decrypt_message_rsa(ciphertext, key_path)
        print(f":white_check_mark: 2/3 decrypted AES key")

        # load file metadata
        metadata = open(project_path.joinpath(f"METADATA_{alias}.json"), "r").read()
        metadata = json.loads(metadata)

        # prepare output file path
        if(out.is_dir()): out_path = out.joinpath(f"{metadata['stem']}{metadata['suffix']}")
        else: raise typer.BadParameter("Output path must be a directory!")

        # Decrypt file using decrypted AES key
        utils.decrypt_file_aes(project_path.joinpath(f"ENC_{alias}.enc"), aes_key, out_path)
        print(f":white_check_mark: 3/3 saved decrypted file to {out_path}")

    except Exception as e:
        print(f":no_entry: [bold red]Error:[/bold red] Could not decrypt file.\n{e}")
        raise typer.Exit(1)

if __name__ == "__main__":
    app()

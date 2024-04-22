import typer, os
from rich import print
from typing_extensions import Annotated
from pathlib import Path
import utils

app = typer.Typer()

@app.command()
def asymmetric(
    file: Annotated[Path, typer.Argument(..., help="path to input file")],
    key: Annotated[Path, typer.Argument(..., help="PATH or ALIAS of public key file")],
    alias: Annotated[Path, typer.Option(..., help="name the project or export")] = os.urandom(4).hex(),
    algo: Annotated[str, typer.Option(help="currently supports RSA or ECC")] = "RSA",
):
    """
    uses hybrid encryption on files, AES + [RSA | ECC]
    """
    try:
        # get key path
        key_path = Path(utils.get_vault_path("keys")).joinpath(f"PUBKEY_{key}.pub")
        if(not key_path.exists()): key_path = Path(key)
        if(not key_path.exists()): raise typer.BadParameter(f"Key file {key} not found.")

        # get output path
        out_path = Path(utils.get_vault_path("projects").joinpath(alias))
        out_path.mkdir(parents=True, exist_ok=False)

        # generate 32 byte key for AES
        aes_key = os.urandom(32)
        # encrypt the file with AES
        utils.encrypt_file_aes(file, aes_key, out_path)
        print(f":white_check_mark: 1/3 saved encrypted file to {out_path}/{file.name}.enc")

        # encrypt AES key with RSA
        utils.encrypt_message_rsa(aes_key, key_path, out_path)
        print(f":white_check_mark: 2/3 saved encrypted AES key to {out_path}/aes.key")

        # package the files for transfer
        utils.compress_folder(alias, out_path)
        print(f":white_check_mark: 3/3 saved compressed archive to {os.getcwd()}/{alias}.zip")

    except Exception as e:
        print(f":no_entry: [bold red]Error:[/bold red] Could not encrypt file.\n{e}")
        raise typer.Exit(1)



if __name__ == "__main__":
    app()

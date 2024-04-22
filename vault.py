import typer
import keys, encrypt, decrypt

app = typer.Typer()
# key management app
app.add_typer(keys.app, name="keys", help="generate, store and manage keys")
# file encryption app
app.add_typer(encrypt.app, name="encrypt", help="encrypt a file using a key")
# file decryption app
app.add_typer(decrypt.app, name="decrypt", help="decrypt a file using a key")

if __name__ == "__main__":
    app()

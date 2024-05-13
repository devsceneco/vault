import boto3, utils, json
from botocore.utils import ClientError
import typer, requests
from pathlib import Path
from rich import print
from botocore.client import Config

DEFAULT_REGION = "ap-south-1"

def create_bucket(bucket_name: str, region=DEFAULT_REGION) -> None:
    """
    creates a new s3 bucket
    """
    try:
        # get credentials
        creds = get_credentials()
        id = creds["accessKey"]["access_key_id"]
        secret = creds["accessKey"]["secret_access_key"]

        # create bucket
        s3 = boto3.client("s3", region_name=region, aws_access_key_id=id, aws_secret_access_key=secret)
        s3.create_bucket(Bucket=bucket_name, CreateBucketConfiguration={'LocationConstraint': region})

    except Exception as e:
        print(f":no_entry: [bold red]Error:[/bold red] Could not create bucket.\n{e}")
        raise typer.Exit(1)

def upload_file(file_path: Path, region=DEFAULT_REGION) -> None:
    """
    uploads a file to s3 bucket
    """
    try:
        # get credentials
        creds = get_credentials()
        id = creds["accessKey"]["access_key_id"]
        secret = creds["accessKey"]["secret_access_key"]
        bucket_name = creds["accessKey"]["bucket_name"]

        # upload file
        s3 = boto3.client("s3", region_name=region, aws_access_key_id=id, aws_secret_access_key=secret)
        with open (file_path, "rb") as f:
            s3.upload_fileobj(f, bucket_name, file_path.name)

    except Exception as e:
        print(f":no_entry: [bold red]Error:[/bold red] Could not upload file to S3.")
        raise typer.Exit(1)

def get_presigned_url(key: str, region=DEFAULT_REGION) -> str:
    """
    returns a presigned URL for a file in s3 bucket
    """
    try:
        # get credentials
        creds = get_credentials()
        id = creds["accessKey"]["access_key_id"]
        secret = creds["accessKey"]["secret_access_key"]
        bucket_name = creds["accessKey"]["bucket_name"]

        # get presigned URL
        s3 = boto3.client(
            "s3",
            endpoint_url=f"https://s3.{region}.amazonaws.com",
            region_name=region,
            aws_access_key_id=id,
            aws_secret_access_key=secret
        )
        url = s3.generate_presigned_url(
            ClientMethod='get_object',
            Params={'Bucket': bucket_name, 'Key': key},
            ExpiresIn=600
        )

        return url
    except Exception as e:
        print(f":no_entry: [bold red]Error:[/bold red] Could not get presigned URL.")
        raise typer.Exit(1)

def get_credentials() -> dict:
    """
    returns AWS credentials
    """
    try:
        # get credentials
        creds_path = Path(utils.get_vault_path(".config")).joinpath("awsconfig.json")
        if not creds_path.exists():
            raise Exception(f"Credentials not found: {creds_path}")

        # read credential file
        with open(creds_path, "r") as f:
            creds = json.load(f)
            return creds

    except Exception as e:
        print(f":no_entry: [bold red]Error:[/bold red] Could not get AWS credentials.\n:bulb: [bold green]Hint:[/bold green] try running [bold green]vault config aws[/green bold]")
        raise typer.Exit(1)

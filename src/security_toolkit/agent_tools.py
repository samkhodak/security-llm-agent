from .validating_models import UrlInput, FilenameInput, ValidationError
from langchain_core.tools import tool
from pprint import pprint, pformat
import vt
from dotenv import load_dotenv
import os
import hashlib
import requests
import ujson
from time import sleep


load_dotenv()
virustotal_api_key = os.getenv("VS_TOTAL_API_KEY")    


# ==== Utilities ====

def collect_url_info(result):
    url_info = {
        "category": result.get("categories", "None for this URL."),
        "last_analysis_stats": result.get("last_analysis_stats", "None for this URL."),
        "community_votes": result.get("total_votes", "None for this URL."),
    }
    return pformat(url_info, indent=2, sort_dicts=False)


def collect_file_info(result):
    file_info = {
        "hash": result.get("sha256", None),
        "names": result.get("names", [])[:4],
        "last_stats": result.get("last_analysis_stats", "None for this file."),
        "threat_class": result.get("popular_threat_classification", "None for this file."),
    }
    return pformat(file_info, indent=2, sort_dicts=False)


def get_analysis(analysis_id, headers):
    analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
    analysis_response = requests.get(analysis_url, headers=headers)
    analysis = ujson.loads(analysis_response.text)
    status = analysis.get("data").get("attributes").get("status")

    return status, analysis


def upload_file(filename):
    scan_url = "https://www.virustotal.com/api/v3/files"

    headers = {
        "accept": "application/json",
        "x-apikey": virustotal_api_key
    }

    try:
        with open(f"./{filename}", "rb") as file:
            files = { "file": (filename, file, "text/x-python") }
            scan_response = requests.post(scan_url, files=files, headers=headers)
    except FileNotFoundError as error:
        print(vars(error.strerror))
        raise ValueError("File not found. Please make sure the file you're looking to scan is in the current directory.")


    analysis_id = scan_response.json().get("data", {}).get("id")
    print(analysis_id)

    # After posting file contents, we need to wait until the status code is "completed". 
    # analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
    # analysis_response = requests.get(analysis_url, headers=headers)
    # analysis = ujson.loads(analysis_response.text)
    # status = analysis.get("data").get("attributes").get("status")
    status, analysis = get_analysis(analysis_id, headers)

    timeout = 300  # Seconds
    interval = 5
    seconds = 0
    # TODO: simplify, move to function?
    while((status != "completed") and (seconds < timeout)):
        print("Waiting for file scan to complete... Please standby.")
        sleep(interval)
        seconds += interval
        status, analysis = get_analysis(analysis_id, headers)
        # analysis_response = requests.get(analysis_url, headers=headers)
        # analysis = ujson.loads(analysis_response.text)
        # status = analysis.get("data", {}).get("attributes", {}).get("status")

    if (status != "completed"):
        raise RuntimeError("The scan timed out. Due to unknown API delay, the file could not be scanned completely.")

    file_info = analysis.get("meta", {}).get("file_info", {})
    return file_info.get("sha_256")



# ==== Tools ====

@tool("check_url_safety", return_direct=False)
def check_url_safety(url):
    """
    Given a hostname URL, will return a concise dictionary of information on the security of the URL.
    """
    try:
        validated_url = UrlInput(url=url).url
    except ValidationError as ve:
        error = ve.errors()[0]
        raise ValueError(error.get("msg")[13:])

    url_id = vt.url_id(validated_url)
    with vt.Client(virustotal_api_key) as client:
        try:
            url_analysis = client.get_object("/urls/{}", url_id)
        except Exception as error:
            # vt-py does not provide specific error types to except, so we must manually check.
            if (error.code == "NotFoundError"):
                print("\n\n\nThis url is not in the VirusTotal database yet. Scanning - may take a minute.....\n\n\n")
                url_analysis = client.scan_url(url, wait_for_completion=True)
            else:
                raise

    return collect_url_info(url_analysis)


@tool("get_file_info", return_direct=False)
def get_file_info(filename):
    """
    Given a filename, will get security information on whether the file is safe or not. The information will have potential
    malware names/hashes, stats on whether the file was rated as malicious, and the threat classification of the file once it is scanned.
    """
    try:
        validated_filename = FilenameInput(file_name=filename).file_name
    except ValidationError as ve:
        error = ve.errors()[0]
        raise ValueError(error.get("msg")[13:])

    # 128 kb in binary
    kb_120 = 131072 
    sha256_hasher = hashlib.new('sha256')

    try:
        file = open(f"./{validated_filename}", "rb")
    except FileNotFoundError:
        raise ValueError("File not found. Please make sure the file you're looking to scan is in the current directory.")

    # First, hash file to check if it's already in vt database.
    while True:
        bytes = file.read(kb_120)
        if not bytes:
            break
        sha256_hasher.update(bytes)
    file_hash = sha256_hasher.hexdigest()

    # Request file info if it exists, and upload the file if not.
    with vt.Client(apikey=virustotal_api_key, timeout=500) as client:
        try: 
            file_analysis = client.get_object("/files/{}", file_hash)

        except Exception as error:
            if (error.code == "NotFoundError"):
                print("\n\n\nThis file's hash is not in the VirusTotal database yet. Scanning - may take a minute.....\n\n\n")
                file_hash = upload_file(validated_filename)                  
                file_analysis = client.get_object("/files/{}", file_hash)
            else:
                raise
    
    file.close()
        
    return collect_file_info(file_analysis)


            
    

from .validating_models import UrlInput, FilenameInput, ValidationError
from langchain_core.tools import tool
from pprint import pprint, pformat
import vt
from dotenv import load_dotenv
import os
import hashlib
import requests
import ujson
import traceback
from time import sleep


load_dotenv()
virustotal_api_key = os.getenv("VS_TOTAL_API_KEY")    


# ==== Utilities ====

def collect_url_info(url_report: dict) -> dict:
    """ Collect file info from url report into a concise dictionary. 

    :param file_report: Dictionary of url info
    :type file_report: dict
    :return: Dictionary of security statistics for url. 
    :rtype: dict
    """
    url_info = {
        "category": url_report.get("categories", "None for this URL."),
        "last_analysis_stats": url_report.get("last_analysis_stats", "None for this URL."),
        "community_votes": url_report.get("total_votes", "None for this URL."),
    }
    return pformat(url_info, indent=2, sort_dicts=False)


def collect_file_info(file_report: dict) -> dict:
    """ Collect file info from file report into a concise dictionary. 

    :param file_report: Dictionary of file info 
    :type file_report: dict
    :return: Dictionary of security-related info for file.
    :rtype: dict
    """
    attributes = file_report.get("data", {}).get("attributes", {})
    file_info = {
        "hash": attributes.get("sha256", None),
        "names": attributes.get("names", [])[:4],
        "last_stats": attributes.get("last_analysis_stats", "None for this file."),
        "threat_class": attributes.get("popular_threat_classification", "None for this file."),
    }
    return pformat(file_info, indent=2, sort_dicts=False)


def get_file_analysis(analysis_id: str, headers: dict) -> tuple[str,dict]:
    """ Query virustotal analysis endpoint to check if analysis is done, and return analysis.

    :param analysis_id: ID of analysis in progress.
    :type analysis_id: str
    :param headers: Dictionary of header values for API
    :type headers: dict
    :return: status code and dictionary of analysis info.
    :rtype: tuple(str, dict)
    """
    analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
    analysis_response = requests.get(analysis_url, headers=headers)
    analysis = ujson.loads(analysis_response.text)
    status = analysis.get("data").get("attributes").get("status")

    return status, analysis


def retrieve_file_report(sha256: str) -> dict:
    """ Retrieve file report for a specific file hash.

    :param sha256: sha-256 hash for file.
    :type sha256: str
    :raises RuntimeError: If file is not yet in database, throw error in order to catch and scan the file.
    :return: Dictionary of file report details from response.
    :rtype: dict 
    """
    url = f"https://www.virustotal.com/api/v3/files/{sha256}"
    headers = {
        "accept": "application/json",
        "x-apikey": virustotal_api_key 
    }

    response = requests.get(url, headers=headers)
    if (response.status_code == 404):
        raise RuntimeError("This file's hash is not in the VirusTotal database.")
        
    file_report = ujson.loads(response.text)
    return file_report 
    


def upload_file(filename: str) -> str:
    """ Uploads a file to virustotal api and displays while looping until analysis is complete.

    :param filename: Name of file from current directory to scan.
    :type filename: str
    :raises ValueError: If file doesn't exist in curent directory, error thrown.
    :raises RuntimeError: If API scan exceeds preset timeout, error thrown.
    :return: sha-256 hash of uploaded file.
    :rtype: str
    """
    scan_url = "https://www.virustotal.com/api/v3/files"
    headers = {
        "accept": "application/json",
        "x-apikey": virustotal_api_key
    }

    try:
        with open(f"./{filename}", "rb") as file:
            files = { "file": (filename, file, "text/x-python") }
            scan_response = requests.post(scan_url, files=files, headers=headers)
    except FileNotFoundError:
        raise ValueError("File not found. Please make sure the file you're looking to scan is in the current directory.")


    analysis_id = scan_response.json().get("data", {}).get("id")
    status, analysis = get_file_analysis(analysis_id, headers)

    timeout = 500  # Seconds
    request_interval = 5
    seconds = 0
    while((status != "completed") and (seconds < timeout)):
        if (seconds % (request_interval*2) == 0): # Display every (interval*2) seconds.
            print(f"Waiting for file scan to complete... Please standby. ({seconds} seconds)")
        sleep(request_interval)
        seconds += request_interval
        status, analysis = get_file_analysis(analysis_id, headers)

    if (status != "completed"):
        raise RuntimeError("Due to API delay, your scan timed out. Please try again later.")

    file_info = analysis.get("meta", {}).get("file_info", {})
    return file_info.get("sha256")


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
        raise ValueError(error.get("msg")[13:]) # ValidationError returns a partly ugly string for our purposes.

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
    with vt.Client(apikey=virustotal_api_key, timeout=1000) as client:
        try: 
            file_report = retrieve_file_report(file_hash)

        except RuntimeError as exception:
            print(f"\n\n{str(exception)} Scanning file - may take a minute...\n")
            file_sha256 = upload_file(validated_filename)
            file_report = retrieve_file_report(file_sha256) 

    file.close()
    return collect_file_info(file_report)


            
    

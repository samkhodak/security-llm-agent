from .validating_models import UrlInput, FilenameInput
from langchain_core.tools import tool
from pprint import pprint, pformat
import vt
from dotenv import load_dotenv
import os
import traceback
import hashlib
import requests
import ujson
from time import sleep


load_dotenv()
virustotal_api_key = os.getenv("VS_TOTAL_API_KEY")    

def collect_url_info(result):
    url_categories = result.categories
    _, sample_category = url_categories.popitem()
    url_info = {
        "category": sample_category,
        "last_analysis_stats": result.last_analysis_stats,
        "community_votes": result.total_votes
    }
    return pformat(url_info, indent=2, sort_dicts=False)

@tool("check_url_safety", args_schema=UrlInput, return_direct=False)
def check_url_safety(url):
    """
    Given a hostname URL, will return a concise dictionary of information on the security of the URL.
    """
    url_id = vt.url_id(url)
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


def upload_file(filename):

    scan_url = "https://www.virustotal.com/api/v3/files"

    headers = {
        "accept": "application/json",
        "x-apikey": virustotal_api_key
    }

    with open(f"./{filename}", "rb") as file:

        files = { "file": (filename, file, "text/x-python") }
        scan_response = requests.post(scan_url, files=files, headers=headers)

    analysis_id = scan_response.json().get("data").get("id")
    print(analysis_id)
    
    analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
    analysis_response = requests.get(analysis_url, headers=headers)
    analysis = ujson.loads(analysis_response.text)
    status = analysis.get("data").get("attributes").get("status")

    timeout = 150
    interval = 5
    seconds = 0
    while((status != "completed") and (seconds < timeout)):
        print("Waiting for file scan to complete... Please standby.")
        sleep(interval)
        seconds += interval
        analysis_response = requests.get(analysis_url, headers=headers)
        analysis = ujson.loads(analysis_response.text)
        status = analysis.get("data", {}).get("attributes", {}).get("status")

    if (seconds >= timeout):
        print("Sorry, the scan timed out.")

    file_info = analysis.get("meta", {}).get("file_info", {})
    return file_info.get("sha_256")


        

    
    



@tool("get_file_info", args_schema=FilenameInput, return_direct=False)
def get_file_info(filename):
    """
    Given a filename, will get security information on whether the file is safe or not.
    """

    # os.path will return nothing if path ends with '/' on unix systems.
    if (filename[-1] == '/' or filename[-1] == '\\'):
        filename = filename[:-1]

    final_filename = os.path.basename(filename)

    if not final_filename:
        raise ValueError("Invalid filename.")

    # 128 kb in binary
    kb_120 = 131072 
    sha256_hasher = hashlib.new('sha256')

    with open(f"./{final_filename}", "rb") as file:

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
                    file_hash = upload_file(final_filename)                  
                    file_analysis = client.get_object("/files/{}", file_hash)
                else:
                    raise

            pprint(vars(file_analysis))
            pprint(type(file_analysis))
            
    

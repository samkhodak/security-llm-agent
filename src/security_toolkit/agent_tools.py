from .validating_models import UrlInput, FilenameInput
from langchain_core.tools import tool
from pprint import pprint, pformat
import vt
from dotenv import load_dotenv
import os
import traceback
import hashlib


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

    
    # 120 kb in binary
    kb_120 = 131072 
    sha256_hasher = hashlib.new('sha256')

    with open(f"./{final_filename}", "rb") as file:
        while True:
            bytes = file.read(kb_120)
            if not bytes:
                break
            sha256_hasher.update(bytes)
        
        file_hash = sha256_hasher.hexdigest()

        print(file_hash)

        with vt.Client(virustotal_api_key) as client:
            try: 
                file_analysis = client.get_object("/files/{}", file_hash)
            except Exception as error:
                if (error.code == "NotFoundError"):
                    print("\n\n\nThis file's hash is not in the VirusTotal database yet. Scanning - may take a minute.....\n\n\n")
                    
                    file_analysis = client.scan_file(file, wait_for_completion=True)

                else:
                    raise

            pprint(vars(file_analysis))
            pprint(type(file_analysis))
            
    

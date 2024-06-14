from .validating_models import UrlInput, FilenameInput, ValidationError
from .utilities import (collect_url_info, collect_file_info, retrieve_file_report, scan_file)
from langchain_core.tools import tool
from pprint import pformat
from langchain_openai import ChatOpenAI
from langchain_anthropic import ChatAnthropic
from dotenv import load_dotenv
import vt
import os
import hashlib



load_dotenv()
virustotal_api_key = os.getenv("VS_TOTAL_API_KEY")    

gpt_llm = ChatOpenAI(model='gpt-4o', temperature=0)
claude_llm = ChatAnthropic(model="claude-3-sonnet-20240229")



# ==== Security Tools ====

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

    collected_url_info = collect_url_info(url_analysis)
    return pformat(collected_url_info, indent=4, sort_dicts=False)


@tool("analyze_file", return_direct=False)
def analyze_file(filename):
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
            file_sha256 = scan_file(validated_filename)
            file_report = retrieve_file_report(file_sha256) 

    file.close()

    collected_info = collect_file_info(file_report)
    return pformat(collected_info, indent=4, sort_dicts=False)


            
    

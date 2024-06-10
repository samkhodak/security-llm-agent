from .validating_models import HostNameInput, DocumentFilename
from langchain_core.tools import tool
from pprint import pprint, pformat
import vt
from dotenv import load_dotenv
import os


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

@tool("check_url_safety", args_schema=HostNameInput, return_direct=False)
def check_url_safety(url):
    """
    Given a hostname URL, will return a concise dictionary of information on the security of the URL.
    """
    url_id = vt.url_id(url)
    with vt.Client(virustotal_api_key) as client:
        try:
            search_result = client.get_object("/urls/{}", url_id)
        except Exception:
            print("\n\n\nThis url is not in the VirusTotal database yet. Scanning - may take a minute.....\n\n\n")
            search_result = client.scan_url(url, wait_for_completion=True)

        return collect_url_info(search_result)
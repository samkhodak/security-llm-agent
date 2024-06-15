from langchain.agents import AgentExecutor, create_react_agent
from langchain_community.agent_toolkits.load_tools import load_tools
from langchain import hub
from langchain_openai import ChatOpenAI
from langchain_anthropic import ChatAnthropic
from time import sleep
from dotenv import load_dotenv
import os
import requests
import ujson



load_dotenv()
virustotal_api_key = os.getenv("VS_TOTAL_API_KEY")    

gpt_llm = ChatOpenAI(model='gpt-4o', temperature=0)
claude_llm = ChatAnthropic(model="claude-3-sonnet-20240229")



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
    return url_info



def collect_file_info(file_report: dict) -> dict:
    """ Parse file info from file report into a concise dictionary. 

    :param file_report: Dictionary of file info 
    :type file_report: dict
    :return: Dictionary of security-related info for file.
    :rtype: dict
    """
    attributes = file_report.get("data", {}).get("attributes", {})

    file_hash = attributes.get("sha256", None)
    last_stats = attributes.get("last_analysis_stats", "None for this file.")
    popular_threat_stats = attributes.get("popular_threat_classification", {})

    popular_threat_names = popular_threat_stats.get("popular_threat_name", "None for this file.")
    popular_threat_categories = popular_threat_stats.get("popular_threat_category", "None for this file.")

    # Potential threat is the most likely name and threat type for the file.
    try:
        threat_name = popular_threat_names[0].get("value", None)
        threat_category = popular_threat_categories[0].get("value", None)
        potential_threat = [f"{threat_name} - {threat_category}"]
    except (KeyError, AttributeError): 
        potential_threat = None
        pass
    
    file_info = {
        "hash": file_hash,
        "last_stats": last_stats, 
        "popular_threat_categories": popular_threat_categories,
        "popular_threat_names": popular_threat_names,
    }

    # If the file is likely malware and has a potential threat, research and add an explanation of malware to the dict.
    if (potential_threat):
        malware_explanation = search_malware_info(potential_threat)
        file_info.update({"potential_explanation_of_malware": malware_explanation})

    return file_info



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
        "x-apikey": virustotal_api_key,
    }

    response = requests.get(url, headers=headers)
    if (response.status_code == 404):
        raise RuntimeError("This file's hash is not in the VirusTotal database.")
        
    file_report = ujson.loads(response.text)
    return file_report 
    


def scan_file(filename: str) -> str:
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

    # Scan file
    try:
        with open(f"./{filename}", "rb") as file:
            files = { "file": (filename, file, "text/x-python") }
            scan_response = requests.post(scan_url, files=files, headers=headers)
    except FileNotFoundError:
        raise ValueError("File not found. Please make sure the file you're looking to scan is in the current directory.")


    analysis_id = scan_response.json().get("data", {}).get("id")
    status, analysis = get_file_analysis(analysis_id, headers)


    timeout = 500 
    request_interval = 5
    seconds = 0
    # Loop until file scan is completed, or until timeout seconds.
    while((status != "completed") and (seconds < timeout)):
        if (seconds % (request_interval*2) == 0):           # Display every (interval*2) seconds.
            print(f"Waiting for file scan to complete... Please standby. ({seconds} seconds)")
        sleep(request_interval)
        seconds += request_interval
        status, analysis = get_file_analysis(analysis_id, headers)

    if (status != "completed"):
        raise RuntimeError("Due to API delay, your scan timed out. Please try again later.")

    file_info = analysis.get("meta", {}).get("file_info", {})
    return file_info.get("sha256")



def search_malware_info(name: str) -> str:
    """ Use an agent to research the name of a potential malware and explain what it does.

    :param name: The name of a malware type that should be researched.
    :type name: str
    :return: A description of the malware.
    :rtype: str
    """    
    base_prompt = hub.pull("khodak/react-agent-template")
    prompt = base_prompt.partial(instructions="""
        You are an intelligent researching agent that helps uncover potentially unsafe files in a user's system. 
        From the input, you will be given a name or file hash from a file that could potentially be associated with malware. 
        Your job is to look up the name and see if it corresponds to any known malware. 

        If the name potentially corresponds to malware, formulate an explanation of the potential malware and explain
        what it does. Limit the response to four sentences or less and keep your tone official and informative.
    """)

    tools = load_tools(["serpapi"])
    claude_agent = create_react_agent(claude_llm, tools, prompt)
    agent_exec = AgentExecutor(agent=claude_agent, tools=tools, verbose=True, handle_parsing_errors=True, max_iterations=3)
    result = agent_exec.invoke({"input": name})
    return result.get("output", None)

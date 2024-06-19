# Security LLM Agent

This is a command-line LLM agent that uses tools to perform security scans on URLs and files that the user provides, using the VirusTotal API.

## Install

[Pip - Python](https://pip.pypa.io/en/stable/installation/)

## Setup

You can install the agent in a virtual environment by running the following commands:

```
pip install virtualenv
virtualenv -p python3 env
source env/bin/activate
pip install -r requirements.txt
```

## Environment variables

Create a .env file in the root directory with the following environment variables:\
VS_TOTAL_API_KEY= [Virustotal API key](https://www.virustotal.com/)\
SERPAPI_API_KEY= [SerpApi API key](https://serpapi.com/)\
LANGCHAIN_API_KEY= [Langchain API key](https://www.langchain.com/)\
OPENAI_API_KEY= [OpenAI API key](https://platform.openai.com/api-keys)\
ANTHROPIC_API_KEY= [Anthropic API key](https://www.anthropic.com/api)
<!-- * [Virustotal API key](https://www.virustotal.com/)
* [SerpApi API key](https://serpapi.com/)
* [Langchain API key](https://www.langchain.com/)
* [OpenAI API key](https://platform.openai.com/api-keys)
* [Anthropic API key](https://www.anthropic.com/api) -->

## Running

After installing, run the main file with

``` python3 app.py```
from langchain_google_genai import GoogleGenerativeAI, HarmCategory, HarmBlockThreshold
from langchain_openai import ChatOpenAI
from langchain.agents import AgentExecutor, create_react_agent
from langchain_community.agent_toolkits.load_tools import load_tools
from langsmith import Client
from textwrap import dedent
from langchain import hub
from dotenv import load_dotenv
import asyncio
import vt
from pprint import pprint
import traceback
import os

load_dotenv()

os.environ["LANGCHAIN_TRACING_V2"] = "true"
os.environ["LANGCHAIN_PROJECT"] = f"gensec-final"
os.environ["LANGCHAIN_ENDPOINT"] = "https://api.smith.langchain.com"
client = Client()

gemini_llm = GoogleGenerativeAI(
    model="gemini-1.5-pro-latest",
    temperature=0,
    safety_settings = {
        HarmCategory.HARM_CATEGORY_DANGEROUS_CONTENT: HarmBlockThreshold.BLOCK_NONE, 
        HarmCategory.HARM_CATEGORY_HATE_SPEECH: HarmBlockThreshold.BLOCK_NONE, 
        HarmCategory.HARM_CATEGORY_HARASSMENT: HarmBlockThreshold.BLOCK_NONE, 
    }
)
gpt_llm = ChatOpenAI(model='gpt-4o', temperature=0)

async def get_url_info(url):
    api_key = os.getenv("VS_TOTAL_API_KEY")    

    async with vt.Client(api_key) as client:
        url_id = vt.url_id(url)
        url = await client.get_object_async("/urls/{}", url_id)
        print(type(url))
        print(url)
        pprint(vars(url))



def main():

    # TESTING 
    asyncio.run(get_url_info("http://www.virustotal.com"))
    # TESTING

    base_prompt = hub.pull("khodak/react-agent-template")
    prompt = base_prompt.partial(instructions=dedent("""You are an agent that is used for helping the user use any tool that's available to you.
        Be as helpful as possible. If you are unable to produce an answer that is helpful to the user, say so."""))

    tools = load_tools(["serpapi"])

    gpt_agent = create_react_agent(gpt_llm, tools, prompt)
    gpt_executor = AgentExecutor(
            agent=gpt_agent, 
            tools=tools, 
            max_iterations=5, 
            verbose=True
    )

    for tool in gpt_executor.tools:
        print(f"\n{tool.name}: \n\n\t{tool.description}")


    

    while True:
        try:
            line = input("\n\nEnter query (\"exit\" to end) >>  ")
            if line and line != "exit": 
                print("\n\n\nPlease wait while the Agent completes your request.\n\n\n")
                result = gpt_executor.invoke({"input":line})
                print(f"\n\n{result.get('output')}")
            else:
                break

        except ValueError as v_error:
            print(f"\n\n{str(v_error)}")
        except Exception:
            traceback.print_exc()

    return


if __name__ == "__main__":
    main()

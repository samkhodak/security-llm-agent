from langchain_openai import ChatOpenAI
from langchain.agents import AgentExecutor, create_react_agent
from langchain_community.agent_toolkits.load_tools import load_tools
from langsmith import Client
from textwrap import dedent
from langchain import hub
from src.security_toolkit import check_url_safety, analyze_file
from dotenv import load_dotenv
import traceback
import os


load_dotenv()

os.environ["LANGCHAIN_TRACING_V2"] = "true"
os.environ["LANGCHAIN_PROJECT"] = f"gensec-final"
os.environ["LANGCHAIN_ENDPOINT"] = "https://api.smith.langchain.com"
client = Client()

gpt_llm = ChatOpenAI(model='gpt-4o', temperature=0)




def main():
    base_prompt = hub.pull("khodak/react-agent-template")
    prompt = base_prompt.partial(instructions=dedent("""You are an agent that is used for helping the user with security-related tasks.
        Be as helpful as possible. If you are unable to produce an answer that is helpful to the user, say so."""))

    tools = load_tools(["serpapi"])
    tools.extend([check_url_safety, analyze_file])

    
    gpt_agent = create_react_agent(gpt_llm, tools, prompt)
    gpt_executor = AgentExecutor(
            agent=gpt_agent, 
            tools=tools, 
            max_iterations=5, 
            verbose=True,
            handle_parsing_errors=True,
    )

    print("\n\nThe agent has access to the following tools: \n")
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
            
        except (ValueError, RuntimeError) as exception:
            print(f"\n\n{str(exception)}")
        except Exception:
            traceback.print_exc()

    return


if __name__ == "__main__":
    main()

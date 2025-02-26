import random

from langchain.agents import AgentExecutor
from langchain.agents.format_scratchpad.openai_tools import (
    format_to_openai_tool_messages,
)
from langchain.agents.output_parsers.openai_tools import OpenAIToolsAgentOutputParser
from langchain.prompts import ChatPromptTemplate, MessagesPlaceholder
from langchain_core.agents import AgentAction, AgentFinish
from langchain_core.utils.function_calling import convert_to_openai_tool
from langchain_openai import AzureChatOpenAI

from patchagent.agent.base import BaseAgent
from patchagent.agent.java.prompt import (
    JAVA_SYSTEM_PROMPT_TEMPLATE,
    JAVA_USER_PROMPT_TEMPLATE,
)
from patchagent.agent.java.proxy.default import (
    create_locate_tool,
    create_validate_tool,
    create_viewcode_tool,
)
from patchagent.context import Context
from patchagent.logger import log
from patchagent.task import PatchTask
from patchagent.utils import debug_mode


class OpenAIJavaAgent(BaseAgent):
    def __init__(
        self,
        task: PatchTask,
        model: str = "gpt-4o",
        temperature: float = 1,
        auto_hint: bool = False,
        counterexample_num: int = 3,
        max_iterations: int = 30,
    ):
        super().__init__()

        self.task = task
        self.model = model
        self.temperature = temperature
        self.auto_hint = auto_hint
        self.counterexample_num = counterexample_num
        self.max_iterations = max_iterations
        self.counterexamples = self.get_counterexamples()

        self.llm = AzureChatOpenAI(temperature=self.temperature, model=self.model)

    def setup(self, context: Context):
        lc_tools = [
            create_viewcode_tool(self.task, auto_hint=self.auto_hint),
            create_validate_tool(self.task, auto_hint=self.auto_hint),
            create_locate_tool(self.task, auto_hint=self.auto_hint),
        ]
        oai_tools = [convert_to_openai_tool(tool) for tool in lc_tools]

        self.prompt = ChatPromptTemplate.from_messages(
            [
                ("system", JAVA_SYSTEM_PROMPT_TEMPLATE),
                ("user", JAVA_USER_PROMPT_TEMPLATE),
                MessagesPlaceholder(variable_name="agent_scratchpad"),
            ]
        )
        context.add_system_message(JAVA_SYSTEM_PROMPT_TEMPLATE.format())

        context.add_user_message(
            JAVA_USER_PROMPT_TEMPLATE.format(
                project=self.task.project,
                report=self.task.report.summary,  # type: ignore
                counterexamples=self.counterexamples,
            )
        )

        self.llm_with_tool = self.llm.bind_tools(tools=oai_tools)

        def save_agent_output(output):
            if isinstance(output, AgentFinish):
                context.add_llm_response(output.log)
            else:
                if not isinstance(output, list):
                    log.error(f"Invalid output: {output}")
                else:
                    for action in output:
                        if isinstance(action, AgentAction):
                            context.add_llm_response(action.log)
                        else:
                            log.error(f"Invalid action: {action}")

            return output

        self.agent = (
            {
                "project": lambda input: self.task.project,
                "report": lambda input: self.task.report.summary,  # type: ignore
                "counterexamples": lambda input: self.counterexamples,
                "agent_scratchpad": lambda input: format_to_openai_tool_messages(input["intermediate_steps"]),
            }
            | self.prompt
            | self.llm_with_tool
            | OpenAIToolsAgentOutputParser()
            | save_agent_output
        )

        self.agent_executor = AgentExecutor(
            agent=self.agent,  # type: ignore
            tools=lc_tools,
            verbose=debug_mode(),
            max_iterations=self.max_iterations,
        )

    def get_counterexamples(self):
        counterexamples = []
        for context in self.task.contexts:
            for tool_call in context.tool_calls:
                if tool_call["name"] == "validate":
                    counterexamples.append(f"Error case: \n{tool_call['args']['patch']}")

        counterexamples = random.sample(counterexamples, min(self.counterexample_num, len(counterexamples)))
        if len(counterexamples) == 0:
            return ""

        message = "Here are some wrong patches you generated previously, you CAN NOT use them again:\n"
        message += "\n".join(counterexamples)
        return message

    def apply(self):
        log.info(f"[🤖] Applying {self.__class__.__name__} (model: {self.model}, temp: {self.temperature}, ah: {self.auto_hint}, #ce: {self.counterexample_num})")

        with self.task.new_context() as context:
            self.setup(context)
            _ = self.agent_executor.invoke({})

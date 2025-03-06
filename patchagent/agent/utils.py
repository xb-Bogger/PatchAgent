from typing import List

import openai
from langchain_openai import AzureChatOpenAI, ChatOpenAI


def construct_chat_openai(*args, **kwargs):
    _openai_class_ = [ChatOpenAI, AzureChatOpenAI]

    errors: List[str] = []
    for cls in _openai_class_:
        try:
            return cls(*args, **kwargs)
        except openai.OpenAIError as e:
            errors.append(str(e))
            continue

    raise openai.OpenAIError(errors)

from typing import List

from langchain_openai import AzureChatOpenAI, ChatOpenAI


class OpenAIException(Exception):
    pass


def construct_chat_openai(*args, **kwargs):
    _openai_class_ = [ChatOpenAI, AzureChatOpenAI]

    errors: List[str] = []
    for cls in _openai_class_:
        try:
            return cls(*args, **kwargs)
        except Exception as e:
            errors.append(str(e))
            continue

    raise OpenAIException(f"Failed to construct OpenAI chat: {errors}")

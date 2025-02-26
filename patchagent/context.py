import time


class Context:
    def __init__(self, data: dict = {}) -> None:
        self.patch = data.get("patch", None)
        self.messages = data.get("messages", [])
        self.elapsed_time = data.get("elapsed_time", None)

    def __enter__(self):
        self.start_time = time.time()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.elapsed_time = time.time() - self.start_time

    @property
    def tool_calls(self):
        return [message["message"] for message in self.messages if message["role"] == "tool"]

    def add_tool_call(self, name: str, args: dict, result: str):
        self.messages.append(
            {
                "role": "tool",
                "message": {
                    "name": name,
                    "args": args,
                    "result": result,
                },
            }
        )

    def add_llm_response(self, response: str):
        if len(response) > 0:
            self.messages.append(
                {
                    "role": "ai",
                    "message": response,
                }
            )

    def add_system_message(self, message: str):
        if len(message) > 0:
            self.messages.append(
                {
                    "role": "system",
                    "message": message,
                }
            )

    def add_user_message(self, message: str):
        if len(message) > 0:
            self.messages.append(
                {
                    "role": "user",
                    "message": message,
                }
            )

    def dump(self):
        return {
            "patch": self.patch,
            "elapsed_time": self.elapsed_time,
            "messages": self.messages,
        }

from enum import Enum, auto

'''语言枚举/判定与语言相关能力分发'''
class Lang(Enum):
    CLIKE = auto()
    JVM = auto()

    @classmethod
    def from_str(cls, inp: str) -> "Lang":
        _lang_map = {
            "c": Lang.CLIKE,
            "c++": Lang.CLIKE,
            "jvm": Lang.JVM,
        }

        if inp not in _lang_map:
            raise NotImplementedError(f"Language {inp} is not supported")

        return _lang_map[inp]

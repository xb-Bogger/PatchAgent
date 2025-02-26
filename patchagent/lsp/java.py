from patchagent.lsp.language import LanguageServer


class JavaLanguageServer(LanguageServer):
    def __init__(self, source_path):
        super().__init__(source_path)

    # TODO: Implement JavaServer

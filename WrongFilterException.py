class WrongFilterException(Exception):
    def __init__(self, filterName):
        self.filterName = filterName
        self.message = f"Filter protocol <{self.filterName}> does not exist"
        super().__init__(self.message)
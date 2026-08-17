"""
Case Collaboration Manager
Manages shared cases.
"""
class CaseManager:
    def __init__(self):
        self.cases = {}

    def create_case(self, case_id: str, title: str):
        self.cases[case_id] = {"title": title, "members": []}

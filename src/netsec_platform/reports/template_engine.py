"""
Report Template Engine
Generates reports from templates.
"""
class TemplateEngine:
    def render(self, template: str, data: dict):
        return template.format(**data)

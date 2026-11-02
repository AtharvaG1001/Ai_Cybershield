class SecurityReport:

    def __init__(self, module):

        self.module = module
        self.status = "SUCCESS"
        self.risk_score = 0
        self.data = {}
        self.warnings = []

    def add_data(self, key, value):
        self.data[key] = value

    def add_warning(self, warning):
        self.warnings.append(warning)

    def set_risk(self, score):
        self.risk_score = score

    def to_dict(self):
        return {
            "module": self.module,
            "status": self.status,
            "risk_score": self.risk_score,
            "data": self.data,
            "warnings": self.warnings
        }
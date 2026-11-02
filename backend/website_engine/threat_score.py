class ThreatScoreEngine:

    def __init__(self):
        pass

    def calculate(self, reports, ml_result=None):

        total_score = 0

        warnings = []

        recommendations = []

        score_breakdown = {}


        # ==========================================
        # SECURITY MODULES
        # ==========================================

        for report in reports:

            module = report.get(
                "module",
                "Unknown"
            )

            score = report.get(
                "risk_score",
                0
            )

            # Make sure score is valid
            try:
                score = float(score)
            except (TypeError, ValueError):
                score = 0

            score = max(0, min(score, 100))


            total_score += score

            score_breakdown[module] = score

            warnings.extend(
                report.get(
                    "warnings",
                    []
                )
            )

            recommendations.extend(
                report.get(
                    "recommendations",
                    []
                )
            )


        # ==========================================
        # MACHINE LEARNING SCORE
        # ==========================================

        ml_score = 0

        if ml_result is not None:

            probability = ml_result.get(
                "phishing_probability",
                0
            )

            try:
                probability = float(probability)
            except (TypeError, ValueError):
                probability = 0

            probability = max(
                0,
                min(probability, 100)
            )


            # --------------------------------------
            # ML RISK CONTRIBUTION
            # --------------------------------------

            if probability >= 99:

                ml_score = 50

            elif probability >= 95:

                ml_score = 40

            elif probability >= 85:

                ml_score = 30

            elif probability >= 70:

                ml_score = 20

            elif probability >= 50:

                ml_score = 10

            else:

                ml_score = 0


            score_breakdown[
                "Machine Learning"
            ] = ml_score

            total_score += ml_score


        # ==========================================
        # NORMALIZE
        # ==========================================

        total_score = min(
            round(total_score),
            100
        )


        # ==========================================
        # FINAL VERDICT
        # ==========================================

        if total_score < 25:

            verdict = "SAFE"

            level = "LOW"


        elif total_score < 50:

            verdict = "SUSPICIOUS"

            level = "MEDIUM"


        elif total_score < 75:

            verdict = "LIKELY PHISHING"

            level = "HIGH"


        else:

            verdict = "PHISHING"

            level = "CRITICAL"


        # ==========================================
        # REMOVE DUPLICATE WARNINGS
        # ==========================================

        warnings = list(
            dict.fromkeys(warnings)
        )


        # ==========================================
        # REMOVE DUPLICATE RECOMMENDATIONS
        # ==========================================

        recommendations = list(
            dict.fromkeys(recommendations)
        )


        # ==========================================
        # RETURN FINAL RESULT
        # ==========================================

        return {

            "overall_score": total_score,

            "security_level": level,

            "verdict": verdict,

            "score_breakdown": score_breakdown,

            "warnings": warnings,

            "recommendations": recommendations
        }

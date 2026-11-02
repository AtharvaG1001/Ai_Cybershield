import os
import subprocess

html_content = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>AI CyberShield — Viva Presentation & System Guide</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;600&display=swap');

  @page {
    size: A4;
    margin: 14mm 14mm 14mm 14mm;
    @bottom-right {
      content: counter(page);
    }
  }

  * {
    box-sizing: border-box;
    margin: 0;
    padding: 0;
  }

  body {
    font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    color: #1e293b;
    background: #ffffff;
    line-height: 1.55;
    font-size: 13.5px;
  }

  /* Cover / Header section */
  .header-card {
    background: linear-gradient(135deg, #0f172a 0%, #1e1b4b 50%, #0f172a 100%);
    color: #ffffff;
    padding: 30px;
    border-radius: 12px;
    margin-bottom: 22px;
    border: 1px solid #312e81;
    page-break-inside: avoid;
  }

  .badge {
    display: inline-block;
    padding: 4px 10px;
    font-size: 11px;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.06em;
    border-radius: 9999px;
    background: rgba(99, 102, 241, 0.25);
    color: #a5b4fc;
    border: 1px solid rgba(165, 180, 252, 0.3);
    margin-bottom: 12px;
  }

  .header-card h1 {
    font-size: 26px;
    font-weight: 800;
    margin-bottom: 8px;
    letter-spacing: -0.02em;
    color: #ffffff;
  }

  .header-card p.subtitle {
    font-size: 14px;
    color: #cbd5e1;
    max-width: 90%;
    margin-bottom: 16px;
  }

  .meta-grid {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 12px;
    margin-top: 16px;
    padding-top: 16px;
    border-top: 1px solid rgba(255, 255, 255, 0.12);
  }

  .meta-item {
    font-size: 11.5px;
  }

  .meta-label {
    color: #94a3b8;
    text-transform: uppercase;
    font-weight: 600;
    letter-spacing: 0.05em;
    margin-bottom: 3px;
  }

  .meta-val {
    color: #f8fafc;
    font-weight: 600;
    font-size: 12.5px;
  }

  /* Headings */
  h2 {
    font-size: 18px;
    font-weight: 700;
    color: #0f172a;
    margin-top: 22px;
    margin-bottom: 12px;
    padding-bottom: 6px;
    border-bottom: 2px solid #e2e8f0;
    display: flex;
    align-items: center;
    gap: 8px;
    page-break-after: avoid;
  }

  .section-num {
    background: #4f46e5;
    color: white;
    width: 22px;
    height: 22px;
    border-radius: 6px;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    font-size: 12px;
    font-weight: 700;
  }

  h3 {
    font-size: 14.5px;
    font-weight: 600;
    color: #1e293b;
    margin-top: 14px;
    margin-bottom: 6px;
    page-break-after: avoid;
  }

  p {
    margin-bottom: 10px;
    color: #334155;
  }

  /* Cards & Callouts */
  .card {
    background: #f8fafc;
    border: 1px solid #e2e8f0;
    border-radius: 8px;
    padding: 14px 16px;
    margin-bottom: 14px;
    page-break-inside: avoid;
  }

  .card-highlight {
    background: #f0fdf4;
    border: 1px solid #bbf7d0;
    border-left: 4px solid #16a34a;
  }

  .card-viva {
    background: #fdf4ff;
    border: 1px solid #f0abfc;
    border-left: 4px solid #c026d3;
  }

  .card-info {
    background: #eff6ff;
    border: 1px solid #bfdbfe;
    border-left: 4px solid #2563eb;
  }

  .viva-tag {
    display: inline-block;
    background: #c026d3;
    color: white;
    font-size: 10.5px;
    font-weight: 700;
    padding: 2px 7px;
    border-radius: 4px;
    margin-bottom: 6px;
    text-transform: uppercase;
  }

  /* Simple explanation speech bubble */
  .say-in-viva {
    background: #fffbeb;
    border: 1px dashed #f59e0b;
    border-radius: 8px;
    padding: 12px 14px;
    margin: 8px 0 12px 0;
    font-style: normal;
    color: #92400e;
    page-break-inside: avoid;
  }
  .say-in-viva strong {
    color: #78350f;
    display: block;
    margin-bottom: 4px;
    font-size: 12px;
    text-transform: uppercase;
    letter-spacing: 0.05em;
  }

  /* Tables */
  table {
    width: 100%;
    border-collapse: collapse;
    margin: 12px 0 16px 0;
    font-size: 12px;
    page-break-inside: avoid;
  }

  th, td {
    border: 1px solid #cbd5e1;
    padding: 7px 10px;
    text-align: left;
  }

  th {
    background: #f1f5f9;
    font-weight: 600;
    color: #0f172a;
  }

  tr:nth-child(even) td {
    background: #f8fafc;
  }

  /* Grid layout */
  .grid-2 {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 12px;
    page-break-inside: avoid;
    margin-bottom: 12px;
  }

  .grid-3 {
    display: grid;
    grid-template-columns: 1fr 1fr 1fr;
    gap: 10px;
    page-break-inside: avoid;
    margin-bottom: 12px;
  }

  .stat-box {
    background: #ffffff;
    border: 1px solid #e2e8f0;
    border-radius: 8px;
    padding: 12px;
    text-align: center;
    box-shadow: 0 1px 3px rgba(0,0,0,0.05);
  }
  .stat-num {
    font-size: 20px;
    font-weight: 800;
    color: #4f46e5;
  }
  .stat-label {
    font-size: 11px;
    color: #64748b;
    text-transform: uppercase;
    font-weight: 600;
    margin-top: 2px;
  }

  /* Architecture diagram */
  .diagram-container {
    background: #0f172a;
    color: #e2e8f0;
    border-radius: 8px;
    padding: 14px;
    font-family: 'JetBrains Mono', monospace;
    font-size: 11px;
    line-height: 1.45;
    white-space: pre;
    overflow-x: auto;
    margin: 12px 0;
    page-break-inside: avoid;
    border: 1px solid #1e293b;
  }

  ul, ol {
    margin-left: 20px;
    margin-bottom: 10px;
    color: #334155;
  }

  li {
    margin-bottom: 4px;
  }

  code {
    font-family: 'JetBrains Mono', monospace;
    font-size: 11.5px;
    background: #f1f5f9;
    padding: 1px 5px;
    border-radius: 4px;
    color: #d946ef;
    border: 1px solid #e2e8f0;
  }

  .page-break {
    page-break-before: always;
  }

  .qa-box {
    background: #ffffff;
    border: 1px solid #e2e8f0;
    border-radius: 8px;
    padding: 12px 14px;
    margin-bottom: 10px;
    page-break-inside: avoid;
  }
  .qa-q {
    font-weight: 700;
    color: #1e1b4b;
    margin-bottom: 4px;
    font-size: 13px;
    display: flex;
    align-items: baseline;
    gap: 6px;
  }
  .qa-q span {
    color: #4f46e5;
    font-weight: 800;
  }
  .qa-a {
    color: #334155;
    font-size: 12.5px;
    line-height: 1.5;
  }
</style>
</head>
<body>

  <!-- COVER / HEADER -->
  <div class="header-card">
    <div class="badge">Viva Presentation & Technical Defense Guide</div>
    <h1>AI CyberShield: Intelligent Phishing Detection Platform</h1>
    <p class="subtitle">A full-stack, machine-learning-driven cybersecurity system combining automated 35-feature URL analysis, multi-layered heuristics (SSL, DNS, WHOIS), email header & link parsing, and real-time threat intelligence.</p>
    
    <div class="meta-grid">
      <div class="meta-item">
        <div class="meta-label">Domain</div>
        <div class="meta-val">AI & Cyber Security</div>
      </div>
      <div class="meta-item">
        <div class="meta-label">ML Accuracy</div>
        <div class="meta-val">99.58% (PhiUSIIL Dataset)</div>
      </div>
      <div class="meta-item">
        <div class="meta-label">Backend Tech</div>
        <div class="meta-val">Python FastAPI + SQLAlchemy</div>
      </div>
      <div class="meta-item">
        <div class="meta-label">Frontend Tech</div>
        <div class="meta-val">Next.js 14 + React + TypeScript</div>
      </div>
    </div>
  </div>

  <!-- SECTION 1: ONE-LINE ELEVATOR PITCH -->
  <h2><span class="section-num">1</span> What is this Project? (Explain in 30 Seconds)</h2>
  <div class="card card-highlight">
    <p><strong>The Core Problem:</strong> Phishing is the #1 cyber attack vector in the world. Traditional antivirus and firewalls use "blacklists" (lists of known bad websites). But hackers create thousands of brand-new phishing websites every single minute. A blacklist cannot stop a website created 5 minutes ago.</p>
    <p><strong>Our Solution:</strong> <strong>AI CyberShield</strong> uses <strong>Machine Learning (Artificial Intelligence)</strong> and <strong>Multi-Layered Security Verification</strong> to detect phishing websites in <em>real-time</em> — even if the website has never been seen before in history.</p>
  </div>

  <div class="say-in-viva">
    <strong>🎯 Exact Words to Say to the External Examiner:</strong>
    "Sir/Madam, traditional security relies on static blacklists which fail against newly registered domains (zero-day phishing). Our project, AI CyberShield, solves this by analyzing the structural patterns of the URL using a trained Machine Learning model together with real-time checks on SSL certificates, domain age, DNS records, and email headers to calculate an automated threat score from 0 to 100 within milliseconds."
  </div>

  <!-- SECTION 2: SYSTEM ARCHITECTURE -->
  <h2><span class="section-num">2</span> Complete System Architecture & Technologies Used</h2>

  <div class="diagram-container">
+-----------------------------------------------------------------------------------+
|                        FRONTEND (Next.js 14 + TypeScript)                         |
|  - Real-time Threat Dashboard (Stats, Charts)    - Interactive URL Scanner        |
|  - Deep Email Header & Link Analyzer             - Scan History & Model Metrics   |
+-----------------------------------------------------------------------------------+
                                        |  REST API Calls (JSON via HTTP)
                                        v
+-----------------------------------------------------------------------------------+
|                           BACKEND (FastAPI / Python 3.10+)                        |
|  - OpenAPI / Swagger Docs (/api/docs)            - Pydantic v2 Request Validation |
|  - Dependency Injection & CORS Middleware        - SQLAlchemy 2.0 ORM             |
+-----------------------------------------------------------------------------------+
                                        |
                 +----------------------+----------------------+
                 |                                             |
                 v                                             v
+--------------------------------+           +----------------------------------+
|    AI & DETECTION ENGINES      |           |     PERSISTENCE & DATABASE       |
| 1. ML Predictor (35 Features)  |           | - SQLite (cybershield.db)        |
|    - HistGradientBoosting      |           | - Scans Table (verdict, score)   |
| 2. SSL/TLS Certificate Checker |           | - Findings Table (granular bugs) |
| 3. DNS & WHOIS Domain Checker  |           | - ModelEvaluations Table         |
| 4. Keyword & Brand Heuristics  |           +----------------------------------+
| 5. Threat Score Engine (0-100) |
| 6. Email Header / DKIM Engine  |
+--------------------------------+
  </div>

  <h3>Summary of All Technologies Used:</h3>
  <table>
    <thead>
      <tr>
        <th>Layer</th>
        <th>Technology</th>
        <th>Purpose / Role in the Project</th>
      </tr>
    </thead>
    <tbody>
      <tr>
        <td><strong>Frontend</strong></td>
        <td>Next.js 14, React, TypeScript</td>
        <td>Fast, responsive Single-Page Dashboard with client-side state and high-performance routing.</td>
      </tr>
      <tr>
        <td><strong>UI Styling</strong></td>
        <td>Modern CSS & Lucide Icons</td>
        <td>Glassmorphic dark-theme interface with risk gauges, status rings, and badge components.</td>
      </tr>
      <tr>
        <td><strong>Backend API</strong></td>
        <td>Python 3.10+, FastAPI, Uvicorn</td>
        <td>Asynchronous high-throughput REST API with automatic OpenAPI (Swagger) documentation.</td>
      </tr>
      <tr>
        <td><strong>Machine Learning</strong></td>
        <td>Scikit-Learn, NumPy, Pandas</td>
        <td>Feature extraction (35 lexical indicators) and HistGradientBoosting Classifier for inference.</td>
      </tr>
      <tr>
        <td><strong>Database / ORM</strong></td>
        <td>SQLite, SQLAlchemy 2.0</td>
        <td>Stores scan history, granular threat findings, and offline model validation metrics.</td>
      </tr>
      <tr>
        <td><strong>Security Libraries</strong></td>
        <td>dnspython, python-whois, cryptography</td>
        <td>Performs live DNS resolution, WHOIS domain creation queries, and SSL certificate inspection.</td>
      </tr>
    </tbody>
  </table>

  <div class="page-break"></div>

  <!-- SECTION 3: HOW THE WEBSITE WORKS (STEP-BY-STEP) -->
  <h2><span class="section-num">3</span> How the Website Works (Step-by-Step Flow)</h2>

  <div class="grid-3">
    <div class="stat-box">
      <div class="stat-num">Step 1</div>
      <div class="stat-label">Input Submission</div>
      <p style="font-size:11.5px; color:#475569; margin-top:5px;">User enters a website URL or pastes email text/headers.</p>
    </div>
    <div class="stat-box">
      <div class="stat-num">Step 2</div>
      <div class="stat-label">Parallel Scanning</div>
      <p style="font-size:11.5px; color:#475569; margin-top:5px;">Backend triggers ML extraction + SSL + DNS + WHOIS checks.</p>
    </div>
    <div class="stat-box">
      <div class="stat-num">Step 3</div>
      <div class="stat-label">Verdict & Findings</div>
      <p style="font-size:11.5px; color:#475569; margin-top:5px;">Threat Score (0-100) calculated, stored in DB, rendered live.</p>
    </div>
  </div>

  <h3>Detailed Lifecycle of a Scan:</h3>
  <ol>
    <li><strong>Client Request:</strong> The user types a URL (e.g., <code>http://secure-login-paypal.com.account-update.xyz/verify</code>) into the Next.js frontend and clicks <em>Analyze URL</em>.</li>
    <li><strong>API Validation:</strong> The request hits <code>POST /api/scan/url</code> on FastAPI. Pydantic validates the URL schema.</li>
    <li><strong>Layer 1 — ML Feature Extraction (35 Features):</strong> The system extracts structural features from the raw string without needing to visit or execute malicious code.
      <ul>
        <li>URL length, path length, query length, character entropy (randomness).</li>
        <li>Count of dots, hyphens, slashes, '@' symbols, digits, and suspicious TLDs (e.g., <code>.xyz</code>, <code>.top</code>).</li>
        <li>Subdomain count (phishing sites often stack subdomains to trick mobile users).</li>
      </ul>
    </li>
    <li><strong>Layer 2 — ML Classification:</strong> The feature vector is passed to our pre-trained <code>HistGradientBoostingClassifier</code>, which outputs a Phishing Probability (e.g., 98.4%).</li>
    <li><strong>Layer 3 — SSL/TLS Inspection:</strong>
      <ul>
        <li>Is the certificate valid, expired, or self-signed?</li>
        <li>Does the Common Name (CN) match the domain?</li>
        <li>Is HTTP plain text used instead of HTTPS?</li>
      </ul>
    </li>
    <li><strong>Layer 4 — WHOIS & Domain Age Check:</strong>
      <ul>
        <li>Phishing sites are typically registered only a few days before an attack. If domain age &lt; 30 days, a severe risk flag is raised.</li>
      </ul>
    </li>
    <li><strong>Layer 5 — DNS & Keyword Heuristics:</strong>
      <ul>
        <li>Resolves A/AAAA records. Checks for brand spoofing (e.g., using "paypal" or "netflix" inside an untrusted domain name).</li>
      </ul>
    </li>
    <li><strong>Threat Score Aggregator:</strong> All signals are combined into an overall score (0 to 100):
      <ul>
        <li><strong>0 – 24:</strong> <span style="color:#16a34a; font-weight:700;">LOW RISK</span> (Safe / Legitimate)</li>
        <li><strong>25 – 49:</strong> <span style="color:#ca8a04; font-weight:700;">MEDIUM RISK</span> (Suspicious elements present)</li>
        <li><strong>50 – 74:</strong> <span style="color:#ea580c; font-weight:700;">HIGH RISK</span> (Probable Phishing threat)</li>
        <li><strong>75 – 100:</strong> <span style="color:#dc2626; font-weight:700;">CRITICAL RISK</span> (Confirmed Dangerous Attack)</li>
      </ul>
    </li>
    <li><strong>Database & UI Display:</strong> The result is saved in SQLite and returned as JSON to the frontend. The UI animates a score gauge, displays actionable warnings, and logs the scan in the audit history.</li>
  </ol>

  <!-- SECTION 4: MACHINE LEARNING MODEL & DATASET -->
  <h2><span class="section-num">4</span> The Machine Learning Pipeline (Everything in Simple Words)</h2>

  <div class="grid-2">
    <div class="card">
      <h3>Dataset: PhiUSIIL Phishing URL Dataset</h3>
      <ul>
        <li><strong>Total Records:</strong> 235,795 verified URLs</li>
        <li><strong>Training Set:</strong> 188,636 URLs (80%)</li>
        <li><strong>Testing Set:</strong> 47,159 URLs (20%)</li>
        <li><strong>Classes:</strong> Balanced split of Legitimate and Phishing websites.</li>
      </ul>
    </div>
    <div class="card">
      <h3>Model Performance Metrics</h3>
      <ul>
        <li><strong>Accuracy:</strong> 99.58%</li>
        <li><strong>Precision:</strong> 99.91% (Almost zero false accusations)</li>
        <li><strong>Recall:</strong> 99.11% (Catches 99 out of 100 phishing sites)</li>
        <li><strong>ROC-AUC:</strong> 0.9983 (Near-perfect discrimination)</li>
        <li><strong>False Positive Rate:</strong> 0.07%</li>
      </ul>
    </div>
  </div>

  <div class="say-in-viva">
    <strong>🎯 Examiner might ask: "Why did you choose HistGradientBoosting over Simple Random Forest or Logistic Regression?"</strong>
    <p><strong>Your Answer:</strong> "Sir, HistGradientBoosting groups continuous numerical features into integer-valued bins (similar to LightGBM). This makes training and prediction over 10x faster with 235,000 samples, drastically reduces memory usage, naturally handles missing values, and gave us a higher accuracy of 99.58% compared to traditional models."</p>
  </div>

  <div class="page-break"></div>

  <!-- SECTION 5: EMAIL SCANNER ENGINE -->
  <h2><span class="section-num">5</span> Email Scanner & Header Analysis Engine</h2>
  <div class="card card-info">
    <p>Phishing attacks typically arrive through fraudulent emails. AI CyberShield includes an automated Email Inspector that analyzes three critical dimensions:</p>
  </div>

  <table>
    <thead>
      <tr>
        <th>Verification Area</th>
        <th>What It Checks</th>
        <th>Why It Matters in Phishing</th>
      </tr>
    </thead>
    <tbody>
      <tr>
        <td><strong>SPF (Sender Policy Framework)</strong></td>
        <td>Validates if the sending mail server IP is authorized by the sender's domain DNS.</td>
        <td>Prevents basic email spoofing (e.g., someone pretending to send mail from <code>ceo@google.com</code>).</td>
      </tr>
      <tr>
        <td><strong>DKIM (DomainKeys Identified Mail)</strong></td>
        <td>Verifies cryptographic digital signature attached to email headers.</td>
        <td>Ensures the email body was not intercepted or altered in transit.</td>
      </tr>
      <tr>
        <td><strong>DMARC Alignment</strong></td>
        <td>Checks domain policy enforcing action if SPF or DKIM fails.</td>
        <td>Tells the receiving server whether to reject or quarantine fake emails.</td>
      </tr>
      <tr>
        <td><strong>Urgency & Panic Words</strong></td>
        <td>Scans body text for psychological triggers: <em>"Account suspended", "Action required in 24 hours", "Verify bank PIN"</em>.</td>
        <td>Phishers rely on artificial panic to force users into making hasty mistakes.</td>
      </tr>
      <tr>
        <td><strong>Embedded Link Extraction</strong></td>
        <td>Extracts every clickable hyperlink inside the email HTML/text.</td>
        <td>Pipes each extracted URL into our 35-feature ML Engine to find hidden traps.</td>
      </tr>
    </tbody>
  </table>

  <!-- SECTION 6: TOP 15 VIVA QUESTIONS & ANSWERS -->
  <h2><span class="section-num">6</span> Top 15 Viva Questions & Winning Answers</h2>

  <div class="qa-box">
    <div class="qa-q"><span>Q1.</span> What is the motivation behind building AI CyberShield?</div>
    <div class="qa-a"><strong>Answer:</strong> Traditional defense systems use signature or blacklist matching. Hackers bypass this easily by spinning up short-lived domains using bulletproof hosting. AI CyberShield uses machine learning to detect phishing by analyzing intrinsic behavioral and structural patterns of URLs and emails rather than relying on prior blacklists.</div>
  </div>

  <div class="qa-box">
    <div class="qa-q"><span>Q2.</span> What features does your ML model extract from a URL?</div>
    <div class="qa-a"><strong>Answer:</strong> It extracts 35 structural and lexical features including: total URL length, domain length, path depth, character entropy (randomness), count of special symbols (<code>@</code>, <code>?</code>, <code>-</code>, <code>%</code>, <code>=</code>), IP address presence, count of subdomains, and suspicious Top-Level Domains (TLDs).</div>
  </div>

  <div class="qa-box">
    <div class="qa-q"><span>Q3.</span> Why is URL Entropy an important feature?</div>
    <div class="qa-a"><strong>Answer:</strong> Entropy measures the randomness of characters in a string. Legitimate websites use readable dictionary words (e.g., <code>amazon.com/orders</code>). Phishing URLs generated by automated malware kits often contain long pseudo-random hashes or obfuscated strings (high entropy), making entropy a strong indicator of malicious intent.</div>
  </div>

  <div class="qa-box">
    <div class="qa-q"><span>Q4.</span> Does HTTPS guarantee that a website is safe?</div>
    <div class="qa-a"><strong>Answer:</strong> No! Many people mistakenly think a padlock icon means safe. Today, over 80% of phishing sites use free SSL certificates (like Let's Encrypt). HTTPS only encrypts the connection between the user and the server; it does not verify whether the server owner is honest or a cyber criminal. Our system checks certificate age, issuer, and domain matching.</div>
  </div>

  <div class="qa-box">
    <div class="qa-q"><span>Q5.</span> What is the difference between Precision and Recall in this project?</div>
    <div class="qa-a"><strong>Answer:</strong> 
      <strong>Precision (99.91%):</strong> Out of all sites our model called "phishing", 99.91% were truly phishing (extremely low false alarms).<br>
      <strong>Recall (99.11%):</strong> Out of all actual phishing sites out there, our model successfully detected 99.11% of them. In cybersecurity, high recall is vital so zero threats slip through.
    </div>
  </div>

  <div class="qa-box">
    <div class="qa-q"><span>Q6.</span> How is the Overall Threat Score (0–100) calculated?</div>
    <div class="qa-a"><strong>Answer:</strong> It is a weighted hybrid calculation. The Machine Learning prediction contributes 60% of the weight, SSL/TLS checks contribute 15%, WHOIS domain age contributes 15%, and DNS/Keyword heuristics contribute 10%. If any critical failure is detected (such as an active brand spoof or expired SSL), extra penalty points are added.</div>
  </div>

  <div class="qa-box">
    <div class="qa-q"><span>Q7.</span> What happens if WHOIS or DNS lookup times out? Does the whole scan crash?</div>
    <div class="qa-a"><strong>Answer:</strong> No, we implemented isolated fault-tolerant try-except blocks for each engine layer. If WHOIS times out, the backend logs a partial warning, gracefully falls back, and computes the verdict using the ML model and available signals without crashing the user interface.</div>
  </div>

  <div class="page-break"></div>

  <div class="qa-box">
    <div class="qa-q"><span>Q8.</span> What is the role of SQLite and SQLAlchemy in this project?</div>
    <div class="qa-a"><strong>Answer:</strong> SQLite provides lightweight, zero-configuration local relational storage for scan history, threats, and offline model evaluation metrics. SQLAlchemy provides the Object Relational Mapper (ORM) to query and write data using structured Python classes instead of writing raw SQL strings.</div>
  </div>

  <div class="qa-box">
    <div class="qa-q"><span>Q9.</span> Why did you build the frontend in Next.js instead of simple HTML/CSS or basic React?</div>
    <div class="qa-a"><strong>Answer:</strong> Next.js offers modern component architecture, TypeScript type safety, automated code-splitting, fast client-side navigation, and seamless state management. It provides a production-grade dashboard experience with modular reusable components for scan cards, gauges, and tables.</div>
  </div>

  <div class="qa-box">
    <div class="qa-q"><span>Q10.</span> What are Homograph / Punycode Attacks?</div>
    <div class="qa-a"><strong>Answer:</strong> Phishers substitute Latin letters with identical-looking Cyrillic or Greek characters (e.g., replacing 'a' with Cyrillic 'а'). When registered, the browser translates it into Punycode (e.g., <code>xn--...</code>). Our keyword and URL preprocessor checks for punycode encoding and flags homograph brand impersonations.</div>
  </div>

  <div class="qa-box">
    <div class="qa-q"><span>Q11.</span> What is the role of Pydantic in FastAPI?</div>
    <div class="qa-a"><strong>Answer:</strong> Pydantic handles request and response data validation. When a request is sent, Pydantic automatically checks data types (ensuring URLs are valid strings, numbers are within ranges) and generates automatic Swagger/OpenAPI documentation schemas.</div>
  </div>

  <div class="qa-box">
    <div class="qa-q"><span>Q12.</span> How did you handle CORS (Cross-Origin Resource Sharing)?</div>
    <div class="qa-a"><strong>Answer:</strong> Since our Next.js frontend runs on port 3000 and FastAPI runs on port 8000, browser security blocks cross-origin requests by default. We added FastAPI's <code>CORSMiddleware</code> to explicitly authorize cross-origin API calls between the two origins.</div>
  </div>

  <div class="qa-box">
    <div class="qa-q"><span>Q13.</span> What are the limitations of this project?</div>
    <div class="qa-a"><strong>Answer:</strong> 1) If an attacker compromises a legitimate, aged domain (like a hacked school or corporate server), the WHOIS age check will look safe, so the system must rely purely on ML lexical cues. 2) Websites requiring two-factor or login walls cannot have their full internal pages analyzed without authenticated crawling.</div>
  </div>

  <div class="qa-box">
    <div class="qa-q"><span>Q14.</span> What are future enhancements for this project?</div>
    <div class="qa-a"><strong>Answer:</strong> 1) Integrating a headless browser sandbox (like Playwright) to capture visual screenshots and run Computer Vision models against login form clones. 2) Deploying a lightweight Chrome/Firefox browser extension that intercepts URLs in real-time before page load.</div>
  </div>

  <div class="qa-box">
    <div class="qa-q"><span>Q15.</span> Can you summarize your project in three bullet points?</div>
    <div class="qa-a"><strong>Answer:</strong>
      1. <strong>Predictive:</strong> Uses Machine Learning trained on 235k+ URLs to catch zero-day phishing with 99.58% accuracy.<br>
      2. <strong>Multi-layered:</strong> Combines AI with SSL, DNS, WHOIS, and Email header verification for defense-in-depth.<br>
      3. <strong>Full-Stack & Production-Ready:</strong> Backed by high-speed FastAPI backend, SQLite database, and responsive Next.js dark-mode UI.
    </div>
  </div>

  <!-- SECTION 7: LIVE DEMO CHEAT SHEET -->
  <h2><span class="section-num">7</span> Live Demonstration Script (Step-by-Step for Viva)</h2>
  <div class="card card-viva">
    <span class="viva-tag">Examiner Demo Guide</span>
    <p>When the examiner asks you to demonstrate the project, follow this exact 4-step sequence:</p>
    <ol>
      <li><strong>Show the Dashboard (Overview):</strong>
        <br>Open <code>http://localhost:3000</code>. Point out the live stats cards: Total Scans, Critical Threats, Safe Scans, and the Recent Scan Activity log. Explain that this gives a SOC (Security Operations Center) analyst immediate threat visibility.
      </li>
      <li><strong>Demo 1: Scan a Legitimate URL:</strong>
        <br>Click on <em>URL Scanner</em> in the sidebar. Click the <code>https://google.com</code> example button and press <em>Scan Now</em>.
        <br>Show the result: <strong>Threat Score: 0/100 (LOW RISK - SAFE)</strong>. Point out that the ML model gave 0.0% phishing probability, SSL certificate is valid, and WHOIS domain age is over 25 years old.
      </li>
      <li><strong>Demo 2: Scan a Malicious / Suspicious URL:</strong>
        <br>Enter a typical phishing simulation: <code>http://paypal-security-update.com.verify-login.xyz/account</code>.
        <br>Click <em>Scan Now</em>. Show the result: <strong>Threat Score: 85+/100 (CRITICAL RISK - PHISHING DETECTED)</strong>.
        <br>Show the examiner the red badge breakdown: Brand impersonation keywords detected, suspicious TLD (<code>.xyz</code>), multiple subdomains, and lack of valid SSL.
      </li>
      <li><strong>Show the Email Scanner:</strong>
        <br>Click on <em>Email Scanner</em>. Paste a simulated phishing email with urgent subject lines and fake links. Show how the engine parses the header, flags missing SPF/DKIM, and detects embedded attack links.
      </li>
      <li><strong>Show the Model Metrics View:</strong>
        <br>Click on <em>Model Health</em> in the sidebar to prove to the examiner that the model has real metrics (99.58% Accuracy, 235k dataset size, ROC-AUC curve).
      </li>
    </ol>
  </div>

  <div style="text-align: center; margin-top: 25px; font-size: 11px; color: #94a3b8; border-top: 1px solid #e2e8f0; padding-top: 10px;">
    AI CyberShield Project Viva Guide • Generated for Academic Presentation & Defense
  </div>

</body>
</html>
"""

html_path = r"C:\Users\gaikw\Desktop\AI-Phishing-Detection-System-main\AI_Phishing_Detection_System-main\viva_presentation_guide.html"
pdf_path = r"C:\Users\gaikw\Desktop\AI-Phishing-Detection-System-main\AI_Phishing_Detection_System-main\AI_Phishing_Detection_System_Viva_Guide.pdf"

with open(html_path, "w", encoding="utf-8") as f:
    f.write(html_content)

print(f"HTML guide written to {html_path}")

# Run Chrome headless to generate PDF
chrome_cmd = [
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    "--headless",
    "--disable-gpu",
    "--run-all-compositor-stages-before-draw",
    "--no-pdf-header-footer",
    f"--print-to-pdf={pdf_path}",
    html_path
]

res = subprocess.run(chrome_cmd, capture_output=True, text=True)
print("Chrome stdout:", res.stdout)
print("Chrome stderr:", res.stderr)
print(f"PDF exists: {os.path.exists(pdf_path)}, Size: {os.path.getsize(pdf_path) if os.path.exists(pdf_path) else 0} bytes")

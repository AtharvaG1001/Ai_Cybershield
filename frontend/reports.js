// =========================================================
//  AI SHIELD — Reports, Export & Analytics Engine
// =========================================================

function getJSPDF() {
    // Support both UMD (jspdf.umd.min.js) and module builds
    if (window.jspdf && window.jspdf.jsPDF) {
        return window.jspdf.jsPDF;
    }
    if (typeof jsPDF !== 'undefined') {
        return jsPDF;
    }
    return null;
}

/* ============================= */
/* REPORT ROUTER                 */
/* ============================= */

function downloadReport(format) {

    var data = null;
    var scanType = null;

    // Email scan has priority if it exists
    if (window.latestEmailScan) {

        data = window.latestEmailScan;
        scanType = "email";

    }
    // Otherwise use website scan
    else if (window.latestScan) {

        data = window.latestScan;
        scanType = "website";
    }


    // If variables are unavailable, try saved latest scans
    if (!data) {

        try {

            var savedWebsite =
                localStorage.getItem("latestScan");

            var savedEmail =
                localStorage.getItem("latestEmailScan");


            if (savedEmail) {

                data = JSON.parse(savedEmail);
                scanType = "email";

            } else if (savedWebsite) {

                data = JSON.parse(savedWebsite);
                scanType = "website";
            }

        } catch (error) {

            console.error(
                "Could not load saved scan:",
                error
            );
        }
    }


    // Still nothing found
    if (!data) {

        alert(
            "Please run a threat scan first before generating a report."
        );

        return;
    }


    if (format === "pdf") {

        generatePDF(data, scanType);

    } else if (format === "csv") {

        generateCSV(data, scanType);
    }
}

/* ============================= */
/* PDF REPORT GENERATOR          */
/* ============================= */

function generatePDF(data, scanType) {

    const jsPDFClass = getJSPDF();

    if (!jsPDFClass) {
        alert('PDF library not loaded. Please refresh the page.');
        return;
    }

    if (scanType === 'email') {
        generateEmailPDF(data, jsPDFClass);
    } else {
        generateWebsitePDF(data, jsPDFClass);
    }
}

/* ---------- WEBSITE PDF ---------- */

function generateWebsitePDF(data, jsPDFClass) {

    const doc = new jsPDFClass();
    const prediction = data.machine_learning?.prediction || 'UNKNOWN';
    const confidence = data.machine_learning?.confidence ?? 0;
    const threat = data.threat_analysis?.overall_score ?? 0;
    const verdict = data.threat_analysis?.verdict || 'Unknown';
    const date = new Date().toLocaleString();
    const isPhishing = prediction === 'PHISHING';

    const primaryColor = isPhishing ? [239, 68, 68] : [34, 197, 94];
    const accentColor = [56, 189, 248];
    const darkBg = [15, 23, 42];

    doc.setFillColor(darkBg[0], darkBg[1], darkBg[2]);
    doc.rect(0, 0, 210, 40, 'F');

    doc.setFont('helvetica', 'bold');
    doc.setFontSize(22);
    doc.setTextColor(accentColor[0], accentColor[1], accentColor[2]);
    doc.text('AI SHIELD', 14, 20);

    doc.setFontSize(12);
    doc.setTextColor(200, 200, 200);
    doc.text('Website Threat Analysis Report', 14, 28);
    doc.setFontSize(10);
    doc.text('Generated: ' + date, 14, 35);

    doc.setFillColor(primaryColor[0], primaryColor[1], primaryColor[2]);
    doc.roundedRect(14, 48, 182, 18, 3, 3, 'F');
    doc.setTextColor(255, 255, 255);
    doc.setFontSize(14);
    doc.setFont('helvetica', 'bold');
    doc.text('VERDICT: ' + prediction, 20, 59);

    doc.setTextColor(30, 30, 30);
    doc.setFontSize(11);
    doc.setFont('helvetica', 'normal');

    let y = 78;
    const lh = 8;

    doc.setFont('helvetica', 'bold');
    doc.text('Target URL:', 14, y);
    doc.setFont('helvetica', 'normal');
    doc.text(data.url || 'N/A', 50, y);
    y += lh + 4;

    doc.setFont('helvetica', 'bold');
    doc.text('Threat Score:', 14, y);
    doc.setFont('helvetica', 'normal');
    doc.text(threat + '/100', 50, y);
    y += lh;

    doc.setFont('helvetica', 'bold');
    doc.text('Confidence:', 14, y);
    doc.setFont('helvetica', 'normal');
    doc.text(confidence + '%', 50, y);
    y += lh;

    doc.setFont('helvetica', 'bold');
    doc.text('Analysis:', 14, y);
    doc.setFont('helvetica', 'normal');
    doc.text(verdict, 50, y);
    y += lh + 6;

    doc.setDrawColor(200, 200, 200);
    doc.line(14, y, 196, y);
    y += 10;

    // SSL
    if (data.ssl && data.ssl.data) {
        doc.setFont('helvetica', 'bold');
        doc.setFontSize(13);
        doc.setTextColor(accentColor[0], accentColor[1], accentColor[2]);
        doc.text('SSL Certificate', 14, y);
        y += 8;

        doc.setFontSize(10);
        doc.setTextColor(50, 50, 50);
        doc.setFont('helvetica', 'normal');
        const ssl = data.ssl.data;
        doc.text('Status: ' + (ssl.ssl_available ? 'Valid' : 'Invalid'), 14, y); y += lh;
        doc.text('Issuer: ' + (ssl.issuer || 'N/A'), 14, y); y += lh;
        doc.text('Days Remaining: ' + (ssl.days_remaining != null ? ssl.days_remaining : 'N/A'), 14, y); y += lh + 4;
    }

    // WHOIS
    if (data.whois) {
        doc.setFont('helvetica', 'bold');
        doc.setFontSize(13);
        doc.setTextColor(accentColor[0], accentColor[1], accentColor[2]);
        doc.text('WHOIS Information', 14, y);
        y += 8;

        doc.setFontSize(10);
        doc.setTextColor(50, 50, 50);
        doc.setFont('helvetica', 'normal');
        const whois = data.whois;
        const age = whois.domain_age_days ? Math.floor(whois.domain_age_days / 365) + ' Years' : 'N/A';
        doc.text('Domain Age: ' + age, 14, y); y += lh;
        doc.text('Country: ' + (whois.country || 'N/A'), 14, y); y += lh;
        doc.text('Registrar: ' + (whois.registrar || 'N/A'), 14, y); y += lh + 4;
    }

    // Keywords
    if (data.keywords && data.keywords.data) {
        doc.setFont('helvetica', 'bold');
        doc.setFontSize(13);
        doc.setTextColor(accentColor[0], accentColor[1], accentColor[2]);
        doc.text('Keyword Analysis', 14, y);
        y += 8;

        doc.setFontSize(10);
        doc.setTextColor(50, 50, 50);
        doc.setFont('helvetica', 'normal');
        const kw = data.keywords.data;
        doc.text('Total Matches: ' + (kw.total_matches || 0), 14, y); y += lh;
        const matched = kw.matched_keywords && kw.matched_keywords.length > 0
            ? kw.matched_keywords.join(', ')
            : 'None detected';
        const lines = doc.splitTextToSize('Matched: ' + matched, 180);
        doc.text(lines, 14, y);
        y += lines.length * lh + 4;
    }

    // Warnings
    const warnings = data.threat_analysis && data.threat_analysis.warnings ? data.threat_analysis.warnings : [];
    if (warnings.length > 0) {
        doc.setFont('helvetica', 'bold');
        doc.setFontSize(13);
        doc.setTextColor(239, 68, 68);
        doc.text('Security Warnings', 14, y);
        y += 8;

        doc.setFontSize(10);
        doc.setTextColor(50, 50, 50);
        doc.setFont('helvetica', 'normal');
        warnings.forEach(function(w) {
            if (y > 270) { doc.addPage(); y = 20; }
            const lines = doc.splitTextToSize('- ' + w, 180);
            doc.text(lines, 14, y);
            y += lines.length * lh;
        });
    }

    // Recommendations
    const recs = data.threat_analysis && data.threat_analysis.recommendations ? data.threat_analysis.recommendations : [];
    if (recs.length > 0) {
        if (y > 250) { doc.addPage(); y = 20; }
        doc.setFont('helvetica', 'bold');
        doc.setFontSize(13);
        doc.setTextColor(34, 197, 94);
        doc.text('Recommendations', 14, y);
        y += 8;

        doc.setFontSize(10);
        doc.setTextColor(50, 50, 50);
        doc.setFont('helvetica', 'normal');
        recs.forEach(function(r) {
            if (y > 270) { doc.addPage(); y = 20; }
            const lines = doc.splitTextToSize('- ' + r, 180);
            doc.text(lines, 14, y);
            y += lines.length * lh;
        });
    }

    doc.setFontSize(9);
    doc.setTextColor(150, 150, 150);
    doc.text('AI Shield - Phishing & Threat Detection System', 14, 290);
    doc.text('Confidential', 180, 290);

    const cleanUrl = (data.url || 'unknown').replace(/[^a-zA-Z0-9]/g, '_').substring(0, 30);
    doc.save('AI-Shield-Website-Report-' + cleanUrl + '-' + Date.now() + '.pdf');
}

/* ---------- EMAIL PDF ---------- */

function generateEmailPDF(data, jsPDFClass) {

    const doc = new jsPDFClass();

    const email = data.email || {};
    const threat = data.threat_analysis?.data || data.threat_analysis || {};
    const spam = data.spam_analysis?.data || {};
    const intent = data.intent_analysis?.data || {};
    const sender = data.sender_analysis?.data || {};
    const keyword = data.keyword_analysis?.data || {};
    const links = data.link_analysis?.data || {};

    const score = threat.overall_score ?? 0;
    const verdict = threat.verdict || 'UNKNOWN';
    const securityLevel = threat.security_level || 'UNKNOWN';
    const date = new Date().toLocaleString();
    const isPhishing = score >= 50;

    const primaryColor = isPhishing ? [239, 68, 68] : (score >= 25 ? [245, 158, 11] : [34, 197, 94]);
    const accentColor = [56, 189, 248];
    const darkBg = [15, 23, 42];

    // Header
    doc.setFillColor(darkBg[0], darkBg[1], darkBg[2]);
    doc.rect(0, 0, 210, 40, 'F');

    doc.setFont('helvetica', 'bold');
    doc.setFontSize(22);
    doc.setTextColor(accentColor[0], accentColor[1], accentColor[2]);
    doc.text('AI SHIELD', 14, 20);

    doc.setFontSize(12);
    doc.setTextColor(200, 200, 200);
    doc.text('Email Threat Analysis Report', 14, 28);
    doc.setFontSize(10);
    doc.text('Generated: ' + date, 14, 35);

    // Verdict banner
    doc.setFillColor(primaryColor[0], primaryColor[1], primaryColor[2]);
    doc.roundedRect(14, 48, 182, 18, 3, 3, 'F');
    doc.setTextColor(255, 255, 255);
    doc.setFontSize(14);
    doc.setFont('helvetica', 'bold');
    doc.text('VERDICT: ' + verdict, 20, 59);

    // Details
    doc.setTextColor(30, 30, 30);
    doc.setFontSize(11);
    doc.setFont('helvetica', 'normal');

    let y = 78;
    const lh = 8;

    doc.setFont('helvetica', 'bold');
    doc.text('From:', 14, y);
    doc.setFont('helvetica', 'normal');
    doc.text(email.sender || 'N/A', 50, y);
    y += lh;

    doc.setFont('helvetica', 'bold');
    doc.text('To:', 14, y);
    doc.setFont('helvetica', 'normal');
    doc.text(email.recipient || 'N/A', 50, y);
    y += lh;

    doc.setFont('helvetica', 'bold');
    doc.text('Subject:', 14, y);
    doc.setFont('helvetica', 'normal');
    const subjectLines = doc.splitTextToSize(email.subject || 'N/A', 145);
    doc.text(subjectLines, 50, y);
    y += subjectLines.length * lh;

    doc.setFont('helvetica', 'bold');
    doc.text('Threat Score:', 14, y);
    doc.setFont('helvetica', 'normal');
    doc.text(score + '/100', 50, y);
    y += lh;

    doc.setFont('helvetica', 'bold');
    doc.text('Security Level:', 14, y);
    doc.setFont('helvetica', 'normal');
    doc.text(securityLevel, 50, y);
    y += lh + 6;

    doc.setDrawColor(200, 200, 200);
    doc.line(14, y, 196, y);
    y += 10;

    // Sender Analysis
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(13);
    doc.setTextColor(accentColor[0], accentColor[1], accentColor[2]);
    doc.text('Sender Analysis', 14, y);
    y += 8;

    doc.setFontSize(10);
    doc.setTextColor(50, 50, 50);
    doc.setFont('helvetica', 'normal');
    doc.text('Sender Score: ' + (sender.sender_score ?? 0) + '/100', 14, y); y += lh;
    doc.text('Risk Level: ' + (sender.risk_level || 'UNKNOWN'), 14, y); y += lh;
    doc.text('Domain: ' + (sender.domain || 'N/A'), 14, y); y += lh;
    doc.text('Free Provider: ' + (sender.free_email_provider ? 'Yes' : 'No'), 14, y); y += lh + 4;

    // Spam Analysis
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(13);
    doc.setTextColor(accentColor[0], accentColor[1], accentColor[2]);
    doc.text('Spam Analysis', 14, y);
    y += 8;

    doc.setFontSize(10);
    doc.setTextColor(50, 50, 50);
    doc.setFont('helvetica', 'normal');
    doc.text('Verdict: ' + (spam.verdict || 'UNKNOWN'), 14, y); y += lh;
    doc.text('Spam Score: ' + (spam.spam_score ?? 0), 14, y); y += lh;
    doc.text('Spam Level: ' + (spam.spam_level || 'UNKNOWN'), 14, y); y += lh + 4;

    // Intent
    if (intent.category) {
        doc.setFont('helvetica', 'bold');
        doc.setFontSize(13);
        doc.setTextColor(accentColor[0], accentColor[1], accentColor[2]);
        doc.text('Intent Analysis', 14, y);
        y += 8;

        doc.setFontSize(10);
        doc.setTextColor(50, 50, 50);
        doc.setFont('helvetica', 'normal');
        doc.text('Category: ' + (intent.category || 'UNKNOWN'), 14, y); y += lh;
        doc.text('Confidence: ' + (intent.confidence ?? 0) + '%', 14, y); y += lh + 4;
    }

    // Phishing keywords
    if (keyword.phishing_count) {
        doc.setFont('helvetica', 'bold');
        doc.setFontSize(13);
        doc.setTextColor(accentColor[0], accentColor[1], accentColor[2]);
        doc.text('Phishing Keywords', 14, y);
        y += 8;

        doc.setFontSize(10);
        doc.setTextColor(50, 50, 50);
        doc.setFont('helvetica', 'normal');
        doc.text('Detected: ' + keyword.phishing_count, 14, y); y += lh;
        const kws = keyword.phishing_keywords?.length
            ? keyword.phishing_keywords.join(', ')
            : 'None detected';
        const kwLines = doc.splitTextToSize('Keywords: ' + kws, 180);
        doc.text(kwLines, 14, y);
        y += kwLines.length * lh + 4;
    }

    // Links
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(13);
    doc.setTextColor(accentColor[0], accentColor[1], accentColor[2]);
    doc.text('Link Analysis', 14, y);
    y += 8;

    doc.setFontSize(10);
    doc.setTextColor(50, 50, 50);
    doc.setFont('helvetica', 'normal');
    doc.text('Link Count: ' + (links.link_count ?? 0), 14, y); y += lh;
    doc.text('Highest Risk: ' + (links.highest_risk_score ?? 0) + '/100', 14, y); y += lh;
    doc.text('Risk Level: ' + (links.highest_risk_level || 'UNKNOWN'), 14, y); y += lh + 4;

    // Warnings
    const warnings = data.warnings || [];
    if (warnings.length > 0) {
        if (y > 250) { doc.addPage(); y = 20; }
        doc.setFont('helvetica', 'bold');
        doc.setFontSize(13);
        doc.setTextColor(239, 68, 68);
        doc.text('Email Warnings', 14, y);
        y += 8;

        doc.setFontSize(10);
        doc.setTextColor(50, 50, 50);
        doc.setFont('helvetica', 'normal');
        warnings.forEach(function(w) {
            if (y > 270) { doc.addPage(); y = 20; }
            const lines = doc.splitTextToSize('- ' + w, 180);
            doc.text(lines, 14, y);
            y += lines.length * lh;
        });
    }

    // Recommendations
    const recs = data.recommendations || [];
    if (recs.length > 0) {
        if (y > 250) { doc.addPage(); y = 20; }
        doc.setFont('helvetica', 'bold');
        doc.setFontSize(13);
        doc.setTextColor(34, 197, 94);
        doc.text('Recommendations', 14, y);
        y += 8;

        doc.setFontSize(10);
        doc.setTextColor(50, 50, 50);
        doc.setFont('helvetica', 'normal');
        recs.forEach(function(r) {
            if (y > 270) { doc.addPage(); y = 20; }
            const lines = doc.splitTextToSize('- ' + r, 180);
            doc.text(lines, 14, y);
            y += lines.length * lh;
        });
    }

    // Footer
    doc.setFontSize(9);
    doc.setTextColor(150, 150, 150);
    doc.text('AI Shield - Phishing & Threat Detection System', 14, 290);
    doc.text('Confidential', 180, 290);

    // Save
    const cleanSubject = (email.subject || 'unknown')
        .replace(/[^a-zA-Z0-9]/g, '_')
        .substring(0, 30);
    doc.save('AI-Shield-Email-Report-' + cleanSubject + '-' + Date.now() + '.pdf');
}

/* ============================= */
/* CSV EXPORT                    */
/* ============================= */

function generateCSV(data, scanType) {

    var rows;

    if (scanType === 'email') {

        var email = data.email || {};
        var threat = data.threat_analysis?.data || data.threat_analysis || {};
        var spam = data.spam_analysis?.data || {};
        var intent = data.intent_analysis?.data || {};
        var sender = data.sender_analysis?.data || {};
        var keyword = data.keyword_analysis?.data || {};
        var links = data.link_analysis?.data || {};

        rows = [
            ['Field', 'Value'],
            ['Scan Type', 'Email'],
            ['From', email.sender || 'N/A'],
            ['To', email.recipient || 'N/A'],
            ['Subject', email.subject || 'N/A'],
            ['Threat Verdict', threat.verdict || 'N/A'],
            ['Threat Score', (threat.overall_score ?? 0) + '/100'],
            ['Security Level', threat.security_level || 'N/A'],
            ['Intent Category', intent.category || 'N/A'],
            ['Intent Confidence', (intent.confidence ?? 0) + '%'],
            ['Spam Verdict', spam.verdict || 'N/A'],
            ['Spam Score', spam.spam_score ?? 0],
            ['Sender Risk Level', sender.risk_level || 'N/A'],
            ['Sender Score', (sender.sender_score ?? 0) + '/100'],
            ['Free Email Provider', sender.free_email_provider ? 'Yes' : 'No'],
            ['Phishing Keywords', keyword.phishing_count ?? 0],
            ['Link Count', links.link_count ?? 0],
            ['Highest Link Risk', (links.highest_risk_score ?? 0) + '/100'],
            ['Date', new Date().toLocaleString()]
        ];

    } else {

        rows = [
            ['Field', 'Value'],
            ['Scan Type', 'Website'],
            ['URL', data.url || 'N/A'],
            ['Prediction', data.machine_learning && data.machine_learning.prediction ? data.machine_learning.prediction : 'N/A'],
            ['Confidence', (data.machine_learning && data.machine_learning.confidence ? data.machine_learning.confidence : 0) + '%'],
            ['Threat Score', (data.threat_analysis && data.threat_analysis.overall_score != null ? data.threat_analysis.overall_score : 0) + '/100'],
            ['Verdict', data.threat_analysis && data.threat_analysis.verdict ? data.threat_analysis.verdict : 'N/A'],
            ['SSL Available', data.ssl && data.ssl.data && data.ssl.data.ssl_available ? 'Yes' : 'No'],
            ['SSL Issuer', data.ssl && data.ssl.data && data.ssl.data.issuer ? data.ssl.data.issuer : 'N/A'],
            ['Domain Age (Years)', data.whois && data.whois.domain_age_days ? Math.floor(data.whois.domain_age_days / 365) : 'N/A'],
            ['Country', data.whois && data.whois.country ? data.whois.country : 'N/A'],
            ['Keyword Matches', data.keywords && data.keywords.data && data.keywords.data.total_matches != null ? data.keywords.data.total_matches : 0],
            ['Date', new Date().toLocaleString()]
        ];
    }

    var csvContent = rows.map(function(r) {
        return r.map(function(cell) {
            return '"' + String(cell).replace(/"/g, '""') + '"';
        }).join(',');
    }).join('\n');

    var blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    var link = document.createElement('a');
    link.href = URL.createObjectURL(blob);
    link.download = 'AI-Shield-' + (scanType === 'email' ? 'Email' : 'Website') + '-Export-' + Date.now() + '.csv';
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(link.href);
}

/* ============================= */
/* ANALYTICS DASHBOARD           */
/* ============================= */

function showAnalytics() {
    var history = JSON.parse(localStorage.getItem('scanHistory')) || [];

    if (history.length === 0) {
        alert('No scan data available. Run some scans first to see analytics.');
        return;
    }

    var total = history.length;
    var phishing = 0;
    history.forEach(function(h) { if (h.prediction === 'PHISHING') phishing++; });
    var safe = total - phishing;
    var avgScore = history.reduce(function(sum, h) { return sum + (h.score || 0); }, 0) / total;

    var modal = document.createElement('div');
    modal.id = 'analyticsModal';
    modal.innerHTML = '<div class="analytics-overlay" onclick="closeAnalytics()">' +
        '<div class="analytics-modal" onclick="event.stopPropagation()">' +
            '<div class="analytics-header">' +
                '<h2><i class="fa-solid fa-chart-column"></i> Threat Analytics</h2>' +
                '<button class="analytics-close" onclick="closeAnalytics()">' +
                    '<i class="fa-solid fa-xmark"></i>' +
                '</button>' +
            '</div>' +
            '<div class="analytics-body">' +
                '<div class="analytics-grid">' +
                    '<div class="analytics-card">' +
                        '<div class="analytics-number">' + total + '</div>' +
                        '<div class="analytics-label">Total Scans</div>' +
                    '</div>' +
                    '<div class="analytics-card safe">' +
                        '<div class="analytics-number">' + safe + '</div>' +
                        '<div class="analytics-label">Safe</div>' +
                    '</div>' +
                    '<div class="analytics-card danger">' +
                        '<div class="analytics-number">' + phishing + '</div>' +
                        '<div class="analytics-label">Threats Detected</div>' +
                    '</div>' +
                    '<div class="analytics-card">' +
                        '<div class="analytics-number">' + avgScore.toFixed(1) + '</div>' +
                        '<div class="analytics-label">Avg Threat Score</div>' +
                    '</div>' +
                '</div>' +
                '<div class="analytics-chart">' +
                    '<h3>Detection Breakdown</h3>' +
                    '<div class="analytics-bar">' +
                        '<div class="analytics-bar-fill safe" style="width: ' + (safe / total * 100) + '%"></div>' +
                        '<div class="analytics-bar-fill danger" style="width: ' + (phishing / total * 100) + '%"></div>' +
                    '</div>' +
                    '<div class="analytics-legend">' +
                        '<span><span class="dot safe"></span> Safe (' + safe + ')</span>' +
                        '<span><span class="dot danger"></span> Phishing (' + phishing + ')</span>' +
                    '</div>' +
                '</div>' +
                '<div class="analytics-recent">' +
                    '<h3>Recent Activity</h3>' +
                    '<div class="analytics-list">' +
                        history.slice(0, 5).map(function(h) {
                            return '<div class="analytics-item">' +
                                '<span class="analytics-url">' + (h.url || h.subject || 'N/A') + '</span>' +
                                '<span class="analytics-badge ' + (h.prediction === 'PHISHING' ? 'danger' : 'safe') + '">' + h.prediction + '</span>' +
                            '</div>';
                        }).join('') +
                    '</div>' +
                '</div>' +
            '</div>' +
        '</div>' +
    '</div>';

    document.body.appendChild(modal);

    requestAnimationFrame(function() {
        modal.querySelector('.analytics-overlay').style.opacity = '1';
        modal.querySelector('.analytics-modal').style.transform = 'translateY(0)';
    });
}

function closeAnalytics() {
    var modal = document.getElementById('analyticsModal');
    if (modal) {
        modal.querySelector('.analytics-overlay').style.opacity = '0';
        modal.querySelector('.analytics-modal').style.transform = 'translateY(30px)';
        setTimeout(function() { modal.remove(); }, 300);
    }
}

document.addEventListener('keydown', function(e) {
    if (e.key === 'Escape') closeAnalytics();
});
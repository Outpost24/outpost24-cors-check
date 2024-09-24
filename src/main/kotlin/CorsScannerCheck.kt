import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.scanner.AuditResult
import burp.api.montoya.scanner.ConsolidationAction
import burp.api.montoya.scanner.ScanCheck
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint
import burp.api.montoya.scanner.audit.issues.AuditIssue

class CorsScannerCheck(private val api: MontoyaApi) : ScanCheck {
    private val auditedRequests: MutableSet<String> = HashSet()
    override fun activeAudit(baseRequestResponse: HttpRequestResponse, auditInsertionPoint: AuditInsertionPoint): AuditResult {
        /*
        PLAN:
        1. Check of origin header exists at all -> DONE
        2. If it does, use its value as the "trusted" domain part of the checks -> DONE
        3. Loop through the bypasses found on the PortSwigger cheatsheet (plus the localhost bypass we know exists) starting with arbitrary origin reflection
        4. If a check works, report an issue including the requestResponse pair and highlight the ACAO and ACAC headers
        5. If any of the checks work, stop the loop and don't report
        */

        //Check if scan check is actually enabled
        if (!CorsCheckExtension.scanCheckEnabled) {
            return AuditResult.auditResult()
        }

        //Ensure we only run the check once per request ("request" is defined as $requestUrl$headers$requestBody so any changes to those will allow another scan)
        val requestHash = generateRequestHash(baseRequestResponse)

        if (auditedRequests.contains(requestHash)) {
            return AuditResult.auditResult()
        }

        //Add current request to list of "not to be scanned" items
        auditedRequests.add(requestHash)

        //Check for arbitrary reflection and exit if there is (burp will handle this for us)
        if (checkArbitraryOriginReflection(api, baseRequestResponse.request())) {
            return AuditResult.auditResult()
        }
        val issues = TrustedDomainValidationBypassCheck.runTrustedDomainValidationBypassCheck(
            api,
            baseRequestResponse.request(),
            baseRequestResponse.httpService().host()
        )

        return AuditResult.auditResult(issues)

    }

    override fun passiveAudit(p0: HttpRequestResponse?): AuditResult {
        return AuditResult.auditResult()
    }

    override fun consolidateIssues(p0: AuditIssue?, p1: AuditIssue?): ConsolidationAction {
        return ConsolidationAction.KEEP_EXISTING
    }

    private fun generateRequestHash(baseRequestResponse: HttpRequestResponse): String {
        val requestUrl = baseRequestResponse.request().url()
        val headers = baseRequestResponse.request().headers()
        val requestBody = baseRequestResponse.request().body().toString()

        // Generate a hash using the URL, headers, and body to uniquely identify the request
        return "$requestUrl$headers$requestBody".hashCode().toString()
    }
}
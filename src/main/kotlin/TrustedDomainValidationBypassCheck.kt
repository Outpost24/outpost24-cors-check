import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.Marker
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.scanner.audit.issues.AuditIssue
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity

object TrustedDomainValidationBypassCheck {
    fun runTrustedDomainValidationBypassCheck(api: MontoyaApi, selectedRequest: HttpRequest, trustedDomain: String): List<AuditIssue> {
        val bypasses = listOf(
            "trusted.com._.web-attacker.com",
            "trusted.com.-.web-attacker.com",
            "trusted.com.,.web-attacker.com",
            "trusted.com.;.web-attacker.com",
            "trusted.com.!.web-attacker.com",
            "trusted.com.'.web-attacker.com",
            "trusted.com.(.web-attacker.com",
            "trusted.com.).web-attacker.com",
            "trusted.com.*.web-attacker.com",
            "trusted.com.&.web-attacker.com",
            "trusted.com.+.web-attacker.com",
            "trusted.com.web-attacker.com",
            "trusted.com.=.web-attacker.com",
            "trusted.com.~.web-attacker.com",
            "trusted.com.$.web-attacker.com",
            "trusted.com.{.web-attacker.com",
            "trusted.com.}.web-attacker.com",
            "trusted.com.`.web-attacker.com",
            "trusted.com.\".web-attacker.com",
            "trusted.com.web-attacker.com",
            "trusted.comweb-attacker.com",
            "web-attacker.com.trusted.com",
            "anythingtrusted.com",
            //"localhostweb-attacker.com",
            //"localhost.web-attacker.com",
            "strusted.com"
        )

        val attackerDomain = randSting(12) + ".com"

        val issues = mutableListOf<AuditIssue>()

        for (bypass in bypasses) {
            val originHeaderDomain: String
            //Update placeholders if required
            if (bypass.contains("web-attacker.com") && bypass.contains("trusted.com")) {
                originHeaderDomain = bypass.replace("trusted.com", trustedDomain).replace("web-attacker.com", attackerDomain)
            } else if (bypass.contains("web-attacker.com")){
                originHeaderDomain = bypass.replace("web-attacker.com", attackerDomain)
            } else if (bypass.contains("trusted.com")) {
                originHeaderDomain = bypass.replace("trusted.com", trustedDomain)
            } else {
                originHeaderDomain = bypass
            }

            val checkRequest: HttpRequest

            if (selectedRequest.httpService().secure()) {
                checkRequest = selectedRequest.withHeader("Origin", "https://$originHeaderDomain")
            } else {
                checkRequest = selectedRequest.withHeader("Origin", "http://$originHeaderDomain")
            }


            val checkRequestResponse = api.http().sendRequest(checkRequest)
            val acacHeader = "true"
            val vulnerableOrigin = checkRequest.headerValue("Origin")

            if (checkRequestResponse.response().headerValue("Access-Control-Allow-Credentials") != acacHeader) {
                continue
            }
            if (checkRequestResponse.response().headerValue("Access-Control-Allow-Origin") != vulnerableOrigin) {
                continue
            }

            //checkRequestResponse.response() contains both the ACAC = True and ACAO = reflected origin header, we have a vuln!
            val acacMarker = getMarkerFromResponse(checkRequestResponse, "Access-Control-Allow-Credentials: true")
            val vulnerableOriginMarker =
                getMarkerFromResponse(checkRequestResponse, "Access-Control-Allow-Origin: $vulnerableOrigin")

            val exploitOriginMarker = getMarkerFromRequest(checkRequestResponse, "Origin: $vulnerableOrigin")

            val responseHighlights = mutableListOf<Marker?>()
            responseHighlights.add(acacMarker)
            responseHighlights.add(vulnerableOriginMarker)

            val requestHighlights = mutableListOf<Marker?>()
            requestHighlights.add(exploitOriginMarker)

            val auditIssue = AuditIssue.auditIssue(
                "Permissive Cross-Origin Resource Sharing via '$bypass'",
                "The application can be tricked into trusting arbitrary origins via the bypass mentioned in the name of this issue. For some special character bypasses you may need the victim to use Safari. This check is based off of these research papers -> https://corben.io/blog/18-6-16-advanced-cors-techniques | https://portswigger.net/web-security/ssrf/url-validation-bypass-cheat-sheet",
                "Validate the 'Origin' header against a whitelist of know-trusted domains and subdomains.",
                selectedRequest.url(),
                AuditIssueSeverity.HIGH,
                AuditIssueConfidence.CERTAIN,
                "Permissive Cross-Origin Resource Sharing may allow an attacker to steal sensitive data from unsuspecting users. For this to work, the application must implement some form of authentication that the browser will automatically include with requests (think cookies, basic auth, digest but NOT Authorization Bearer). Additionally, if Cookies are used, SameSite will likely need to be explicitly set to 'None' for the cookie to be sent cross-domain.",
                "Implementing URL validation in a regex can be tricky. It is more secure to implement a whitelist and have the origin header match exactly those values.",
                AuditIssueSeverity.HIGH,
                checkRequestResponse.withResponseMarkers(responseHighlights).withRequestMarkers(requestHighlights)
            )
            issues.add(auditIssue)
        }
        return issues
    }
}
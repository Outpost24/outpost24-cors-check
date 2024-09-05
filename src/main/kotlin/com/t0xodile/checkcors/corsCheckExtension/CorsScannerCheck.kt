package com.t0xodile.checkcors.corsCheckExtension

import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.Marker
import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.scanner.AuditResult
import burp.api.montoya.scanner.ConsolidationAction
import burp.api.montoya.scanner.ScanCheck
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint
import burp.api.montoya.scanner.audit.issues.AuditIssue
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity

class CorsScannerCheck(private val api: MontoyaApi) : ScanCheck {
    private val auditedRequests: MutableSet<HttpRequestResponse> = HashSet()
    override fun activeAudit(baseRequestResponse: HttpRequestResponse, auditInsertionPoint: AuditInsertionPoint): AuditResult {
        /*
        PLAN:
        1. Check of origin header exists at all -> DONE
        2. If it does, use its value as the "trusted" domain part of the checks -> DONE
        3. Loop through the bypasses found on the PortSwigger cheatsheet (plus the localhost bypass we know exists) starting with arbitrary origin reflection
        4. If a check works, report an issue including the requestResponse pair and highlight the ACAO and ACAC headers
        5. If any of the checks work, stop the loop and don't report
        */

        //Ensure we only run the check once... not for each request
        if (auditedRequests.contains(baseRequestResponse)) {
            return AuditResult.auditResult()
        }

        //Add current request to list of "not to be scanned" items
        auditedRequests.add(baseRequestResponse)

        val bypasses = listOf(
            "example.com._.web-attacker.com",
            "example.com.-.web-attacker.com",
            "example.com.,.web-attacker.com",
            "example.com.;.web-attacker.com",
            "example.com.!.web-attacker.com",
            "example.com.'.web-attacker.com",
            "example.com.(.web-attacker.com",
            "example.com.).web-attacker.com",
            "example.com.*.web-attacker.com",
            "example.com.&.web-attacker.com",
            "example.com.+.web-attacker.com",
            "example.com.web-attacker.com",
            "example.com.=.web-attacker.com",
            "example.com.~.web-attacker.com",
            "example.com.$.web-attacker.com",
            "example.comweb-attacker.com",
            "web-attacker.com.example.com",
            "web-attacker.com.example.com",
            "anythingexample.com",
            "anythingexample.com",
            "localhostweb-attacker.com",
            "localhost.web-attacker.com",
            "null",
            "sexample.com",
            "[::]",
            "[::1]",
            "[::ffff:7f00:1]",
            "[0000:0000:0000:0000:0000:0000:0000:0000]",
            "example.com.local",
            "example.com.localhost",
            "0.0.0.0",
            "127.0.0.1",
            "localhost"
        )

        val schemes = listOf(
            "https://",
            "http://"
        )




        val trustedDomain: String

        if (!baseRequestResponse.request().hasHeader("Origin")) {
            trustedDomain = baseRequestResponse.request().httpService().host() //Set the origin header to the target domain if it doesn't exist
        } else {
            val domainRegex = """https?://([a-zA-Z0-9.-]+)""".toRegex()
            trustedDomain = domainRegex.find(baseRequestResponse.request().headerValue("Origin"))?.groupValues?.get(1) ?: baseRequestResponse.request().httpService().host()
        }

        val issues = mutableListOf<AuditIssue>()

        for (scheme in schemes) {
            for (bypass in bypasses) {
                val originHeaderDomain: String
                //If the bypass doesn't contain any placeholders
                if (!bypass.contains("web-attacker.com") || !bypass.contains("example.com")) {
                    originHeaderDomain = bypass
                } else {
                    originHeaderDomain = bypass.replace("example.com", trustedDomain)
                }

                val checkRequest = baseRequestResponse.request().withHeader("Origin", "$scheme$originHeaderDomain")

                val checkRequestResponse = api.http().sendRequest(checkRequest)
                val acacHeader = "true"
                val vulnerableOrigin = "$scheme$originHeaderDomain"

                if (checkRequestResponse.response().headerValue("Access-Control-Allow-Credentials") != acacHeader) {
                    continue
                }
                if (checkRequestResponse.response().headerValue("Access-Control-Allow-Origin") != vulnerableOrigin) {
                    continue
                }

                //checkRequestResponse.response() contains both the ACAC = True and ACAO = reflected origin header, we have a vuln!
                val acacMarker = getMarkerFromResponse(checkRequestResponse, "Access-Control-Allow-Credentials: true")
                val vulnerableOriginMarker = getMarkerFromResponse(checkRequestResponse, "Access-Control-Allow-Origin: $scheme$originHeaderDomain")

                val exploitOriginMarker = getMarkerFromRequest(checkRequestResponse, "Origin: $scheme$originHeaderDomain")

                val responseHighlights = mutableListOf<Marker?>()
                responseHighlights.add(acacMarker)
                responseHighlights.add(vulnerableOriginMarker)

                val requestHighlights = mutableListOf<Marker?>()
                requestHighlights.add(exploitOriginMarker)

                val auditIssue = AuditIssue.auditIssue(
                    "Permissive Cross-Origin Resource Sharing via '$bypass'",
                    "This response is reflecting a super-weird origin header value that actually makes it vulnerable. For some special characters you might need to use Safari. This check is based off of this research -> https://corben.io/blog/18-6-16-advanced-cors-techniques | https://github.com/lc/theftfuzzer/tree/master",
                    "Validate the 'Origin' header against a whitelist of know-trusted domains and subdomains.",
                    baseRequestResponse.request().url(),
                    AuditIssueSeverity.HIGH,
                    AuditIssueConfidence.CERTAIN,
                    "Permissive Cross-Origin Resource Sharing may allow an attacker to steal sensitive data from unsuspecting users. For this to work, the application must implement some form of authentication that the browser will automatically include with requests (think cookies, basic auth, digest but NOT Authorization Bearer). Additionally, if Cookies are used, SameSite will likely need to be EXPLICITLY set to 'None' for the cookie to be sent cross-domain.",
                    "Implementing URL validation in a regex can be tricky. Better to implement a whitelist and have the origin header match EXACTLY those values, otherwise reject. ",
                    AuditIssueSeverity.HIGH,
                    checkRequestResponse.withResponseMarkers(responseHighlights).withRequestMarkers(requestHighlights)
                )
                issues.add(auditIssue)

            }
        }
        return AuditResult.auditResult(issues)

    }


    override fun passiveAudit(p0: HttpRequestResponse?): AuditResult {
        return AuditResult.auditResult()
    }

    override fun consolidateIssues(p0: AuditIssue?, p1: AuditIssue?): ConsolidationAction {
        return ConsolidationAction.KEEP_EXISTING
    }

    private fun getMarkerFromResponse(requestResponse: HttpRequestResponse, match: String): Marker? {
        val start = requestResponse.response().toString().indexOf(match, 0)
        val end = start+match.length
        val marker = Marker.marker(start, end)
        return marker
    }

    private fun getMarkerFromRequest(requestResponse: HttpRequestResponse, match: String): Marker? {
        val start = requestResponse.request().toString().indexOf(match, 0)
        val end = start+match.length
        val marker = Marker.marker(start, end)
        return marker
    }
}
package com.t0xodile.checkcors.corsCheckExtension

import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.Marker
import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.scanner.audit.issues.AuditIssue
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity

object TrustedDomainValidationBypassCheck {
    fun runTrustedDomainValidationBypassCheck(api: MontoyaApi, selectedRequest: HttpRequest, trustedDomain: String) {
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

        val attackerDomain = randSting(12) + ".com"

        val issues = mutableListOf<AuditIssue>()

        for (bypass in bypasses) {
            val originHeaderDomain: String
            //Update placeholders if required
            if (bypass.contains("web-attacker.com") && bypass.contains("example.com")) {
                originHeaderDomain = bypass.replace("example.com", trustedDomain).replace("web-attacker.com", attackerDomain)
            } else if (bypass.contains("web-attacker.com")){
                originHeaderDomain = bypass.replace("web-attacker.com", attackerDomain)
            } else if (bypass.contains("example.com")) {
                originHeaderDomain = bypass.replace("example.com", trustedDomain)
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
            val vulnerableOriginMarker = getMarkerFromResponse(checkRequestResponse, "Access-Control-Allow-Origin: $vulnerableOrigin")

            val exploitOriginMarker = getMarkerFromRequest(checkRequestResponse, "Origin: $vulnerableOrigin")

            val responseHighlights = mutableListOf<Marker?>()
            responseHighlights.add(acacMarker)
            responseHighlights.add(vulnerableOriginMarker)

            val requestHighlights = mutableListOf<Marker?>()
            requestHighlights.add(exploitOriginMarker)

            val auditIssue = AuditIssue.auditIssue(
                "Permissive Cross-Origin Resource Sharing via '$bypass'",
                "This response is reflecting a super-weird origin header value that actually makes it vulnerable. For some special characters you might need to use Safari. This check is based off of this research -> https://corben.io/blog/18-6-16-advanced-cors-techniques | https://github.com/lc/theftfuzzer/tree/master",
                "Validate the 'Origin' header against a whitelist of know-trusted domains and subdomains.",
                selectedRequest.url(),
                AuditIssueSeverity.HIGH,
                AuditIssueConfidence.CERTAIN,
                "Permissive Cross-Origin Resource Sharing may allow an attacker to steal sensitive data from unsuspecting users. For this to work, the application must implement some form of authentication that the browser will automatically include with requests (think cookies, basic auth, digest but NOT Authorization Bearer). Additionally, if Cookies are used, SameSite will likely need to be EXPLICITLY set to 'None' for the cookie to be sent cross-domain.",
                "Implementing URL validation in a regex can be tricky. Better to implement a whitelist and have the origin header match EXACTLY those values, otherwise reject. ",
                AuditIssueSeverity.HIGH,
                checkRequestResponse.withResponseMarkers(responseHighlights).withRequestMarkers(requestHighlights)
            )
            issues.add(auditIssue)
        }
        for (issue in issues) {
            api.siteMap().add(issue)
        }

    }
}
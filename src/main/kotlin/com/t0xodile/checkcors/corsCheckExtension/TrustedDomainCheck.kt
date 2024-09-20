package com.t0xodile.checkcors.corsCheckExtension

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.HttpService
import burp.api.montoya.http.message.requests.HttpRequest
import kotlin.concurrent.thread

object TrustedDomainCheck {
    fun runTrustedDomainCheck(api: MontoyaApi, domains: Map<String, List<String>>, selectedRequest: HttpRequest) {

        //If unloaded, don't do thread stuff anymore.
        if (CorsCheckExtension.unloaded) {
            return
        }
        thread {
            //Loop through the parent domains in domains
            for ((parentDomain, subDomains) in domains) {
                //Loop through the subdomains FOR THE GIVEN PARENT
                for (origin in subDomains) {
                    if (CorsCheckExtension.unloaded) {
                        break
                    }
                    try {
                        //Create the check requests
                        val httpOrigin: String
                        val httpsOrigin: String
                        if (origin != parentDomain) {
                            httpOrigin = "http://$origin.$parentDomain"
                            httpsOrigin = "https://$origin.$parentDomain"
                        } else { //If the origin == the target host, then we are just testing the parent domain, no dots needed.
                            httpOrigin = "http://$origin"
                            httpsOrigin = "https://$origin"
                        }

                        //Send the request
                        //api.logging().logToOutput("Checking if $origin is trusted.")

                        val httpsCheck = selectedRequest.withHeader("Origin", httpsOrigin)
                        val httpCheck = selectedRequest.withHeader("Origin", httpOrigin)

                        val httpsCheckResp = api.http().sendRequest(httpsCheck)
                        val httpCheckResp = api.http().sendRequest(httpCheck)

                        //Check for matching ACAO in https
                        if (!httpsCheckResp.response().hasHeader("Access-Control-Allow-Origin")) {
                            api.logging().logToOutput("ACAO not found... Skipping")
                        }

                        if (httpsCheckResp.response().headerValue("Access-Control-Allow-Origin") == httpsOrigin) {
                            api.logging().logToOutput("Trusted Domain found! $httpsOrigin trusted by ${selectedRequest.httpService().host()}... Launching Permissive CORS scan")
                            TrustedDomainValidationBypassCheck.runTrustedDomainValidationBypassCheck(api, selectedRequest, httpsOrigin.replace("https://", ""))
                        }

                        //Check for matching ACAO in http
                        if (!httpCheckResp.response().hasHeader("Access-Control-Allow-Origin")) {
                            api.logging().logToOutput("ACAO not found... Skipping")
                        }

                        if (httpCheckResp.response().headerValue("Access-Control-Allow-Origin") == httpOrigin) {
                            api.logging().logToOutput("Trusted domain found! $httpOrigin trusted by ${selectedRequest.httpService().host()}... Launching Permissive CORS scan")
                            TrustedDomainValidationBypassCheck.runTrustedDomainValidationBypassCheck(api, selectedRequest, httpOrigin.replace("http://", ""))
                        }
                    } catch (e: Exception) {
                        api.logging().logToError("Error checking CORs for Origin $origin against ${selectedRequest.httpService().host()}")
                    }
                }
            }
            api.logging().logToOutput("Trusted domain scan complete for: ${selectedRequest.httpService().host()}. Check 'All issues' for any reported vulnerabilities")
        }
    }
}

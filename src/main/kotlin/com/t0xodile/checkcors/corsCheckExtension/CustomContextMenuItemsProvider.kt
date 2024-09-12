package com.t0xodile.checkcors.corsCheckExtension

import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.ToolSource
import burp.api.montoya.core.ToolType
import burp.api.montoya.http.HttpService
import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.http.message.StatusCodeClass
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.scanner.AuditResult
import burp.api.montoya.ui.contextmenu.ContextMenuEvent
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider
import burp.api.montoya.ui.contextmenu.InvocationType
import java.awt.BorderLayout
import java.awt.Component
import java.awt.Dimension
import java.util.concurrent.Callable
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.Future
import javax.swing.*
import kotlin.concurrent.thread

class CustomContextMenuItemsProvider(private val api: MontoyaApi) : ContextMenuItemsProvider {
    override fun provideMenuItems(event: ContextMenuEvent): MutableList<JMenuItem> {
        val menuItemList = ArrayList<JMenuItem>()

        val findSubdomains = JMenuItem("Open Trusted Domains Scanner")

        //Target host of selected request
        val selectedRequest = event.messageEditorRequestResponse().get().requestResponse().request()

        //
        findSubdomains.addActionListener {
            SwingUtilities.invokeLater{
                openNewWindow(selectedRequest)
            }
        }
        menuItemList.add(findSubdomains)
        return menuItemList
    }

    private fun openNewWindow(selectedRequest: HttpRequest) {
        SwingUtilities.invokeLater {
            val frame = JFrame("Discovered Subdomains")
            frame.defaultCloseOperation = JFrame.DISPOSE_ON_CLOSE
            frame.setSize(600, 400)
            frame.layout = BorderLayout()

            // Center the window on the screen
            frame.setLocationRelativeTo(null)

            // Create a text area for editable text input
            val textArea = JTextArea(selectedRequest.httpService().host())
            textArea.lineWrap = true
            textArea.wrapStyleWord = true
            textArea.isEditable = true
            textArea.isFocusable = true

            // Add the text area to a scroll pane in case of long content
            val scrollPane = JScrollPane(textArea)
            scrollPane.preferredSize = Dimension(580, 320)
            frame.add(scrollPane, BorderLayout.CENTER)

            // Create the "Run trusted domain scan" button
            val runButton = JButton("Run trusted domain scan")
            runButton.preferredSize = Dimension(200, 40)

            runButton.addActionListener {
                // Close the window when the button is clicked
                frame.dispose()

                // Run the scan, but only if there isn't arbitrary origin reflection. Otherwise no point!
                if (!checkArbitraryOriginReflection(selectedRequest)) {
                    runTrustedDomainScan(textArea.text, selectedRequest)
                }
            }

            // Add the button to the bottom of the frame
            frame.add(runButton, BorderLayout.SOUTH)

            // Show the window
            frame.isVisible = true
        }
    }

    // Runs the scan for trusted domains based on user input
    private fun runTrustedDomainScan(domainsText: String, selectedRequest: HttpRequest) {
        // Split the text area content by newlines to get the list of domains
        val parentDomains = domainsText.split("\n").map { it.trim() }.filter { it.isNotEmpty() }

        val allDomains = mutableMapOf<String, MutableList<String>>()

        // Set up the countdown latch to wait for all subdomain lookups to finish
        val latch = CountDownLatch(parentDomains.size)

        for (domain in parentDomains) {
            // Don't do stuff if we're unloaded
            if (CorsCheckExtension.unloaded) {
                break
            }
            thread {
                try {
                    api.logging().logToOutput("Looking up subdomains for: $domain")
                    val url = "https://columbus.elmasy.com/api/lookup/$domain"
                    val apiResp = api.http().sendRequest(HttpRequest.httpRequestFromUrl(url).withHeader("Accept", "text/plain"))

                    //Create a list of subdomains for this specific parent domain
                    val subDomainsForParent = mutableListOf<String>()

                    //Add a the OG target domain in case it trusts itself!
                    subDomainsForParent.add(domain)

                    //Only add remaining domains to list if we get a successful response!
                    if (apiResp.response().statusCode().toInt() == 200) {
                        val subDomainsList = apiResp.response().bodyToString().split("\n").map { it.trim() }.filter { it.isNotEmpty() }

                        //Add the remaining subDomains to the big list
                        subDomainsForParent.addAll(subDomainsList)
                    }

                    //Add the list of subdomains to the map with the parent domain as they key
                    synchronized(allDomains) {
                        allDomains[domain] = subDomainsForParent
                    }

                } catch (e: Exception) {
                    api.logging().logToError("Error looking up $domain: ${e.message}")
                } finally {
                    // Decrement the latch count when the thread finishes
                    latch.countDown()
                }
            }
        }

        // Wait for all threads to finish before continuing
        latch.await()

        // Log the selected domain
        api.logging().logToOutput("Selected domain for CORS checks: ${selectedRequest.httpService()}")

        // Send the selected domain and subdomains for CORS check
        TrustedDomainCheck.runTrustedDomainCheck(api, allDomains, selectedRequest)
    }

    private fun checkArbitraryOriginReflection(selectedRequest: HttpRequest): Boolean {
        val attackerDomain = randSting(12) + ".com"
        //Check if we have arbitrary origin reflection. If we do, just give-up burp will handle this for us and we don't want to report all of these bypasses....
        val arbitraryOriginCheckRequest = selectedRequest.withHeader("Origin", attackerDomain)

        val executor = Executors.newSingleThreadExecutor()
        val future: Future<Boolean> = executor.submit(Callable {
            try {
                val arbitraryOrigincheckRequestResponse = api.http().sendRequest(arbitraryOriginCheckRequest)
                if (arbitraryOrigincheckRequestResponse.response().headerValue("Access-Control-Allow-Credentials") == "true" && arbitraryOrigincheckRequestResponse.response().headerValue("Access-Control-Allow-Origin") == attackerDomain) {
                    api.logging().logToOutput("Arbitrary Reflected Origin found, skipping because burp will handle this for us.")
                    return@Callable true
                } else {
                    return@Callable false
                }
            } catch (e: Exception) {
                api.logging().logToError("Error during request: ${e.message}")
                return@Callable false
            }
        })

        val result = future.get()
        executor.shutdown()
        return result
    }

    private fun randSting(length: Int): String {
        val chars = "abcdefghijklmnopqrstucwxyz"
        return (1..length).map{ chars.random() }.joinToString("")
    }
}
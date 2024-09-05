package com.t0xodile.checkcors.corsCheckExtension

import burp.api.montoya.BurpExtension
import burp.api.montoya.MontoyaApi

class CorsCheckExtension : BurpExtension {
    override fun initialize(api: MontoyaApi?) {
        if (api == null) {
            return
        }

        val name = "T0xodile's Cors Check"
        api.extension().setName(name)
        api.logging().logToOutput("Loaded $name")
        api.scanner().registerScanCheck(CorsScannerCheck(api))
    }
}
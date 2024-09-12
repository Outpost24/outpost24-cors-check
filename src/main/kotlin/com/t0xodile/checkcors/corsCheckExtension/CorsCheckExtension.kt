package com.t0xodile.checkcors.corsCheckExtension

import burp.api.montoya.BurpExtension
import burp.api.montoya.MontoyaApi

class CorsCheckExtension : BurpExtension {
    //Store threads
    companion object {
        var unloaded = false
    }

    override fun initialize(api: MontoyaApi?) {
        if (api == null) {
            return
        }

        val name = "t0xodile's Cors Check"
        api.extension().setName(name)
        api.logging().logToOutput("Loaded $name")

        //Scan checks
        api.scanner().registerScanCheck(CorsScannerCheck(api))

        //Register context menu interface
        api.userInterface().registerContextMenuItemsProvider(CustomContextMenuItemsProvider(api))

        //Register unloading handler
        api.extension().registerUnloadingHandler {
            unloaded = true

            api.logging().logToOutput("Unloading Extension...")
        }
    }
}
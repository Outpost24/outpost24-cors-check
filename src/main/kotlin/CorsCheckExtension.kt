import burp.api.montoya.BurpExtension
import burp.api.montoya.MontoyaApi
import javax.swing.JCheckBoxMenuItem
import javax.swing.JMenu

class CorsCheckExtension : BurpExtension {
    companion object {
        var unloaded = false
        var scanCheckEnabled = true
    }

    override fun initialize(api: MontoyaApi?) {
        if (api == null) {
            return
        }

        val name = "t0xodile's CORS Check"
        api.extension().setName(name)
        api.logging().logToOutput("Loaded $name")

        //Register top-level menu bar
        val topMenu = JMenu(name)

        val disableScanCheck = JCheckBoxMenuItem("Enable CORS active scan check", scanCheckEnabled)

        disableScanCheck.addActionListener {
            scanCheckEnabled = !scanCheckEnabled

            if (!scanCheckEnabled) {
                api.logging().logToOutput("Disabled scan check.")
            } else {
                api.logging().logToOutput("Enabled scan check.")
            }
        }

        topMenu.add(disableScanCheck)


        api.userInterface().menuBar().registerMenu(topMenu)


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
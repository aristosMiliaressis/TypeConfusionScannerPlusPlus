import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;

public class TypeConfusionScanner implements BurpExtension {
    @Override
    public void initialize(MontoyaApi api)
    {
        api.extension().setName("TypeConfusionScannerPlusPlus");

        api.scanner().registerScanCheck(new TypeConfusionCheck(api));

        api.logging().logToOutput("TypeConfusionScannerPlusPlus loaded successfully.");
    }
}

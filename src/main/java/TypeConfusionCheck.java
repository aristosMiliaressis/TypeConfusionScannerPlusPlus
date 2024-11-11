import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.core.Marker;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.requests.HttpRequest;
import static burp.api.montoya.scanner.AuditResult.auditResult;
import static burp.api.montoya.scanner.audit.issues.AuditIssue.auditIssue;

import burp.api.montoya.scanner.AuditResult;
import burp.api.montoya.scanner.ConsolidationAction;
import burp.api.montoya.scanner.ScanCheck;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPointType;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.http.message.ContentType;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class TypeConfusionCheck implements ScanCheck {

    private final MontoyaApi api;
    private final String _fuzzyPayload = "s:dfh@%^124g2376#@<<";

    TypeConfusionCheck(MontoyaApi api)
    {
        this.api = api;
    }

    @Override
    public AuditResult activeAudit(HttpRequestResponse baseRequestResponse, AuditInsertionPoint auditInsertionPoint) {
        try
        {
            var url = baseRequestResponse.request().url();
            var insertionPointType = auditInsertionPoint.type();
            var insertionPointName = auditInsertionPoint.name();

            List<AuditInsertionPointType> insertionPointBlackList = new ArrayList<AuditInsertionPointType>()
            {
                {
                    add(AuditInsertionPointType.ENTIRE_BODY);
                    add(AuditInsertionPointType.EXTENSION_PROVIDED);
                    add(AuditInsertionPointType.HEADER);
                    add(AuditInsertionPointType.PARAM_AMF);
                    add(AuditInsertionPointType.PARAM_COOKIE);
                    add(AuditInsertionPointType.PARAM_MULTIPART_ATTR);
                    add(AuditInsertionPointType.PARAM_XML);
                    add(AuditInsertionPointType.PARAM_XML_ATTR);
                    add(AuditInsertionPointType.UNKNOWN);
                    add(AuditInsertionPointType.URL_PATH_FILENAME);
                    add(AuditInsertionPointType.URL_PATH_FOLDER);
                    add(AuditInsertionPointType.USER_PROVIDED);
                    add(AuditInsertionPointType.PARAM_NAME_URL);
                    add(AuditInsertionPointType.PARAM_NAME_BODY);
                }
            };
            if (insertionPointBlackList.contains(insertionPointType))
                return auditResult(new ArrayList<AuditIssue>());

            api.logging().logToOutput("Scanning '" + insertionPointName + "' of type " + insertionPointType.name() + " on url " + url);

            if (insertionPointType == AuditInsertionPointType.PARAM_URL)
                return testQueryStringInsertionPoint(baseRequestResponse, auditInsertionPoint);
            else
                return testBodyInsertionPoint(baseRequestResponse, auditInsertionPoint);
        } catch (Exception ex) {
            api.logging().logToOutput(ex.getMessage());
            return auditResult(new ArrayList<AuditIssue>());
        }
    }

    @Override
    public AuditResult passiveAudit(HttpRequestResponse baseRequestResponse) {
        return auditResult(new ArrayList<AuditIssue>());
    }

    @Override
    public ConsolidationAction consolidateIssues(AuditIssue newIssue, AuditIssue existingIssue) {
        if (existingIssue.detail().equals(newIssue.detail()))
            return ConsolidationAction.KEEP_EXISTING;

        return ConsolidationAction.KEEP_BOTH;
    }

    private AuditResult testQueryStringInsertionPoint(HttpRequestResponse baseRequestResponse, AuditInsertionPoint auditInsertionPoint) {
        var auditIssues = new ArrayList<AuditIssue>();
        var insertionPointName = auditInsertionPoint.name();

        var baseRequest =  baseRequestResponse.request();
        var url = baseRequest.url();
        var baseRequestQuery = baseRequest.query();
        var baseValue = auditInsertionPoint.baseValue();

        // false positive check #1: test if putting garbage in the param changes the response
        var checkRequest = auditInsertionPoint.buildHttpRequestWithPayload(ByteArray.byteArray(_fuzzyPayload));

        checkRequest = checkRequest.withService(baseRequestResponse.httpService());

        var checkRequestResponse = api.http().sendRequest(checkRequest);

        if (!detectChange(baseRequestResponse, checkRequestResponse)) {
            return auditResult(auditIssues);
        }

        // false positive check #2: test if removing the param changes the response
        var param = baseRequest.parameter(insertionPointName, HttpParameterType.URL);
        checkRequest = baseRequest.withRemovedParameters(param);

        checkRequest = checkRequest.withService(baseRequestResponse.httpService());

        checkRequestResponse = api.http().sendRequest(checkRequest);

        if (!detectChange(baseRequestResponse, checkRequestResponse)) {
            return auditResult(auditIssues);
        }

        var payload = String.format("%s=%s&%s=%s1", insertionPointName, api.utilities().urlUtils().encode(baseValue), insertionPointName, api.utilities().urlUtils().encode(baseValue));
        var modifiedQuery = baseRequestQuery
                .replaceFirst(insertionPointName+"=[^&#$]*", payload);

        checkRequest = HttpRequest.httpRequest(baseRequest.toString().replaceFirst(baseRequest.method() + " .+ HTTP\\/", baseRequest.method() + " "+baseRequest.pathWithoutQuery()+"?"+modifiedQuery + " HTTP/"))
                .withService(baseRequestResponse.httpService());

        checkRequestResponse = api.http().sendRequest(checkRequest);

        if (!detectChange(baseRequestResponse, checkRequestResponse)) {
            var requestHighlights = auditInsertionPoint.issueHighlights(ByteArray.byteArray(payload));
            var highlights = new ArrayList<Marker>();
            var offset = insertionPointName.length() + 1;
            var marker = Marker.marker(requestHighlights.get(0).startIndexInclusive() - offset, requestHighlights.get(0).endIndexExclusive() - offset);
            highlights.add(marker);

            auditIssues.add(auditIssue(
                    "Array confusion found in urlencoded query parameter",
                    "The response to the modified request has the same status and similar length to the base request. The value <b>" + baseValue + "</b>, was resubmitted as an array <b>" + payload + "</b> and the response was the same.",
                    null,
                    url,
                    AuditIssueSeverity.INFORMATION,
                    AuditIssueConfidence.FIRM,
                    null,
                    null,
                    AuditIssueSeverity.INFORMATION,
                    checkRequestResponse.withRequestMarkers(highlights)
            ));
        }
        
        payload = String.format("%s[]=%s&%s[]=%s1", insertionPointName, api.utilities().urlUtils().encode(baseValue), insertionPointName, api.utilities().urlUtils().encode(baseValue));
        modifiedQuery = baseRequestQuery
                .replaceFirst(insertionPointName+"=[^&#$]*", payload);

        checkRequest = HttpRequest.httpRequest(baseRequest.toString().replaceFirst(baseRequest.method() + " .+ HTTP\\/", baseRequest.method() + " "+baseRequest.pathWithoutQuery()+"?"+modifiedQuery + " HTTP/"))
                .withService(baseRequestResponse.httpService());

        checkRequestResponse = api.http().sendRequest(checkRequest);

        if (!detectChange(baseRequestResponse, checkRequestResponse)) {
            var requestHighlights = auditInsertionPoint.issueHighlights(ByteArray.byteArray(payload));
            var highlights = new ArrayList<Marker>();
            var offset = insertionPointName.length() + 1;
            var marker = Marker.marker(requestHighlights.get(0).startIndexInclusive() - offset, requestHighlights.get(0).endIndexExclusive() - offset);
            highlights.add(marker);

            auditIssues.add(auditIssue(
                    "Array confusion found in urlencoded query parameter",
                    "The response to the modified request has the same status and similar length to the base request. The value <b>" + baseValue + "</b>, was resubmitted as an array <b>" + payload + "</b> and the response was the same.",
                    null,
                    url,
                    AuditIssueSeverity.INFORMATION,
                    AuditIssueConfidence.FIRM,
                    null,
                    null,
                    AuditIssueSeverity.INFORMATION,
                    checkRequestResponse.withRequestMarkers(highlights)
            ));
        }
        
        payload = String.format("%s[0]=%s&%s[1]=%s1", insertionPointName, api.utilities().urlUtils().encode(baseValue), insertionPointName, api.utilities().urlUtils().encode(baseValue));
        modifiedQuery = baseRequestQuery
                .replaceFirst(insertionPointName+"=[^&#$]*", payload);

        checkRequest = HttpRequest.httpRequest(baseRequest.toString().replaceFirst(baseRequest.method() + " .+ HTTP\\/", baseRequest.method() + " "+baseRequest.pathWithoutQuery()+"?"+modifiedQuery + " HTTP/"))
                .withService(baseRequestResponse.httpService());

        checkRequestResponse = api.http().sendRequest(checkRequest);

        if (!detectChange(baseRequestResponse, checkRequestResponse)) {
            var requestHighlights = auditInsertionPoint.issueHighlights(ByteArray.byteArray(payload));
            var highlights = new ArrayList<Marker>();
            var offset = insertionPointName.length() + 1;
            var marker = Marker.marker(requestHighlights.get(0).startIndexInclusive() - offset, requestHighlights.get(0).endIndexExclusive() - offset);
            highlights.add(marker);

            auditIssues.add(auditIssue(
                    "Array confusion found in urlencoded query parameter",
                    "The response to the modified request has the same status and similar length to the base request. The value <b>" + baseValue + "</b>, was resubmitted as an array <b>" + payload + "</b> and the response was the same.",
                    null,
                    url,
                    AuditIssueSeverity.INFORMATION,
                    AuditIssueConfidence.FIRM,
                    null,
                    null,
                    AuditIssueSeverity.INFORMATION,
                    checkRequestResponse.withRequestMarkers(highlights)
            ));
        }

        return auditResult(auditIssues);
    }

    private AuditResult testBodyInsertionPoint(HttpRequestResponse baseRequestResponse, AuditInsertionPoint auditInsertionPoint) throws IOException {
        var auditIssues = new ArrayList<AuditIssue>();
        var insertionPointName = auditInsertionPoint.name();

        var baseRequest =  baseRequestResponse.request();
        var url = baseRequest.url();
        var baseRequestBody = baseRequest.body();

        var baseValue = auditInsertionPoint.baseValue();

        if (baseRequest.contentType() == ContentType.JSON) {
            // make sure that json param is in the body
            if (!baseRequestBody.toString().contains("\""+insertionPointName+"\""))
                return auditResult(auditIssues);

            HttpRequest checkRequest = null;

            // check that insertionPoint is being processed at all
            if (getJsonPropertyType(baseRequestBody.toString(), insertionPointName, baseValue).equals("number")) {
                var modifiedBody = baseRequestBody
                        .toString()
                        .replaceFirst("\""+insertionPointName+"\"[\\s]*:[\\s]*"+baseValue, "\""+insertionPointName+"\":65534");
                checkRequest = baseRequest.withBody(modifiedBody);
            } else {
                checkRequest = auditInsertionPoint.buildHttpRequestWithPayload(ByteArray.byteArray(_fuzzyPayload));
            }

            checkRequest = checkRequest.withService(baseRequestResponse.httpService());

            var checkRequestResponse = api.http().sendRequest(checkRequest);

            if (!detectChange(baseRequestResponse, checkRequestResponse)) {
                return auditResult(auditIssues);
            }

            // false positive check #2: test if removing the param changes the response
            var param = baseRequest.parameter(insertionPointName, HttpParameterType.JSON);
            checkRequest = baseRequest.withRemovedParameters(param);

            checkRequest = checkRequest.withService(baseRequestResponse.httpService());

            checkRequestResponse = api.http().sendRequest(checkRequest);

            if (!detectChange(baseRequestResponse, checkRequestResponse)) {
                return auditResult(auditIssues);
            }

            if (!getJsonPropertyType(baseRequestBody.toString(), insertionPointName, baseValue).equals("string")) {
                var payload = ByteArray.byteArray(baseValue);

                checkRequest = auditInsertionPoint
                        .buildHttpRequestWithPayload(payload)
                        .withService(baseRequestResponse.httpService());

                checkRequestResponse = api.http().sendRequest(checkRequest);

                if (!detectChange(baseRequestResponse, checkRequestResponse)) {

                    var requestHighlights = auditInsertionPoint.issueHighlights(payload);
                    List<Marker> highlights = new ArrayList<Marker>();
                    var marker = Marker.marker(requestHighlights.get(0).startIndexInclusive(), requestHighlights.get(0).endIndexExclusive());
                    highlights.add(marker);

                    auditIssues.add(auditIssue(
                            "Type confusion found in JSON body",
                            "The response to the modified request has the same status and similar length to the base request. The value <b>" + baseValue + "</b>, was resubmitted as a string <b>" + payload + "</b> and the response was the same.",
                            null,
                            url,
                            AuditIssueSeverity.INFORMATION,
                            AuditIssueConfidence.FIRM,
                            null,
                            null,
                            AuditIssueSeverity.INFORMATION,
                            checkRequestResponse.withRequestMarkers(highlights)
                    ));
                }
            }

            if (!getJsonPropertyType(baseRequestBody.toString(), insertionPointName, baseValue).equals("string")) {
                return auditResult(auditIssues);
            }

            var payload = "\""+insertionPointName+"\":["+getJsonSerializedValue(baseValue)+"]";
            var modifiedBody = baseRequestBody
                    .toString()
                    .replaceFirst("\""+insertionPointName+"\"[\\s]*:[\\s]*"+getJsonSerializedValue(baseValue), payload);

            checkRequest = baseRequest
                    .withBody(modifiedBody)
                    .withService(baseRequestResponse.httpService());

            checkRequestResponse = api.http().sendRequest(checkRequest);

            if (!detectChange(baseRequestResponse, checkRequestResponse)) {
                var requestHighlights = auditInsertionPoint.issueHighlights(ByteArray.byteArray(payload));
                var highlights = new ArrayList<Marker>();
                var marker = Marker.marker(requestHighlights.get(0).startIndexInclusive(), requestHighlights.get(0).endIndexExclusive());
                highlights.add(marker);

                auditIssues.add(auditIssue(
                        "Array confusion found in JSON body",
                        "The response to the modified request has the same status and similar length to the base request. The value <b>" + baseValue + "</b>, was resubmitted as an array <b>" + payload + "</b> and the response was the same.",
                        null,
                        url,
                        AuditIssueSeverity.INFORMATION,
                        AuditIssueConfidence.FIRM,
                        null,
                        null,
                        AuditIssueSeverity.INFORMATION,
                        checkRequestResponse.withRequestMarkers(highlights)
                ));
            }

            payload = "\""+insertionPointName+"\":[["+getJsonSerializedValue(baseValue)+"]]";
            modifiedBody = baseRequestBody
                    .toString()
                    .replaceFirst("\""+insertionPointName+"\"[\\s]*:[\\s]*"+getJsonSerializedValue(baseValue), payload);

            checkRequest = baseRequest
                    .withBody(modifiedBody)
                    .withService(baseRequestResponse.httpService());

            checkRequestResponse = api.http().sendRequest(checkRequest);

            if (!detectChange(baseRequestResponse, checkRequestResponse)) {
                var requestHighlights = auditInsertionPoint.issueHighlights(ByteArray.byteArray(payload));
                var highlights = new ArrayList<Marker>();
                var marker = Marker.marker(requestHighlights.get(0).startIndexInclusive(), requestHighlights.get(0).endIndexExclusive());
                highlights.add(marker);

                auditIssues.add(auditIssue(
                        "Nested Array confusion found in JSON body",
                        "The response to the modified request has the same status and similar length to the base request. The value <b>" + baseValue + "</b>, was resubmitted as a nested array <b>" + payload + "</b> and the response was the same.",
                        null,
                        url,
                        AuditIssueSeverity.INFORMATION,
                        AuditIssueConfidence.FIRM,
                        null,
                        null,
                        AuditIssueSeverity.INFORMATION,
                        checkRequestResponse.withRequestMarkers(highlights)
                ));
            }
        } else if (baseRequest.contentType() == ContentType.URL_ENCODED) {

            // false positive check #1: test if putting garbage in the param changes the response
            var checkRequest = auditInsertionPoint.buildHttpRequestWithPayload(ByteArray.byteArray(_fuzzyPayload));

            checkRequest = checkRequest.withService(baseRequestResponse.httpService());

            var checkRequestResponse = api.http().sendRequest(checkRequest);

            if (!detectChange(baseRequestResponse, checkRequestResponse)) {
                return auditResult(auditIssues);
            }

            // false positive check #2: test if removing the param changes the response
            var param = baseRequest.parameter(insertionPointName, HttpParameterType.BODY);
            checkRequest = baseRequest.withRemovedParameters(param);

            checkRequest = checkRequest.withService(baseRequestResponse.httpService());

            checkRequestResponse = api.http().sendRequest(checkRequest);

            if (!detectChange(baseRequestResponse, checkRequestResponse)) {
                return auditResult(auditIssues);
            }

            var payload = String.format("%s=%s&%s=%s2", insertionPointName, api.utilities().urlUtils().encode(baseValue), insertionPointName, api.utilities().urlUtils().encode(baseValue));

            var modifiedBody = baseRequest.body()
                    .toString()
                    .replaceFirst(insertionPointName+"=[^&#$]*", payload);

            checkRequest = baseRequest.withBody(modifiedBody)
                    .withService(baseRequestResponse.httpService());

            checkRequestResponse = api.http().sendRequest(checkRequest);

            if (!detectChange(baseRequestResponse, checkRequestResponse)) {
                var requestHighlights = auditInsertionPoint.issueHighlights(ByteArray.byteArray(payload));
                var highlights = new ArrayList<Marker>();
                var offset = insertionPointName.length() + 1;
                var marker = Marker.marker(requestHighlights.get(0).startIndexInclusive() - offset, requestHighlights.get(0).endIndexExclusive() - offset);
                highlights.add(marker);

                auditIssues.add(auditIssue(
                        "Array confusion found in urlencoded body parameter",
                        "The response to the modified request has the same status and similar length to the base request. The value <b>" + baseValue + "</b>, was resubmitted as an array <b>" + payload + "</b> and the response was the same.",
                        null,
                        url,
                        AuditIssueSeverity.INFORMATION,
                        AuditIssueConfidence.FIRM,
                        null,
                        null,
                        AuditIssueSeverity.INFORMATION,
                        checkRequestResponse.withRequestMarkers(highlights)
                ));
            }
            
            payload = String.format("%s[]=%s&%s[]=%s2", insertionPointName, api.utilities().urlUtils().encode(baseValue), insertionPointName, api.utilities().urlUtils().encode(baseValue));

            modifiedBody = baseRequest.body()
                    .toString()
                    .replaceFirst(insertionPointName+"=[^&#$]*", payload);

            checkRequest = baseRequest.withBody(modifiedBody)
                    .withService(baseRequestResponse.httpService());

            checkRequestResponse = api.http().sendRequest(checkRequest);

            if (!detectChange(baseRequestResponse, checkRequestResponse)) {
                var requestHighlights = auditInsertionPoint.issueHighlights(ByteArray.byteArray(payload));
                var highlights = new ArrayList<Marker>();
                var offset = insertionPointName.length() + 1;
                var marker = Marker.marker(requestHighlights.get(0).startIndexInclusive() - offset, requestHighlights.get(0).endIndexExclusive() - offset);
                highlights.add(marker);

                auditIssues.add(auditIssue(
                        "Array confusion found in urlencoded body parameter",
                        "The response to the modified request has the same status and similar length to the base request. The value <b>" + baseValue + "</b>, was resubmitted as an array <b>" + payload + "</b> and the response was the same.",
                        null,
                        url,
                        AuditIssueSeverity.INFORMATION,
                        AuditIssueConfidence.FIRM,
                        null,
                        null,
                        AuditIssueSeverity.INFORMATION,
                        checkRequestResponse.withRequestMarkers(highlights)
                ));
            }
            
            payload = String.format("%s[0]=%s&%s[1]=%s2", insertionPointName, api.utilities().urlUtils().encode(baseValue), insertionPointName, api.utilities().urlUtils().encode(baseValue));

            modifiedBody = baseRequest.body()
                    .toString()
                    .replaceFirst(insertionPointName+"=[^&#$]*", payload);

            checkRequest = baseRequest.withBody(modifiedBody)
                    .withService(baseRequestResponse.httpService());

            checkRequestResponse = api.http().sendRequest(checkRequest);

            if (!detectChange(baseRequestResponse, checkRequestResponse)) {
                var requestHighlights = auditInsertionPoint.issueHighlights(ByteArray.byteArray(payload));
                var highlights = new ArrayList<Marker>();
                var offset = insertionPointName.length() + 1;
                var marker = Marker.marker(requestHighlights.get(0).startIndexInclusive() - offset, requestHighlights.get(0).endIndexExclusive() - offset);
                highlights.add(marker);

                auditIssues.add(auditIssue(
                        "Array confusion found in urlencoded body parameter",
                        "The response to the modified request has the same status and similar length to the base request. The value <b>" + baseValue + "</b>, was resubmitted as an array <b>" + payload + "</b> and the response was the same.",
                        null,
                        url,
                        AuditIssueSeverity.INFORMATION,
                        AuditIssueConfidence.FIRM,
                        null,
                        null,
                        AuditIssueSeverity.INFORMATION,
                        checkRequestResponse.withRequestMarkers(highlights)
                ));
            }
        }

        return auditResult(auditIssues);
    }

    private boolean detectChange(HttpRequestResponse baseRequestResponse, HttpRequestResponse checkRequestResponse) {
        var baseResponse = baseRequestResponse.response();
        var checkResponse = checkRequestResponse.response();

        if (baseResponse.statusCode() != checkResponse.statusCode())
            return true;

        var baseResponseBodyLength = baseResponse.body().length();
        var checkResponseBodyLength = checkResponse.body().length();

        return baseResponseBodyLength > checkResponseBodyLength + checkResponseBodyLength / 100 * 40
            || checkResponseBodyLength > baseResponseBodyLength + baseResponseBodyLength / 100 * 40;
    }

    private String getJsonPropertyType(String json, String baseName, String baseValue) throws JsonProcessingException {
        var mapper = new ObjectMapper();
        var jsonValue = mapper.writeValueAsString(baseValue);

        Pattern pattern = Pattern.compile("\""+baseName+"\"[\\s]*:[\\s]*"+jsonValue);
        Matcher matcher = pattern.matcher(json);
        boolean matchFound = matcher.find();

        return matchFound
                ? "string"
                : jsonValue.startsWith("{")
                ? "object"

                : jsonValue.startsWith("[")
                ? "array"
                : jsonValue.equals("true") || jsonValue.equals("false")
                ? "bool"
                : "number";
    }

    private String getJsonSerializedValue(String value) throws JsonProcessingException {
        var mapper = new ObjectMapper();
        return mapper.writeValueAsString(value);
    }
}

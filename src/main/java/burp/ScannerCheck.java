/*
#    Copyright (C) 2019 Alexandre Teyar

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

# http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
#    limitations under the License.
*/

package burp;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;

public class ScannerCheck implements IScannerCheck {

  private IBurpExtenderCallbacks burpExtenderCallbacks;

  private List<String> hosts = new ArrayList<>();

  ScannerCheck(IBurpExtenderCallbacks burpExtenderCallbacks) {
    this.burpExtenderCallbacks = burpExtenderCallbacks;
  }

  // TODO: Ensure that CrimeFlare sends a response back, if blacklisted print an alert
  private boolean queryCrimeFlare(String host) {
    IExtensionHelpers helpers = this.burpExtenderCallbacks.getHelpers();
    byte[] response;

    try {
      URL url = new URL("http://www.crimeflare.org:82/cgi-bin/cfsearch.cgi");
      byte[] request = helpers.buildHttpRequest(url);
      request = helpers
          .addParameter(request, helpers.buildParameter("cfS", host, IParameter.PARAM_BODY));
      request = helpers.toggleRequestMethod(request);

      // this.burpExtenderCallbacks.printOutput(helpers.bytesToString(request));
      response = burpExtenderCallbacks
          .makeHttpRequest("crimeflare.org", 82, false, request);
      // this.burpExtenderCallbacks.printOutput(helpers.bytesToString(response));

      if (helpers.bytesToString(response).contains("these are not CloudFlare-user nameservers.")) {
        this.burpExtenderCallbacks.printOutput("No entry found in the CloudFlare database");
        return false;
      } else {
        this.burpExtenderCallbacks.printOutput("Existing entry found in the CloudFlare database");
        return true;
      }
    } catch (MalformedURLException e) {
      this.burpExtenderCallbacks
          .printError(String.format("%s", e.getMessage()));
      this.burpExtenderCallbacks
          .issueAlert(String.format("%s", e.getMessage()));
    }

    return false;
  }

  @Override
  public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse) {
    List<IScanIssue> scanIssues = new ArrayList<>();
    String host = baseRequestResponse.getHttpService().getHost();

    // TODO: Check that the below code behaves as expected, and that we are not sending
    // TODO: more than 1 request to CrimeFlare per host being scanned
    // Check if the host has already been queried against the CrimeFlare database in order to
    // reduce the total number of requests sent
    if (!this.hosts.contains(host)) {
      if (queryCrimeFlare(host)) {
        scanIssues.add(new ScanIssue(this.burpExtenderCallbacks, baseRequestResponse));
      }
    }

    this.hosts.add(baseRequestResponse.getHttpService().getHost());

    return scanIssues;
  }

  @Override
  public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse,
      IScannerInsertionPoint insertionPoint) {
    return null;
  }

  @Override
  public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue) {
    return -1;
  }
}

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

public class ScanIssue implements IScanIssue {

  private IBurpExtenderCallbacks burpExtenderCallbacks;
  private IHttpRequestResponse httpRequestResponse;

  ScanIssue(IBurpExtenderCallbacks burpExtenderCallbacks,
      IHttpRequestResponse httpRequestResponse) {
    this.burpExtenderCallbacks = burpExtenderCallbacks;
    this.httpRequestResponse = httpRequestResponse;
  }

  @Override
  public URL getUrl() {
    try {
      return new URL("http://www.notworkingyet.co.uk");
    } catch (MalformedURLException e) {
      e.printStackTrace();
    }

    // TODO: Troubleshot the following code which is not working for some obscure reasons...
//    return this.burpExtenderCallbacks.getHelpers()
//        .analyzeRequest(this.httpRequestResponse.getRequest()).getUrl();
    return null;
  }

  @Override
  public String getIssueName() {
    return "CloudFlare bypass";
  }

  @Override
  public int getIssueType() {
    return 0;
  }

  @Override
  public String getSeverity() {
    return "High";
  }

  @Override
  public String getConfidence() {
    return "Certain";
  }

  @Override
  public String getIssueBackground() {
    return
        "<p>CloudFlare is a web infrastructure and website security company, providing content "
            + "delivery network services, DDoS mitigation, Internet security, and distributed "
            + "domain name server services. CloudFlare's services sit between a website's visitor "
            + "and the CloudFlare user's hosting provider, acting as a reverse proxy for "
            + "websites.</p>"
            + ""
            + "<p>Using CrimeFlare it was possible to obtain the IP address(es) of the application "
            + "server(s) sitting behind the CloudFlare. With this information an attacker could "
            + "directly target the application server(s), effectively bypassing the layer of "
            + "protection offered by CloudFlare. To do so, an attacker would need to direct its "
            + "network traffic to the discovered IP address(es) without omitting to set the "
            + "\"Host\" header of its HTTP(S) requests to the relevant hostname in order for the "
            + "server to route the traffic to the relevant application.</p>";
  }

  @Override
  public String getRemediationBackground() {
    return "<p>It is strongly advised to set firewall rules on the application server(s) so that "
        + "only web requests from CloudFlare and IP addresses that the application may require "
        + "access to are authorised. This will prevent attackers from performing Denial of Service "
        + "(DoS) attacks or any other type of attacks that CloudFlare could hinder or prevent "
        + "altogether.</p>";

  }

  @Override
  public String getIssueDetail() {
    return
        "<p>The application is protected by CloudFlare. However, it appears that CrimeFlare was "
            + "able to determine the application server(s) real IP address(es). This means that "
            + "bypassing CloudFlare using the application server IP(s) and HTTP \"Host\" header "
            + "should be possible.</p>"
            + ""
            + "<p>Please visit <a href=\"http://www.crimeflare.org:82/cgi-bin/cfsearch.cgi\">"
            + "CrimeFlare</a> to manually investigate and validate this issue.</p>";
  }

  @Override
  public String getRemediationDetail() {
    return "<p>Consider adding firewall rules (whitelist approach) to the application server(s) to "
        + "limit direct access using the its supposed to be hidden IP address(es).</p>";
  }

  @Override
  public IHttpRequestResponse[] getHttpMessages() {
    return new IHttpRequestResponse[0];
  }

  @Override
  public IHttpService getHttpService() {
    return this.httpRequestResponse.getHttpService();
  }
}

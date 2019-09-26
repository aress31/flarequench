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

  // private IBurpExtenderCallbacks burpExtenderCallbacks;
  private IHttpRequestResponse httpRequestResponse;

  ScanIssue(IBurpExtenderCallbacks burpExtenderCallbacks,
      IHttpRequestResponse httpRequestResponse) {
    // this.burpExtenderCallbacks = burpExtenderCallbacks;
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
    return "Cloudflare bypass";
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
        "<p>Cloudflare is a web infrastructure and website security company, providing content "
            + "delivery network services, DDoS mitigation, Internet security, and distributed "
            + "domain name server services. Cloudflare's services sit between a website's visitor "
            + "and the Cloudflare customer's hosting provider, acting as a reverse proxy for "
            + "websites.</p>"
            + ""
            + "<p>It was possible to obtain the application's origin IP(s) which represent the"
            + "server(s) sitting behind Cloudflare. With this information an attacker could"
            + "directly target the application server(s), effectively bypassing the layer of "
            + "protection offered by Cloudflare. To exploit this, an attacker would need to "
            + "redirect their network traffic to the discovered origin IP(s) and manipulate the "
            + "\"Host\" header of their HTTP(S) requests to the relevant hostname in order to "
            + "ensure that the application's origin server is still able to route the traffic "
            + "to the correct virtual host. This destination IP and host header manipulation "
            + "can be achieved automatically using the Target Redirector Burp extension "
            + "available in the Burp App Store.</p>"
            + ""
            + "<p>When using this approach, keep in mind that behind Cloudflare, the naked "
            + "application might be hosted from a different TCP port than that which Cloudflare "
            + "presented it on. A port scan of the origin IP and a process of elimination can "
            + "help to identify the correct port. The Target Redirector extension can also "
            + "automatically change the port, as well as switch between HTTP and HTTPS "
            + "necessary.</p>";
  }

  @Override
  public String getRemediationBackground() {
    return "<p>It is strongly advised to set firewall rules on the application server(s) so that "
        + "only web requests from Cloudflare and IP addresses that the application may require "
        + "access to are authorised. This will prevent attackers from performing Denial of Service "
        + "(DoS) attacks or any other type of attacks that Cloudflare could hinder or prevent "
        + "altogether.</p>";
  }

  @Override
  public String getIssueDetail() {
    return
        "<p>The application is protected by Cloudflare. However, it appears that CrimeFlare was "
            + "able to determine the application server(s) origin IP address(es). This means that "
            + "bypassing Cloudflare using the application's origin IP(s) and HTTP \"Host\" header "
            + "should be possible. This can be achieved automatically using the Target Redirector "
            + "Burp extension available in the Burp App store.</p>"
            + ""
            + "<p>Please visit <a href=\"http://www.crimeflare.org:82/cgi-bin/cfsearch.cgi\">"
            + "CrimeFlare</a> to manually investigate and validate this issue.</p>";
  }

  @Override
  public String getRemediationDetail() {
    return "<p>Consider protecting the application server(s) with firewall rules which whitelist "
        + "Cloudflare's network and prevent access from any other IP ranges.</p>";
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

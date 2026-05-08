from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Tuple


# Domain validation pattern: allows labels with alphanumeric and hyphens,
# must start/end with alphanumeric, max 63 chars per label, max 253 chars total.
# Also allows wildcard prefix (*.example.com) for subdomain matching.
_DOMAIN_LABEL_RE = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$")

PRIVATE_NETS_V4 = [
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "127.0.0.0/8",
    "169.254.0.0/16",
]


@dataclass(frozen=True)
class CompatibilityPreset:
    id: str
    title: str
    description: str
    domains: Tuple[str, ...]


COMPATIBILITY_PRESETS: Tuple[CompatibilityPreset, ...] = (
    CompatibilityPreset(
        id="discord",
        title="Discord",
        description="Voice/chat gateway, API, media, and CDN hosts commonly sensitive to TLS interception.",
        domains=("discord.com", "*.discord.com", "discord.gg", "*.discord.gg", "discordapp.com", "*.discordapp.com", "discordapp.net", "*.discordapp.net"),
    ),
    CompatibilityPreset(
        id="microsoft-cloud",
        title="Microsoft cloud / Windows update",
        description="Source-backed Microsoft 365 Optimize/Allow, Entra sign-in, Teams, Windows Update, Microsoft Store, Edge update, and GitHub/Copilot endpoints that Microsoft or appliance vendors recommend bypassing for TLS break-and-inspect.",
        domains=(
            "outlook.cloud.microsoft", "outlook.office.com", "outlook.office365.com", "*.sharepoint.com",
            "*.auth.microsoft.com", "*.lync.com", "*.mail.protection.outlook.com", "*.msftidentity.com", "*.msidentity.com", "*.mx.microsoft",
            "*.officeapps.live.com", "*.online.office.com", "*.protection.office.com", "*.protection.outlook.com", "*.security.microsoft.com",
            "*.teams.cloud.microsoft", "*.teams.microsoft.com", "account.activedirectory.windowsazure.com", "accounts.accesscontrol.windows.net",
            "adminwebservice.microsoftonline.com", "api.passwordreset.microsoftonline.com", "autologon.microsoftazuread-sso.com",
            "becws.microsoftonline.com", "ccs.login.microsoftonline.com", "clientconfig.microsoftonline-p.net", "companymanager.microsoftonline.com",
            "compliance.microsoft.com", "defender.microsoft.com", "device.login.microsoftonline.com", "graph.microsoft.com", "graph.windows.net",
            "login-us.microsoftonline.com", "login.microsoft.com", "login.microsoftonline-p.com", "login.microsoftonline.com", "login.windows.net",
            "logincert.microsoftonline.com", "loginex.microsoftonline.com", "nexus.microsoftonline-p.com", "office.live.com",
            "passwordreset.microsoftonline.com", "protection.office.com", "provisioningapi.microsoftonline.com", "purview.microsoft.com",
            "security.microsoft.com", "smtp.office365.com", "teams.cloud.microsoft", "teams.microsoft.com",
            "windowsupdate.com", "*.windowsupdate.com", "*.download.windowsupdate.com", "ctldl.windowsupdate.com",
            "*.delivery.mp.microsoft.com", "*.dl.delivery.mp.microsoft.com", "*.do.dsp.mp.microsoft.com",
            "*.wns.windows.com", "storeedgefd.dsx.mp.microsoft.com", "livetileedge.dsx.mp.microsoft.com", "storecatalogrevocation.storequality.microsoft.com",
            "manage.devcenter.microsoft.com", "displaycatalog.mp.microsoft.com", "*.displaycatalog.mp.microsoft.com", "share.microsoft.com", "licensing.mp.microsoft.com",
            "login.live.com", "img-prod-cms-rt-microsoft-com.akamaized.net", "img-s-msn-com.akamaized.net", "msedge.api.cdp.microsoft.com",
            "microsoft.com", "*.microsoft.com", "office.com", "*.office.com", "office365.com", "*.office365.com",
            "live.com", "*.live.com", "msftauth.net", "*.msftauth.net", "msauth.net", "*.msauth.net",
            "github.com", "*.github.com", "githubcopilot.com", "*.githubcopilot.com",
        ),
    ),
    CompatibilityPreset(
        id="apple-cloud",
        title="Apple services",
        description="Apple explicitly says its services fail with HTTPS interception and to disable inspection for listed enterprise network hosts covering activation, APNs/MDM, software updates, Apps/Books, Apple Account, iCloud, Siri/Search, and Private Cloud Compute.",
        domains=(
            "apple.com", "*.apple.com", "icloud.com", "*.icloud.com", "itunes.com", "*.itunes.com", "mzstatic.com", "*.mzstatic.com",
            "cdn-apple.com", "*.cdn-apple.com", "icloud-content.com", "*.icloud-content.com", "apple-cloudkit.com", "*.apple-cloudkit.com",
            "apple-livephotoskit.com", "*.apple-livephotoskit.com", "apzones.com", "*.apzones.com", "icloud.apple.com", "*.icloud.apple.com",
            "iwork.apple.com", "*.iwork.apple.com", "business.apple.com", "*.business.apple.com", "school.apple.com", "*.school.apple.com",
            "push.apple.com", "*.push.apple.com", "appattest.apple.com", "*.appattest.apple.com", "apple-mapkit.com", "*.apple-mapkit.com",
            "albert.apple.com", "captive.apple.com", "gs.apple.com", "humb.apple.com", "static.ips.apple.com", "tbsc.apple.com",
            "deviceenrollment.apple.com", "deviceservices-external.apple.com", "gdmf.apple.com", "identity.apple.com", "iprofiles.apple.com", "mdmenrollment.apple.com",
            "setup.icloud.com", "vpp.itunes.apple.com", "axm-servicediscovery.apple.com", "appleid.cdn-apple.com", "idmsa.apple.com", "api.ent.apple.com",
            "api.edu.apple.com", "api-business.apple.com", "api-school.apple.com", "axm-adm-enroll.apple.com", "axm-adm-mdm.apple.com", "axm-adm-scep.apple.com",
            "axm-app.apple.com", "icons.axm-usercontent-apple.com", "s.mzstatic.com", "play.itunes.apple.com", "ws-ee-maidsvc.icloud.com", "ws.school.apple.com",
            "pg-bootstrap.itunes.apple.com", "cls-iosclient.itunes.apple.com", "cls-ingest.itunes.apple.com", "appldnld.apple.com", "configuration.apple.com", "gg.apple.com",
            "ig.apple.com", "mesu.apple.com", "oscdn.apple.com", "osrecovery.apple.com", "skl.apple.com", "swcdn.apple.com", "swdist.apple.com",
            "swdownload.apple.com", "swscan.apple.com", "updates-http.cdn-apple.com", "updates.cdn-apple.com", "xp.apple.com", "gdmf-ados.apple.com",
            "gsra.apple.com", "wkms-public.apple.com", "fcs-keys-pub-prod.cdn-apple.com", "account.apple.com", "gsa.apple.com", "mask.icloud.com",
            "mask-h2.icloud.com", "mask-api.icloud.com", "probe.icloud.com", "pong.icloud.com", "metrics.icloud.com", "apple-native-relay.apple.com",
            "guzzoni.apple.com", "*.smoot.apple.com", "apple-relay.cloudflare.com", "apple-relay.fastly-edge.com", "cp4.cloudflare.com",
            "apple-relay.apple.com", "app-site-association.cdn-apple.com", "app-site-association.networking.apple",
        ),
    ),
    CompatibilityPreset(
        id="adobe-cloud",
        title="Adobe Creative Cloud / Acrobat",
        description="Adobe enterprise network endpoint minimum allowlist plus activation, sign-in, update, content, Fonts/Typekit, Stock/Behance, collaboration, and common Adobe CDN/service domains.",
        domains=(
            "adobe.com", "*.adobe.com", "adobe.io", "*.adobe.io", "adobecc.com", "*.adobecc.com", "adobecces.com", "*.adobecces.com",
            "adobeccstatic.com", "*.adobeccstatic.com", "adobedtm.com", "*.adobedtm.com", "adobeexchange.com", "*.adobeexchange.com",
            "adobegenuine.com", "*.adobegenuine.com", "adobegov.com", "*.adobegov.com", "adobe-identity.com", "*.adobe-identity.com",
            "adobejanus.com", "*.adobejanus.com", "adobelogin.com", "*.adobelogin.com", "adobedc.net", "*.adobedc.net",
            "adobeoobe.com", "*.adobeoobe.com", "adobeprojectm.com", "*.adobeprojectm.com", "adobesc.com", "*.adobesc.com",
            "adobe-services.com", "*.adobe-services.com", "adobess.com", "*.adobess.com", "adobesunbreak.com", "*.adobesunbreak.com",
            "adobetag.com", "*.adobetag.com", "behance.net", "*.behance.net", "ftcdn.net", "*.ftcdn.net", "typekit.com", "*.typekit.com",
            "typekit.net", "*.typekit.net", "creativecloud.com", "*.creativecloud.com", "licenses.adobe.com", "*.licenses.adobe.com",
            "lm.licenses.adobe.com", "resources.licenses.adobe.com", "cs.licenses.adobe.com", "exception.licenses.adobe.com", "pubcerts.licenses.adobe.com", "workflow.licenses.adobe.com",
            "auth.services.adobe.com", "adminconsole.adobe.com", "ccmdl.adobe.com", "ccmdls.adobe.com", "swupmf.adobe.com", "swupdl.adobe.com",
            "oobe.adobe.com", "productrouter.adobe.com", "armmf.adobe.com", "ardownload.adobe.com", "ardownload2.adobe.com", "armdl.adobe.com",
            "agsupdate.adobe.com", "ims-na1.adobelogin.com", "ims-prod06.adobelogin.com", "ims-prod07.adobelogin.com", "static.adobelogin.com",
            "delegated.adobelogin.com", "adobeid.services.adobe.com", "adobeid-na1.services.adobe.com", "federatedid-na1.services.adobe.com",
            "ad.adobe-identity.com", "ids-proxy.account.adobe.com", "lcs-cops.adobe.io", "lcs-robs.adobe.io", "lcs-entitlement.adobe.io", "lcs-ulecs.adobe.io",
            "ams.adobe.com", "genuine.adobe.com", "prod.adobegenuine.com", "accounts.adobe.com", "api.account.adobe.com", "assets.adobe.com",
            "assets2.adobe.com", "fonts.adobe.com", "use.typekit.net", "api.typekit.com", "polka.typekit.com", "p.typekit.net", "data.typekit.net",
            "stock.adobe.com", "mir-s3-cdn-cf.behance.net", "slp-statics.astockcdn.net", "cloudfront.net", "*.cloudfront.net", "s3.amazonaws.com", "*.s3.amazonaws.com",
            "s3-accelerate.amazonaws.com", "*.s3-accelerate.amazonaws.com", "firebase-settings.crashlytics.com", "*.googleapis.com", "arkoselabs.com", "*.arkoselabs.com",
        ),
    ),
    CompatibilityPreset(
        id="webex",
        title="Cisco Webex",
        description="Cisco Webex service, API, content, activation, and CDN hostnames; Cisco specifically calls out mcs/cb/mcc Webex traffic for TLS inspection exemption.",
        domains=(
            "webex.com", "*.webex.com", "wbx2.com", "*.wbx2.com", "webexapis.com", "*.webexapis.com", "webexcontent.com", "*.webexcontent.com",
            "activation.webex.com", "cisco.com", "*.cisco.com", "cloudfront.net", "*.cloudfront.net", "akamaiedge.net", "*.akamaiedge.net",
            "akamai.net", "*.akamai.net", "akamaitechnologies.com", "*.akamaitechnologies.com", "fastly.net", "*.fastly.net", "s3.amazonaws.com", "*.s3.amazonaws.com",
        ),
    ),
    CompatibilityPreset(
        id="zoom",
        title="Zoom",
        description="Zoom recommends allowing zoom.us and subdomains through firewall/proxy configurations and commonly recommends bypassing proxy or SSL inspection for Zoom client traffic.",
        domains=("zoom.us", "*.zoom.us"),
    ),
    CompatibilityPreset(
        id="google-meet",
        title="Google Meet / ChromeOS",
        description="Google Meet media/API/static-resource hostnames plus ChromeOS/Chrome Enterprise hostnames Google says must be allowed or exempted for TLS-inspected networks.",
        domains=(
            "meet.google.com", "stream.meet.google.com", "workspace.turns.goog", "meet.turns.goog", "meetings.clients6.google.com",
            "meetings.googleapis.com", "hangouts.googleapis.com", "clients1.google.com", "clients2.google.com", "clients3.google.com", "clients4.google.com",
            "clients5.google.com", "clients6.google.com", "accounts.google.com", "accounts.gstatic.com", "apis.google.com", "apps.google.com", "docs.google.com",
            "feedback.googleusercontent.com", "fonts.gstatic.com", "lh3.googleusercontent.com", "www.gstatic.com", "ssl.gstatic.com", "www.googleapis.com",
            "*.googleapis.com", "*.googleusercontent.com", "*.gstatic.com", "*.ggpht.com", "*.gvt1.com", "*.gvt2.com", "*.gvt3.com", "*.1e100.net",
            "dl.google.com", "dl-ssl.google.com", "edgedl.me.gvt1.com", "m.google.com", "mtalk.google.com", "oauthaccountmanager.googleapis.com",
            "safebrowsing.google.com", "safebrowsing.googleapis.com", "storage.googleapis.com", "update.googleapis.com", "chrome.google.com", "play.google.com",
            "android.clients.google.com", "fcm.googleapis.com", "fcm-xmpp.googleapis.com", "gcm-http.googleapis.com", "gcm-xmpp.googleapis.com", "pki.google.com",
        ),
    ),
    CompatibilityPreset(
        id="collaboration-sync",
        title="Collaboration and sync apps",
        description="Dropbox compatibility domains often excluded from deep TLS inspection by default policies. Webex and Zoom now have dedicated, more complete presets.",
        domains=("dropbox.com", "*.dropbox.com", "dropboxapi.com", "*.dropboxapi.com", "dropboxstatic.com", "*.dropboxstatic.com"),
    ),
    CompatibilityPreset(
        id="developer-collaboration",
        title="Developer and collaboration SaaS",
        description="Source-backed GitHub/Copilot, Slack, Atlassian/Bitbucket, and Dropbox domains commonly needed through restrictive proxies; includes WebSocket/real-time paths that vendors recommend exempting from decryption or proxying.",
        domains=(
            "github.com", "*.github.com", "api.github.com", "uploads.github.com", "codeload.github.com", "lfs.github.com",
            "githubusercontent.com", "*.githubusercontent.com", "raw.githubusercontent.com", "objects.githubusercontent.com", "github-cloud.githubusercontent.com",
            "github-cloud.s3.amazonaws.com", "collector.github.com", "copilot-telemetry.githubusercontent.com", "copilot-proxy.githubusercontent.com",
            "origin-tracker.githubusercontent.com", "githubcopilot.com", "*.githubcopilot.com", "individual.githubcopilot.com", "*.individual.githubcopilot.com",
            "business.githubcopilot.com", "*.business.githubcopilot.com", "enterprise.githubcopilot.com", "*.enterprise.githubcopilot.com", "ghe.com", "*.ghe.com",
            "copilot-reports.github.com", "*.b01.azurefd.net", "*.blob.core.windows.net",
            "slack.com", "*.slack.com", "slack-edge.com", "*.slack-edge.com", "slack-imgs.com", "*.slack-imgs.com", "slack-files.com", "*.slack-files.com",
            "wss-primary.slack.com", "wss-backup.slack.com", "wss-mobile.slack.com", "chime.aws", "*.chime.aws",
            "atlassian.com", "*.atlassian.com", "atlassian.net", "*.atlassian.net", "atl-paas.net", "*.atl-paas.net", "bitbucket.org", "*.bitbucket.org",
            "id.atlassian.com", "api.media.atlassian.com", "product-fabric.atlassian.net", "statuspage.io", "*.statuspage.io",
            "dropbox.com", "*.dropbox.com", "dropboxapi.com", "*.dropboxapi.com", "dropboxstatic.com", "*.dropboxstatic.com",
        ),
    ),
    CompatibilityPreset(
        id="identity-mfa",
        title="Identity and MFA services",
        description="Okta explicitly forbids SSL proxy inspection/modification for Okta Verify/FastPass endpoints; Duo Authentication Proxy uses pinned certificates and customer-specific API hostnames, so this preset includes the stable Okta domains and Duo top-level service/download domains only.",
        domains=(
            "okta.com", "*.okta.com", "oktapreview.com", "*.oktapreview.com", "okta-emea.com", "*.okta-emea.com", "okta-gov.com", "*.okta-gov.com",
            "duosecurity.com", "*.duosecurity.com", "duo.com", "*.duo.com", "dl.duosecurity.com", "admin.duosecurity.com",
        ),
    ),
)


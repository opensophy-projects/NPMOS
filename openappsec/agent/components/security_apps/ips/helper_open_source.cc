#include "helper.h"

#include "config.h"

using namespace std;

namespace IPSHelper
{

// NginxionS: the IPS loads its signatures (IPSSignaturesResource, RuleSelector): they came only from the Check Point
// cloud and obfuscated, so the open source agent left them out; NginxionS gives plain ones (ips-protections.json of its
// image, in the local policy). An obfuscated one still fails to load (deobfuscateString below).
bool has_deobfuscation = true;

bool
hasDeobfuscation()
{
    return has_deobfuscation;
}

string
deobfuscateString(const string &str)
{
    if (str.substr(0, 7) == "M^AGI$C") reportConfigurationError("Deobfuscation isn't available in open-source mode");
    return str;
}

string
deobfuscateKeyword(const string &str)
{
    if (str.substr(0, 7) == "M^AGI$C") reportConfigurationError("Deobfuscation isn't available in open-source mode");
    return str;
}

}  // IPSHelper

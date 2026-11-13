// NginxionS: the sections of the local policy that the agent dropped or wrote wrong (docs/WAF-POLICY.md, phase 11),
// each read back by the configuration class of the engine that uses it.
#include <sstream>
#include <string>
#include <vector>

#include "cptest.h"
#include "access_control_practice.h"
#include "new_custom_response.h"
#include "new_log_trigger.h"
#include "triggers_section.h"
#include "generic_rulebase/match_query.h"
#include "generic_rulebase/triggers_config.h"

using namespace std;
using namespace testing;

template <typename T>
static T
loadFrom(const string &json)
{
    T value;
    stringstream ss(json);
    cereal::JSONInputArchive ar(ss);
    value.load(ar);
    return value;
}

template <typename T>
static string
saveOf(const T &section)
{
    stringstream ss;
    {
        cereal::JSONOutputArchive ar(ss);
        section.save(ar);
    }
    return ss.str();
}

static WebUserResponseTriggerSection
webUserResponseOf(const NewAppSecCustomResponse &response)
{
    // as policy_maker_utils.cc (createWebUserResponseTriggerSection<V1beta2AppsecLinuxPolicy>)
    return WebUserResponseTriggerSection(
        "policy/" + response.getName(),
        response.getMode(),
        response.getMessageBody(),
        response.getHttpResponseCode(),
        response.getMessageTitle(),
        response.getRedirectUrl(),
        response.getRedirectAddXEventId()
    );
}

TEST(LocalPolicySections, redirectResponseReachesTheWebTrigger)
{
    auto response = loadFrom<NewAppSecCustomResponse>(
        "{\"name\": \"to-help\", \"mode\": \"redirect\", \"httpResponseCode\": 403,"
        " \"redirectUrl\": \"https://help.example.com/blocked\", \"redirectAddXEventId\": true}"
    );
    auto conf = loadFrom<WebTriggerConf>(saveOf(webUserResponseOf(response)));
    EXPECT_EQ(conf.getDetailsLevel(), "Redirect");
    EXPECT_EQ(conf.getRedirectURL(), "https://help.example.com/blocked");
    EXPECT_TRUE(conf.getAddEventId());
}

TEST(LocalPolicySections, blockPageKeepsItsCodeAndTexts)
{
    auto response = loadFrom<NewAppSecCustomResponse>(
        "{\"name\": \"page\", \"mode\": \"block-page\", \"httpResponseCode\": 406,"
        " \"messageTitle\": \"Stop\", \"messageBody\": \"Blocked\"}"
    );
    auto conf = loadFrom<WebTriggerConf>(saveOf(webUserResponseOf(response)));
    EXPECT_EQ(conf.getDetailsLevel(), "Block Page");
    EXPECT_EQ(conf.getResponseCode(), 406u);
    EXPECT_EQ(conf.getResponseTitle(), "Stop");
    EXPECT_EQ(conf.getResponseBody(), "Blocked");
    EXPECT_EQ(conf.getRedirectURL(), "");
}

TEST(LocalPolicySections, rateLimitRuleHasItsActionAndConditions)
{
    auto rate_limit = loadFrom<AccessControlRateLimit>(
        "{\"overrideMode\": \"prevent\", \"rules\": [{\"uri\": \"/login\", \"limit\": 5, \"unit\": \"minute\","
        " \"action\": \"detect\", \"condition\": [{\"key\": \"sourceIp\", \"value\": \"10.0.0.1\"}]}]}"
    );
    auto rules = rate_limit.createRateLimitRulesSection(RateLimitRulesTriggerSection());
    ASSERT_EQ(rules.size(), 1u);
    string json = saveOf(rules[0]);
    EXPECT_THAT(json, HasSubstr("\"action\": \"Detect\""));
    EXPECT_THAT(json, HasSubstr("\"match\""));
    EXPECT_THAT(json, HasSubstr("\"sourceIP\""));
}

TEST(LocalPolicySections, rateLimitRuleWithoutActionFollowsThePractice)
{
    auto rate_limit = loadFrom<AccessControlRateLimit>(
        "{\"overrideMode\": \"prevent\", \"rules\": [{\"uri\": \"/\", \"limit\": 5, \"unit\": \"second\"}]}"
    );
    string json = saveOf(rate_limit.createRateLimitRulesSection(RateLimitRulesTriggerSection())[0]);
    EXPECT_THAT(json, HasSubstr("\"action\": \"AccordingToPractice\""));
    // no match: any request (RateLimitRule::default_match)
    EXPECT_THAT(json, Not(HasSubstr("\"match\"")));
}

TEST(LocalPolicySections, rateLimitRuleRejectsWhatTheEngineCannotDo)
{
    EXPECT_THROW(
        loadFrom<AccessControlRateLimit>(
            "{\"overrideMode\": \"prevent\", \"rules\": [{\"uri\": \"/\", \"limit\": 5, \"action\": \"drop\"}]}"
        ),
        PolicyGenException
    );
    EXPECT_THROW(
        loadFrom<AccessControlRateLimit>(
            "{\"overrideMode\": \"prevent\", \"rules\": [{\"uri\": \"/\", \"limit\": 5,"
            " \"condition\": [{\"key\": \"method\", \"value\": \"POST\"}]}]}"
        ),
        PolicyGenException
    );
}

TEST(LocalPolicySections, rateLimitMatchIsReadByTheEngine)
{
    // values of a key: any of them; keys: all of them
    RateLimitRuleMatch match({
        RateLimitRuleCondition("sourceIP", "10.0.0.1"),
        RateLimitRuleCondition("url", "/login"),
        RateLimitRuleCondition("sourceIP", "10.0.0.2")
    });
    MatchQuery query(saveOf(match));
    EXPECT_TRUE(query.matchAttributes({{"sourceIP", {"10.0.0.2"}}, {"url", {"/login"}}}));
    EXPECT_TRUE(query.matchAttributes({{"sourceIP", {"10.0.0.1"}}, {"url", {"/login"}}}));
    EXPECT_FALSE(query.matchAttributes({{"sourceIP", {"10.0.0.3"}}, {"url", {"/login"}}}));
    EXPECT_FALSE(query.matchAttributes({{"sourceIP", {"10.0.0.1"}}, {"url", {"/other"}}}));

    MatchQuery single(saveOf(RateLimitRuleMatch({RateLimitRuleCondition("countryCode", "RU")})));
    EXPECT_TRUE(single.matchAttributes({{"countryCode", {"RU"}}}));
    EXPECT_FALSE(single.matchAttributes({{"countryCode", {"US"}}}));
}

TEST(LocalPolicySections, rateLimitAnswersWithTheResponseOfTheRule)
{
    RateLimitSection with_response("example.com", "example.com", "/", "Active", "p", "practice", {}, "response-id");
    EXPECT_THAT(saveOf(with_response), HasSubstr("\"webUserResponseId\": \"response-id\""));
    EXPECT_FALSE(with_response.isAnyAsset());

    RateLimitSection any("Any", "Any", "Any", "Active", "p", "practice", {});
    EXPECT_THAT(saveOf(any), Not(HasSubstr("webUserResponseId")));
    EXPECT_TRUE(any.isAnyAsset());
}

TEST(LocalPolicySections, logServiceProtocol)
{
    EXPECT_EQ(loadFrom<NewLoggingService>("{\"address\": \"10.0.0.5\", \"port\": 514}").getProtocol(), "UDP");
    EXPECT_EQ(
        loadFrom<NewLoggingService>("{\"address\": \"10.0.0.5\", \"port\": 514, \"proto\": \"tcp\"}").getProtocol(),
        "TCP"
    );
}

TEST(LocalPolicySections, logTriggerWritesResponseCodeAndProtocols)
{
    LogTriggerSection trigger(
        "policy/log", "Standard", "high", true, true, false, false, true, true, false, true, true, false, true,
        false, false, false, true, true, 0, "", 514, "10.0.0.5", false, true, "TCP", "UDP"
    );
    string json = saveOf(trigger);
    EXPECT_THAT(json, HasSubstr("\"responseCode\": true"));
    EXPECT_THAT(json, HasSubstr("\"syslogProtocol\": \"TCP\""));
    EXPECT_THAT(json, HasSubstr("\"cefProtocol\": \"UDP\""));
}

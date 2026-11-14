// NginxionS: the sections of the local policy that the agent dropped or wrote wrong (docs/WAF-POLICY.md, phase 11),
// each read back by the configuration class of the engine that uses it.
#include <sstream>
#include <string>
#include <vector>

#include "cptest.h"
#include "access_control_practice.h"
#include "appsec_practice_section.h"
#include "exceptions_section.h"
#include "new_exceptions.h"
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

// NginxionS: the conditions of an exception (x-nginxions, docs/WAF-POLICY.md 5.2), read by MatchQuery as the WAF
// does (Waf2Transaction::getExceptionsDict)
static MatchQuery
exceptionQueryOf(const string &conditions)
{
    auto exception = loadFrom<NewAppsecException>(
        "{\"name\": \"e\", \"action\": \"accept\", \"condition\": " + conditions + "}"
    );
    return MatchQuery(saveOf(ExceptionMatch(exception)));
}

TEST(LocalPolicySections, exceptionKeysOfTheWafBeyondV1beta2)
{
    auto query = exceptionQueryOf(
        "[{\"key\": \"method\", \"value\": \"POST\"}, {\"key\": \"headerName\", \"value\": \"x-internal\"}]"
    );
    EXPECT_TRUE(query.matchAttributes({{"method", {"POST"}}, {"headerName", {"x-internal", "host"}}}));
    EXPECT_FALSE(query.matchAttributes({{"method", {"GET"}}, {"headerName", {"x-internal"}}}));
    EXPECT_FALSE(query.matchAttributes({{"method", {"POST"}}, {"headerName", {"host"}}}));
}

TEST(LocalPolicySections, exceptionNotInMatchesNoneOfTheValues)
{
    // drop for every country but RU and BY
    auto query = exceptionQueryOf(
        "[{\"key\": \"countryCode\", \"op\": \"not-in\", \"value\": \"RU\"},"
        " {\"key\": \"countryCode\", \"op\": \"not-equals\", \"value\": \"BY\"}]"
    );
    EXPECT_TRUE(query.matchAttributes({{"countryCode", {"US"}}}));
    EXPECT_FALSE(query.matchAttributes({{"countryCode", {"RU"}}}));
    EXPECT_FALSE(query.matchAttributes({{"countryCode", {"BY"}}}));

    auto ip = exceptionQueryOf("[{\"key\": \"sourceIp\", \"op\": \"not-in\", \"value\": \"10.0.0.0/8\"}]");
    EXPECT_TRUE(ip.matchAttributes({{"sourceIP", {"192.0.2.1"}}}));
    EXPECT_FALSE(ip.matchAttributes({{"sourceIP", {"10.1.2.3"}}}));
}

TEST(LocalPolicySections, exceptionExistMatchesAnyValueOfTheKey)
{
    auto query = exceptionQueryOf(
        "[{\"key\": \"headerName\", \"value\": \"x-debug\"}, {\"key\": \"url\", \"op\": \"exist\"}]"
    );
    EXPECT_TRUE(query.matchAttributes({{"headerName", {"x-debug"}}, {"url", {"/any"}}}));
    EXPECT_FALSE(query.matchAttributes({{"headerName", {"x-debug"}}}));
}

TEST(LocalPolicySections, exceptionKeepsTheMatchOfV1beta2)
{
    // values of a key: any of them; keys: all of them (as before the extension)
    auto query = exceptionQueryOf(
        "[{\"key\": \"sourceIp\", \"value\": \"10.0.0.1\"}, {\"key\": \"url\", \"value\": \"/login\"},"
        " {\"key\": \"sourceIp\", \"value\": \"10.0.0.2\"}]"
    );
    EXPECT_TRUE(query.matchAttributes({{"sourceIP", {"10.0.0.2"}}, {"url", {"/login"}}}));
    EXPECT_FALSE(query.matchAttributes({{"sourceIP", {"10.0.0.3"}}, {"url", {"/login"}}}));
}

TEST(LocalPolicySections, exceptionRejectsWhatTheWafDoesNotMatch)
{
    EXPECT_THROW(exceptionQueryOf("[{\"key\": \"cookie\", \"value\": \"a\"}]"), PolicyGenException);
    EXPECT_THROW(exceptionQueryOf("[{\"key\": \"url\", \"op\": \"contains\", \"value\": \"a\"}]"), PolicyGenException);
    EXPECT_THROW(exceptionQueryOf("[{\"key\": \"url\", \"op\": \"equals\"}]"), PolicyGenException);
}

// NginxionS: the same exception as the override of the WAF (Waap::Override::Match: basic, and/or of two operands,
// not): a not-in or exist condition was written as {"operator": "not-in"} without a tag and never matched
static string
overrideOf(const string &conditions)
{
    auto exception = loadFrom<NewAppsecException>(
        "{\"name\": \"e\", \"action\": \"accept\", \"condition\": " + conditions + "}"
    );
    return saveOf(ParsedMatch(ExceptionMatch(exception)));
}

static size_t
countOf(const string &text, const string &part)
{
    size_t count = 0;
    for (size_t at = text.find(part); at != string::npos; at = text.find(part, at + part.size())) count++;
    return count;
}

TEST(LocalPolicySections, exceptionOverrideOfNotInIsNotOfTheValues)
{
    string json = overrideOf("[{\"key\": \"sourceIp\", \"op\": \"not-in\", \"value\": \"192.0.2.7\"}]");
    EXPECT_THAT(json, HasSubstr("\"operator\": \"not\""));
    EXPECT_THAT(json, HasSubstr("\"operator\": \"basic\""));
    EXPECT_THAT(json, HasSubstr("\"tag\": \"sourceIP\""));
    EXPECT_THAT(json, HasSubstr("\"value\": \"192.0.2.7\""));
    EXPECT_THAT(json, Not(HasSubstr("not-in")));

    string two = overrideOf(
        "[{\"key\": \"sourceIp\", \"op\": \"not-in\", \"value\": \"192.0.2.7\"},"
        " {\"key\": \"sourceIp\", \"op\": \"not-equals\", \"value\": \"192.0.2.8\"}]"
    );
    EXPECT_THAT(two, HasSubstr("\"values\""));
    EXPECT_THAT(two, HasSubstr("\"192.0.2.8\""));
}

TEST(LocalPolicySections, exceptionOverrideOfExistMatchesAnyValue)
{
    string json = overrideOf("[{\"key\": \"headerName\", \"op\": \"exist\"}]");
    EXPECT_THAT(json, HasSubstr("\"operator\": \"basic\""));
    EXPECT_THAT(json, HasSubstr("\"value\": \".*\""));
}

TEST(LocalPolicySections, exceptionOverrideNestsMoreThanTwoOperands)
{
    // three values of a key: or(a, or(b, c)), every one of them read (the WAF reads operand1 and operand2 only)
    string json = overrideOf(
        "[{\"key\": \"url\", \"value\": \"/a\"}, {\"key\": \"url\", \"value\": \"/b\"},"
        " {\"key\": \"url\", \"value\": \"/c\"}]"
    );
    EXPECT_EQ(countOf(json, "\"operator\": \"or\""), 2u);
    EXPECT_EQ(countOf(json, "\"operand3\""), 0u);
    EXPECT_THAT(json, HasSubstr("\"/c\""));
    // equals stays one basic match of its value
    EXPECT_THAT(overrideOf("[{\"key\": \"url\", \"value\": \"/a\"}]"), HasSubstr("\"value\": \"/a\""));
}

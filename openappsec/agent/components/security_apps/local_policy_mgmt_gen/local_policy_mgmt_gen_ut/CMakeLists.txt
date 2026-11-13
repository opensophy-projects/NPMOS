# NginxionS: unit tests of the sections the local policy is turned into (docs/WAF-POLICY.md, A10): each one is read
# back by the configuration class of the engine that uses it
include_directories(${CMAKE_SOURCE_DIR}/components/security_apps/local_policy_mgmt_gen/include)

add_unit_test(
    local_policy_mgmt_gen_ut
    "local_policy_sections_ut.cc"
    "local_policy_mgmt_gen;generic_rulebase;generic_rulebase_evaluators;ip_utilities;connkey;http_transaction_data;messaging;logging;agent_details;env_details;table;time_proxy;event_is;intelligence_is_v2;orchestration_tools;-lboost_regex;-lcrypto;-lssl;-lz"
)

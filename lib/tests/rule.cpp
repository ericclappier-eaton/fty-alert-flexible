#include "src/rule.h"
#include <catch2/catch.hpp>
#include <fty_log.h>

void rule_test_json(const char* dir, const char* basename)
{
    log_debug("** rule_test_json(): dir=%s, basename=%s", dir, basename);

    CHECK(dir);
    CHECK(basename);

    rule_t* self = rule_new();
    REQUIRE(self);

    // load rule file
    {
        char* rule_file = zsys_sprintf("%s/%s.rule", dir, basename);
        REQUIRE(rule_file);
        int r = rule_load(self, rule_file);
        REQUIRE(r == 0);
        zstr_free(&rule_file);
    }

    // rule serialize
    char* json = rule_serialize(self);
    REQUIRE(json);

    // rule parse from previously serialized
    rule_t* rule = rule_new();
    REQUIRE(rule);
    int r = rule_parse(rule, json);
    REQUIRE(r == 0);
    char* json2 = rule_serialize(rule);
    REQUIRE(json2);

    CHECK(streq(rule_name(rule), rule_name(self)));

    if (!streq(json, json2)) {
        log_debug("== json:\n%s", json);
        log_debug("== json2:\n%s", json2);
    }
    REQUIRE(streq(json, json2));

    zstr_free(&json);
    zstr_free(&json2);
    rule_destroy(&rule);
    rule_destroy(&self);

    CHECK(rule == nullptr);
    CHECK(self == nullptr);
}

void rule_test_lua(const char* dir, const char* basename)
{
    log_debug("** rule_test_lua(): dir=%s, basename=%s", dir, basename);

    CHECK(dir);
    CHECK(basename);

    int     r;
    rule_t* self = rule_new();
    REQUIRE(self);

    // load rule
    {
        char* rule_file = zsys_sprintf("%s/%s.rule", dir, basename);
        REQUIRE(rule_file);
        r = rule_load(self, rule_file);
        REQUIRE(r == 0);
        zstr_free(&rule_file);
    }

    r = rule_compile(self);
    REQUIRE(r == 1);

    rule_destroy(&self);
    CHECK(self == nullptr);
}

TEST_CASE("rule test")
{
    #define SELFTEST_DIR_RO    "tests/selftest-ro"
    #define SELFTEST_DIR_RW    "."
    #define SELFTEST_DIR_RULES SELFTEST_DIR_RO "/rules"

    //  Simple create/destroy test
    {
        rule_t* self = rule_new();
        REQUIRE(self);
        rule_destroy(&self);
        CHECK(self == nullptr);
    }

    //  Load test #1
    {
        rule_t* self = rule_new();
        REQUIRE(self);
        char* rule_file = zsys_sprintf("%s/%s", SELFTEST_DIR_RULES, "load.rule");
        REQUIRE(rule_file);
        int r = rule_load(self, rule_file);
        CHECK(r == 0);
        zstr_free(&rule_file);
        rule_destroy(&self);
        CHECK(self == nullptr);
    }

    //  Load test #2 - tests 'variables' section
    {
        rule_t* self = rule_new();
        REQUIRE(self);
        char* rule_file = zsys_sprintf("%s/%s", SELFTEST_DIR_RULES, "threshold.rule");
        REQUIRE(rule_file);
        int r = rule_load(self, rule_file);
        CHECK(r == 0);
        zstr_free(&rule_file);

        //  prepare expected 'variables' hash
        zhashx_t* expected = zhashx_new();
        REQUIRE(expected);
        zhashx_set_duplicator(expected, reinterpret_cast<zhashx_duplicator_fn*>(strdup));
        zhashx_set_destructor(expected, reinterpret_cast<zhashx_destructor_fn*>(zstr_free));

        zhashx_insert(expected, "high_critical", const_cast<char*>("60"));
        zhashx_insert(expected, "high_warning", const_cast<char*>("40"));
        zhashx_insert(expected, "low_warning", const_cast<char*>("15"));
        zhashx_insert(expected, "low_critical", const_cast<char*>("5"));

        // compare it against self 'variables'
        zhashx_t* variables = rule_variables(self);
        REQUIRE(variables);
        const char* value = reinterpret_cast<const char*>(zhashx_first(variables));
        while (value) {
            const char* key            = reinterpret_cast<const char*>(zhashx_cursor(variables));
            const char* expected_value = reinterpret_cast<const char*>(zhashx_lookup(expected, key));
            CHECK(expected_value);
            CHECK(streq(value, expected_value));
            zhashx_delete(expected, key);
            value = reinterpret_cast<const char*>(zhashx_next(variables));
        }
        zhashx_destroy(&variables);

        CHECK(zhashx_size(expected) == 0);
        zhashx_destroy(&expected);
        rule_destroy(&self);
        CHECK(self == nullptr);
    }

    //  Load test #3
    {
        rule_test_json(SELFTEST_DIR_RULES, "test");
    }

    //  Load test #4
    {
        rule_test_json(SELFTEST_DIR_RULES, "old");
    }

    //  Load test #5 - parse & lua compile
    {
        // .rule files with valid 'evaluation' part
        const char* rules[] = {

            "sts-frequency",
            "sts-preferred-source",
            "sts-voltage",
            "threshold",
            "ups",

            //
            // public flexible templates
            // copied from 42ity/fty-alert-engine/lib/rule_templates
            //

            "templates/door-contact.state-change@__device_sensorgpio__",
            "templates/fire-detector-extinguisher.state-change@__device_sensorgpio__",
            "templates/fire-detector.state-change@__device_sensorgpio__",
            "templates/licensing.expire@__device_rackcontroller__",
            "templates/pir-motion-detector.state-change@__device_sensorgpio__",
            "templates/smoke-detector.state-change@__device_sensorgpio__",
            "templates/sts-frequency@__device_sts__",
            "templates/sts-preferred-source@__device_sts__",
            "templates/sts-voltage@__device_sts__",
            "templates/vibration-sensor.state-change@__device_sensorgpio__",
            "templates/water-leak-detector.state-change@__device_sensorgpio__",
            "templates/single-point-of-failure@__device_ups__",
        };

        for (const auto& rule : rules) {
            rule_test_json(SELFTEST_DIR_RULES, rule);
        }

        for (const auto& rule : rules) {
            rule_test_lua(SELFTEST_DIR_RULES, rule);
        }
    }
}

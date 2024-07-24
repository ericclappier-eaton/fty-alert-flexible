#include "src/flexible_alert.h"
#include "src/audit_log.h"
#include <catch2/catch.hpp>
#include <fty_log.h>
#include <fty_shm.h>
#include <malamute.h>
#include <iostream>

TEST_CASE("flexible alert test")
{
    const char* SELFTEST_DIR_RO = "tests/selftest-ro";
    const char* SELFTEST_DIR_RW = ".";

    const char* MLM_ENDPOINT = "inproc://fty-alert-flexible-test";
    const char* ACTOR_ADDRESS = "alert-flexible-test";

    // initialize log for auditability
    AuditLog::init("flexible-alert-test");
    // logs audit, see /etc/fty/ftylog.cfg (requires privileges)
    audit_log_info("flexible-alert-test audit test %s", "INFO");
    audit_log_error("flexible-alert-test audit test %s", "ERROR");
    //AuditLog::deinit(); return;

    fty_shm_set_test_dir(SELFTEST_DIR_RW);
    const int polling_interval = 5;
    fty_shm_set_default_polling_interval(polling_interval);

    const size_t totalRulesCnt = 9;

    // start malamute
    zactor_t* server = zactor_new(mlm_server, const_cast<char*>("Malamute"));
    REQUIRE(server);
    zstr_sendx(server, "BIND", MLM_ENDPOINT, nullptr);

    // create flexible alert actor
    zlist_t* params = zlist_new();
    REQUIRE(params);
    zlist_append(params, const_cast<char*>(".*")); //assets pattern
    zlist_append(params, const_cast<char*>(".*")); //metrics pattern

    zactor_t* flexible_actor = zactor_new(fty_flexible_alert_actor, params);
    REQUIRE(flexible_actor);
    zstr_sendx(flexible_actor, "CONNECT", MLM_ENDPOINT, ACTOR_ADDRESS, nullptr);
    zstr_sendx(flexible_actor, "PRODUCER", FTY_PROTO_STREAM_ALERTS_SYS, nullptr);
    zstr_sendx(flexible_actor, "CONSUMER", FTY_PROTO_STREAM_ASSETS, ".*", nullptr);
    zstr_sendx(flexible_actor, "CONSUMER", FTY_PROTO_STREAM_METRICS_SENSOR, ".*", nullptr);

    char* rules_dir = nullptr;
    asprintf(&rules_dir, "%s/rules", SELFTEST_DIR_RO);
    REQUIRE(rules_dir != nullptr);
    zstr_sendx(flexible_actor, "LOADRULES", rules_dir, nullptr);
    zstr_free(&rules_dir);

    // create mlm client for interaction with actor
    mlm_client_t* asset = mlm_client_new();
    REQUIRE(asset);
    int r = mlm_client_connect(asset, MLM_ENDPOINT, 5000, "asset-autoupdate-test");
    CHECK(r == 0);
    r = mlm_client_set_producer(asset, FTY_PROTO_STREAM_ASSETS);
    CHECK(r == 0);
    r = mlm_client_set_consumer(asset, FTY_PROTO_STREAM_ALERTS_SYS, ".*");
    CHECK(r == 0);

    // let malamute breath a while
    zclock_sleep(500);

    {
        zhash_t* ext = zhash_new();
        zhash_autofree(ext);
        //zhash_insert(ext, "group.1", const_cast<char*>("all-upses"));
        zhash_insert(ext, "name", const_cast<char*>("my_ups"));
        zmsg_t* msg = fty_proto_encode_asset(nullptr, "ups-1234", "update", ext);
        r = mlm_client_send(asset, "update-asset-ups-1234", &msg);
        zmsg_destroy(&msg);
        zhash_destroy(&ext);
        CHECK(r == 0);
    }

    {
        zmsg_t* msg = fty_proto_encode_metric(nullptr, uint64_t(time(nullptr)), uint32_t(polling_interval * 2), "status.ups", "ups-1234", "64", "");
        fty_proto_t* proto = fty_proto_decode(&msg);
        zmsg_destroy(&msg);
        r = fty::shm::write_metric(proto);
        fty_proto_destroy(&proto);
        CHECK(r == 0);

        log_debug("Wait for alert...");
        zmsg_t* alert = mlm_client_recv(asset);
        log_debug("Alert received");

        REQUIRE(alert);
        CHECK(fty_proto_is(alert));
        proto = fty_proto_decode(&alert);
        zmsg_destroy(&alert);
        REQUIRE(proto);
        fty_proto_print(proto);
        fty_proto_destroy(&proto);
    }

    {

        // test LIST
        zmsg_t* msg = zmsg_new();
        zmsg_addstr(msg, "LIST");
        zmsg_addstr(msg, "all");
        zmsg_addstr(msg, "myclass");
        r = mlm_client_sendto(asset, ACTOR_ADDRESS, "test-LIST", nullptr, 1000, &msg);
        CHECK(r == 0);

        zmsg_t* reply = mlm_client_recv(asset);
        CHECK(reply);

        char* item = zmsg_popstr(reply);
        CHECK(streq("LIST", item));
        zstr_free(&item);

        item = zmsg_popstr(reply);
        CHECK(streq("all", item));
        zstr_free(&item);

        item = zmsg_popstr(reply);
        CHECK(streq("myclass", item));
        zstr_free(&item);

        CHECK(zmsg_size(reply) == totalRulesCnt); // all rules

        zmsg_destroy(&reply);
    }

    {
        // test LIST2 (LIST version 2)

        struct {
            std::string payload; // json
            bool success; // expected
        } testVector[] = {
            { "", false },
            { "{", false }, // invalid json
            { R"({ "hello": "world")", false }, // invalid json
            { "{}", true },
            { R"({ "hello": "world" })", true },
            { R"({ "type": "all" })", true },
            { R"({ "type": "" })", true }, // eg 'all'
            { R"({ "type": "flexible" })", true },
            { R"({ "type": "threshold" })", false }, // type unknown
            { R"({ "type": "single" })", false }, // type unknown
            { R"({ "type": "pattern" })", false }, // type unknown
            { R"({ "type": "hello" })", false }, // type unknown
            { R"({ "asset_type": "hello" })", false }, // asset_type unknown
            { R"({ "asset_type": "ups" })", false }, // asset_type unknown
            { R"({ "asset_type": "rack" })", true },
            { R"({ "asset_sub_type": "hello" })", false }, // asset_sub_type unknown
            { R"({ "asset_sub_type": "ups" })", true },
            { R"({ "asset_sub_type": "rack" })", false }, // asset_sub_type unknown
            { R"({ "in": "ups-123" })", false }, // in (location) invalid
            { R"({ "in": "datacenter-123" })", true },
            { R"({ "in": "room-123" })", true },
            { R"({ "in": "row-123" })", true },
            { R"({ "in": "rack-123" })", true },
            { R"({ "category": "hello" })", true }, // free
            { R"({ "category": "other" })", true },
        };

        for (auto& test : testVector) {
            zmsg_t* command = zmsg_new();
            zmsg_addstrf(command, "%s", "LIST2"); // version 2
            zmsg_addstrf(command, "%s", test.payload.c_str());
            r = mlm_client_sendto(asset, ACTOR_ADDRESS, "anythingyouwant", nullptr, 1000, &command);
            zmsg_destroy(&command);
            CHECK(r == 0);

            zmsg_t* recv = mlm_client_recv(asset);
            REQUIRE(recv);
            zmsg_print(recv);

            char* foo = zmsg_popstr(recv);
            REQUIRE(foo);
            REQUIRE( test.success == streq(foo, "LIST2")); // LIST2 as OK
            REQUIRE(!test.success == streq(foo, "ERROR")); // ERROR as KO
            zstr_free(&foo);

            zmsg_destroy(&recv);
        }
    }

    {
        struct {
            std::string payload; // json
            size_t ruleCnt; // rules count (success expected)
        } testVector[] = {
            { R"({ "type": "all", "rule_class": "deprecated?" })", totalRulesCnt },
            { R"({ "type": "all" })", totalRulesCnt },
            { R"({ "type": "" })", totalRulesCnt }, // eg. all
            { R"({})", totalRulesCnt }, // type=="", eg all
            { R"({ "type": "flexible" })", totalRulesCnt },
            { R"({ "category": "hello" })", 0 },
            { R"({ "category": "sts" })", 3 },
            { R"({ "category": "other" })", totalRulesCnt - 3 }, // all - sts
        };

        for (auto& test : testVector) {
            zmsg_t* command = zmsg_new();
            zmsg_addstrf(command, "%s", "LIST2"); // version 2
            zmsg_addstrf(command, "%s", test.payload.c_str());
            r = mlm_client_sendto(asset, ACTOR_ADDRESS, "anythingyouwant", NULL, 1000, &command);
            zmsg_destroy(&command);
            CHECK(r == 0);

            zmsg_t* recv = mlm_client_recv(asset);
            REQUIRE(recv);
            //zmsg_print(recv);

            REQUIRE(zmsg_size(recv) == (2 + test.ruleCnt));

            char* foo = zmsg_popstr(recv);
            REQUIRE(foo);
            REQUIRE(streq(foo, "LIST2")); // success
            zstr_free(&foo);

            foo = zmsg_popstr(recv);
            REQUIRE(foo);
            REQUIRE(streq(foo, test.payload.c_str()));
            zstr_free(&foo);

            size_t cnt = 0;
            do {
                foo = zmsg_popstr(recv);
                if (!foo) break;
                std::cout << "-- rule-" << cnt << std::endl << foo << std::endl;
                zstr_free(&foo);
                cnt++;
            } while(1);
            REQUIRE(test.ruleCnt == cnt);

            zstr_free(&foo);
            zmsg_destroy(&recv);
        }
    }

    {
        // test GET
        zmsg_t* msg = zmsg_new();
        zmsg_addstr(msg, "GET");
        zmsg_addstr(msg, "load");
        r = mlm_client_sendto(asset, ACTOR_ADDRESS, "ignored", nullptr, 1000, &msg);
        CHECK(r == 0);

        zmsg_t* reply = mlm_client_recv(asset);
        CHECK(reply);

        char* item = zmsg_popstr(reply);
        CHECK(streq("OK", item));
        zstr_free(&item);

        item = zmsg_popstr(reply);
        REQUIRE(item);
        CHECK(item[0] == '{');
        zstr_free(&item);

        zmsg_destroy(&reply);
    }
    {
        // test ADD
        const char* testrulejson =
            "{\"name\":\"testrulejson\",\"description\":\"none\",\"evaluation\":\"function main(x) return OK, 'yes' "
            "end\"}";

        // For ADD and DELETE tests use the RW directory
        zstr_sendx(flexible_actor, "LOADRULES", SELFTEST_DIR_RW, nullptr);
        zclock_sleep(200);

        zmsg_t* msg = zmsg_new();
        zmsg_addstr(msg, "ADD");
        zmsg_addstr(msg, testrulejson);
        r = mlm_client_sendto(asset, ACTOR_ADDRESS, "ignored", nullptr, 1000, &msg);
        CHECK(r == 0);

        zmsg_t* reply = mlm_client_recv(asset);
        CHECK(reply);

        char* item = zmsg_popstr(reply);
        CHECK(streq("OK", item));
        zstr_free(&item);

        item = zmsg_popstr(reply);
        REQUIRE(item);
        CHECK(item[0] == '{');
        zstr_free(&item);

        zmsg_destroy(&reply);
    }

    {
        // test DELETE
        zmsg_t* msg = zmsg_new();
        zmsg_addstr(msg, "DELETE");
        zmsg_addstr(msg, "testrulejson");
        r = mlm_client_sendto(asset, ACTOR_ADDRESS, "ignored", nullptr, 1000, &msg);
        CHECK(r == 0);

        zmsg_t* reply = mlm_client_recv(asset);
        CHECK(reply);

        char* item = zmsg_popstr(reply);
        CHECK(streq("DELETE", item));
        zstr_free(&item);

        item = zmsg_popstr(reply);
        CHECK(streq("testrulejson", item));
        zstr_free(&item);

        item = zmsg_popstr(reply);
        CHECK(streq("OK", item));
        zstr_free(&item);

        zmsg_destroy(&reply);
    }

    mlm_client_destroy(&asset);
    zactor_destroy(&flexible_actor);
    zlist_destroy(&params);
    zactor_destroy(&server);

    fty_shm_delete_test_dir();

    AuditLog::deinit();
}

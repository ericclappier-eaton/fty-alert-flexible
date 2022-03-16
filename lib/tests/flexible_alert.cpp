#include "src/flexible_alert.h"
#include "src/fty_alert_flexible_audit_log.h"
#include <catch2/catch.hpp>
#include <fty_shm.h>
#include <malamute.h>
#include <iostream>

TEST_CASE("flexible alert test")
{
    const char* SELFTEST_DIR_RO = "tests/selftest-ro";
    const char* SELFTEST_DIR_RW = ".";

    // initialize log for auditability
    AuditLogManager::init("flexible-server-test");
    // logs audit, see /etc/fty/ftylog.cfg (requires privileges)
    log_debug_alarms_flexible_audit("flexible-server-test audit test %s", "DEBUG");
    log_info_alarms_flexible_audit("flexible-server-test audit test %s", "INFO");
    log_warning_alarms_flexible_audit("flexible-server-test audit test %s", "WARNING");
    log_error_alarms_flexible_audit("flexible-server-test audit test %s", "ERROR");
    log_fatal_alarms_flexible_audit("flexible-server-test audit test %s", "FATAL");
    //AuditLogManager::deinit(); return;

    fty_shm_set_test_dir(SELFTEST_DIR_RW);
    fty_shm_set_default_polling_interval(5);

    // start malamute
    static const char* endpoint = "inproc://fty-metric-snmp";
    zactor_t*          malamute = zactor_new(mlm_server, const_cast<char*>("Malamute"));
    zstr_sendx(malamute, "BIND", endpoint, nullptr);

    // create flexible alert actor
    zlist_t* params = zlist_new();
    zlist_append(params, const_cast<char*>(".*"));
    zlist_append(params, const_cast<char*>(".*"));

    zactor_t* fs = zactor_new(flexible_alert_actor, params);
    REQUIRE(fs);
    zstr_sendx(fs, "BIND", endpoint, "me", nullptr);
    zstr_sendx(fs, "PRODUCER", FTY_PROTO_STREAM_ALERTS_SYS, nullptr);
    zstr_sendx(fs, "CONSUMER", FTY_PROTO_STREAM_ASSETS, ".*", nullptr);
    // zstr_sendx (fs, "CONSUMER", FTY_PROTO_STREAM_METRICS, ".*", nullptr);
    zstr_sendx(fs, "CONSUMER", FTY_PROTO_STREAM_METRICS_SENSOR, ".*", nullptr);
    char* rules_dir = nullptr;
    asprintf(&rules_dir, "%s/rules", SELFTEST_DIR_RO);
    CHECK(rules_dir != nullptr);
    zstr_sendx(fs, "LOADRULES", rules_dir, nullptr);
    zstr_free(&rules_dir);

    // create mlm client for interaction with actor
    mlm_client_t* asset = mlm_client_new();
    mlm_client_connect(asset, endpoint, 5000, "asset-autoupdate");
    mlm_client_set_producer(asset, FTY_PROTO_STREAM_ASSETS);
    mlm_client_set_consumer(asset, FTY_PROTO_STREAM_ALERTS_SYS, ".*");

    // metric client
    //    mlm_client_t *metric = mlm_client_new ();
    //    mlm_client_connect (metric, endpoint, 5000, "metric");
    //    mlm_client_set_producer (metric, FTY_PROTO_STREAM_METRICS);

    // let malamute establish everything
    zclock_sleep(200);
    {
        zhash_t* ext = zhash_new();
        zhash_autofree(ext);
        zhash_insert(ext, "group.1", const_cast<char*>("all-upses"));
        zhash_insert(ext, "name", const_cast<char*>("mý děvíce"));
        zmsg_t* assetmsg = fty_proto_encode_asset(nullptr, "mydevice", "update", ext);
        mlm_client_send(asset, "myasset", &assetmsg);
        zhash_destroy(&ext);
        zmsg_destroy(&assetmsg);
    }
    zclock_sleep(200);
    {
        // send metric, receive alert
        //        zmsg_t *msg = fty_proto_encode_metric (
        //            nullptr,
        //            time (nullptr),
        //            60,
        //            "status.ups",
        //            "mydevice",
        //            "64",
        //            "");
        //        mlm_client_send (metric, "status.ups@mydevice", &msg);
        fty::shm::write_metric("mydevice", "status.ups", "64", "", 5);

        zmsg_t* alert = mlm_client_recv(asset);
        CHECK(fty_proto_is(alert));
        fty_proto_t* ftymsg = fty_proto_decode(&alert);
        fty_proto_print(ftymsg);
        fty_proto_destroy(&ftymsg);
        zmsg_destroy(&alert);
    }
    zclock_sleep(200);
    {
        // test LIST
        zmsg_t* msg = zmsg_new();
        zmsg_addstr(msg, "LIST");
        zmsg_addstr(msg, "all");
        zmsg_addstr(msg, "myclass");
        mlm_client_sendto(asset, "me", "status.ups@mydevice", nullptr, 1000, &msg);

        zmsg_t* reply = mlm_client_recv(asset);

        char* item = zmsg_popstr(reply);
        CHECK(streq("LIST", item));
        zstr_free(&item);

        item = zmsg_popstr(reply);
        CHECK(streq("all", item));
        zstr_free(&item);

        item = zmsg_popstr(reply);
        CHECK(streq("myclass", item));
        zstr_free(&item);

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
        };

        for (auto& test : testVector) {
            zmsg_t* command = zmsg_new();
            zmsg_addstrf(command, "%s", "LIST2"); // version 2
            zmsg_addstrf(command, "%s", test.payload.c_str());
            mlm_client_sendto(asset, "me", "anythingyouwant", nullptr, 1000, &command);
            zmsg_destroy(&command);

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
            { R"({ "type": "all", "rule_class": "deprecated?" })", 8 },
            { R"({ "type": "all" })", 8 },
            { R"({ "type": "" })", 8 }, // eg. all
            { R"({})", 8 }, // type=="", eg all
            { R"({ "type": "flexible" })", 8 },
        };

        for (auto& test : testVector) {
            zmsg_t* command = zmsg_new();
            zmsg_addstrf(command, "%s", "LIST2"); // version 2
            zmsg_addstrf(command, "%s", test.payload.c_str());
            mlm_client_sendto(asset, "me", "anythingyouwant", NULL, 1000, &command);
            zmsg_destroy(&command);

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
        mlm_client_sendto(asset, "me", "ignored", nullptr, 1000, &msg);

        zmsg_t* reply = mlm_client_recv(asset);

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
        zstr_sendx(fs, "LOADRULES", SELFTEST_DIR_RW, nullptr);
        zclock_sleep(200);

        zmsg_t* msg = zmsg_new();
        zmsg_addstr(msg, "ADD");
        zmsg_addstr(msg, testrulejson);
        mlm_client_sendto(asset, "me", "ignored", nullptr, 1000, &msg);

        zmsg_t* reply = mlm_client_recv(asset);
        char*   item  = zmsg_popstr(reply);
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
        mlm_client_sendto(asset, "me", "ignored", nullptr, 1000, &msg);

        zmsg_t* reply = mlm_client_recv(asset);

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
    // destroy actor
    zactor_destroy(&fs);
    // destroy malamute
    zactor_destroy(&malamute);
    fty_shm_delete_test_dir();

    AuditLogManager::deinit();
}

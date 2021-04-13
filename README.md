# fty-alert-flexible

## How to build

```bash
mkdir build && cd build
cmake -DCMAKE_BUILD_TYPE=Debug -DCMAKE_INSTALL_PREFIX=usr -DBUILD_TESTING=On ..
make
sudo make install
```

## About

This 42ITy agent listen for metrics and produces alerts. Pattern
subscription about METRICS stream is defined by 'malamute/metrics_pattern'
key in fty-alert-flexible.cfg configuration file. Rules
for creating alerts are specified with json and lua. All rule files
are loaded from one directory specified by command line parameter.
File has to have a `.rule` extension. Some example rule files are
provided in the source code among fixtures for the agent's selftest,
in `src/selftest-ro/rules` directory, and are installed as part of
package to the shared data directory.

Evaluation function is written in Lua.

```bash
json
{
    "name"          : "upsload",
    "description"   : "UPS load",
    "metrics"       : ["load.default"],
    "assets"        : [],
    "models"        : [],
    "types"         : [],
    "groups"        : ["allupses"],
    "results"       :  {
        "low_critical"  : { "action" : ["EMAIL", "SMS"] },
        "low_warning"   : { "action" : ["EMAIL"] },
        "high_critical" : { "action" : ["EMAIL", "SMS" ] },
        "high_warning"  : { "action" : ["EMAIL" ] }
    },
    "variables" : {
        "my_global_variable"  : "Something nice or even a number"
    },
    "evaluation"    : "
         function main(load)
             if load > 90 then
                 return CRITICAL, NAME .. ' is overloaded (' .. load .. '%);
             end
             if load > 70 then
                 return WARNING, NAME .. ' is overloaded (' .. load .. '%);
             end
             return OK, 'Load on ' .. NAME ..  ' is within limit (' .. load .. '%)';
         end
    "
}
```

Note: Yes this is not valid json, but the parser used tolerates multi-line
string.

## Rules

Rule file MUST be in UTF-8 encoding (ASCII is OK of course). A Rules json has
following parts:

* name - mandatory - name of the rule, SHOULD be ASCII identifier of the
  rule and MUST be unique
* description - optional - user friendly description of the rule
* metrics - mandatory - list of metrics that are passed to `main()` function
* groups - optional - list of asset groups (extended attribute `group.x`).
  Rule will be used for all assets that belongs to at least one of listed
  groups.
* assets - optional - rule will be applied to assets explicitly listed here
* models - optional - rule will be applied to assets of listed model or
  part number (see extended attribute model and device.part)
* types - optional - rule will be applied to asset of listed type or subtype
* results - optional - List of actions on alert
* variables - optional - List of global (lua context) variables
* evaluation - mandatory - Lua code for producing alert.

You can combine assets, groups and models in one rule.

Lua code MUST have function called main with parameters that corresponds to
the list of metrics.

Lua main function MUST return two values -- alert status (number -2 .. +2) and
alert message. There are global variables set, that you can return.

## global variables
### return values

* OK - no alert, values are in range
* LOW_CRITICAL -- critical alert, value is too low
* LOW_WARNING -- warning alert, value is too low
* HIGH_WARNING -- warning alert, value is too high
* HIGH_CRITICAL -- critical alert, value is too high

There is also WARNING and CRITICAL. Those are equal to HIGH_WARNING and
HIGH_CRITICAL.

### other variables

* NAME -- friendly name of currently evaluated asset
* INAME -- internal name of the asset (id)

## nagios metrics/alerts

Agent automatically creates alerts from metrics called `nagios.*`.
See fty-agent-snmp for more information.


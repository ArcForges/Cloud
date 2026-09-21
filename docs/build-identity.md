# WP02.04 build identity

The service embeds nine independent axes from its source catalog, committed locks and restored Contracts receipt. AppVersion, ContractSet and PackageVersion have independent producers; absent future capability/storage/policy/extension producers remain explicit. This scaffold owns no portable product format or C ABI.

Every owned .NET assembly carries source commit, dirty state, local/CI kind, run/attempt, pipeline URL and Git UTC timestamp. Docker compilation receives those required inputs from the independently resolved checkout identity; incomplete inputs fail compilation. The candidate seals that resolver's report as `build-identity.json`, checked against trusted source/lock/CI inputs during packaging and promotion. This companion is build metadata, not evidence that CI ran the binary.

`ArcForges.Cloud --build-info`, health metadata and the Worker build header remain available for explicit local support diagnostics. CI does not execute them, launch/restart a container, run Worker/RPC tests or poll live deployment metadata. Promotion loads and identifies the sealed image without rebuilding or repeated extraction. See [validation policy](validation-policy.md).

The attributed ArcNotes adaptation and immutable image/Worker provenance history remain unchanged. Full legal contents are inspected through a stopped container at packaging. Synthetic resolver tests establish metadata rules, not business compatibility, migrations or complete commercial behavior.

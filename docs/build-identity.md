# WP02.04 build identity

The service embeds a closed nine-axis source catalog, its committed NuGet/npm
locks and the restored Contracts producer receipt. AppVersion, ContractSet and
PackageVersion have independent sources. Absent future capability/storage/policy/
extension producers remain explicit. This service owns no portable product format
or first-party C ABI; these axes are explicitly not applicable.

Every owned .NET assembly consumes Build.Policy 1.0.0-ci.20.1 and carries its source
commit, dirty state, local/CI kind, run/attempt, pipeline URL and Git source timestamp.
The owner checks real Git inputs in normal builds. Docker's source archive receives
those exact inputs as required build arguments; incomplete inputs fail compilation.
`npm run candidate` and `npm run dev` supply them from the actual checkout.

`ArcForges.Cloud --build-info` writes the complete compiled report without starting
HTTP listeners. The real final image executes this command with networking disabled;
its report must equal an independent Node resolver of Git, release and locked source
inputs. The immutable candidate seals that actual report as `build-identity.json`.
The candidate manifest includes its hash, and verification independently recomputes
its expected contents, rejecting changes even after an outer hash is recomputed.

Health exposes only compiled artifact/build identity alongside its existing fields.
The sealed Worker configuration carries the same build identity and returns it in
`x-arcforges-worker-build`; local Worker and deployment readiness compare it too.
It does not send the full dependency inventory, so the existing 8192-byte Worker
response bound remains unchanged. Container start, restart, local Worker and deployed
Cloud checks compare these fields with the expected candidate. Promotion executes the
loaded image's offline command again before pushing the existing tested image. A
failed deployment may reuse an earlier attempt from the same source/run; it cannot
accept a future attempt or another run. Publication does not rebuild.

The ArcNotes resolver/test adaptation is recorded under `arcnotes-build-identity-r1`.
Full original terms and attribution remain in source and existing image/Worker legal
bundles. The image profile and its two artifact records use immutable successors when
source inputs change. Native image, local Worker and live Cloudflare evidence remain
separate. Local Windows source/JIT checks do not substitute for the Linux image gate.

Synthetic declarations exercise all nine independent resolvers; they do not establish
business compatibility, storage migrations or complete commercial Cloud workflows.

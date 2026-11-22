# Third-party runtime sources

The application uses dynamically linked libraries. Their upstream source archives,
as identified by the signed package recipes, are:

- GLib 2.88.3: https://download.gnome.org/sources/glib/2.88/glib-2.88.3.tar.xz
  SHA-256 `ab24d24e698dfa1e408b7bcdb508f4aafc906185a8b8ce72fdf79bbbdc9b383b`
- GNU libiconv 1.19: https://ftp.gnu.org/gnu/libiconv/libiconv-1.19.tar.gz
  SHA-256 `88dd96a8c0464eca144fc791ae60cd31cd8ee78321e67397e25fc095c4a19aa6`
- GNU gettext 1.0 (libintl): https://ftp.gnu.org/gnu/gettext/gettext-1.0.tar.xz
  SHA-256 `71132a3fb71e68245b8f2ac4e9e97137d3e5c02f415636eb508ae607bc01add7`
- PCRE2 10.49: https://github.com/PCRE2Project/pcre2/releases/download/pcre2-10.49/pcre2-10.49.tar.bz2
  SHA-256 `53c156e1ba416a20da8e65395daa132da0d80e76910424caca3fcdae7831d384`

The runtime libraries came from signed MacPorts arm64 Darwin 23 binary packages.
Their package-specific portfiles and patch directories, retrieved from the exact
ports commits recorded in their signed metadata, are included under
`macports-port-sources/`; each downloaded portfile was compared byte for byte
with the portfile in the corresponding signed package. Referenced PortGroups
are included with Git blob digests and URLs in `groups/MANIFEST.json`. A check
of the included PortGroups found no nested `PortGroup` invocation.

The signed package metadata names the following MacPorts base versions:

| Component | MacPorts base | Ports commit |
| --- | --- | --- |
| GLib | 2.12.6 | `3393469cc03e584134585e5b0d26808eb2104efa` |
| GNU libiconv | 2.12.5 | `03b1b44cce27fbd3fee6686d4b107bcd621940c1` |
| GNU gettext runtime | 2.12.2 | `745ff1b58358f448da09339ba9c3ea3a464e773e` |
| PCRE2 | 2.12.7 | `8cd924b447c30b25649d6e2a6e1553ce98f9fa16` |

The [project's GitHub releases](https://github.com/payara-wy/network-sharer/releases)
provide a separate archive containing the upstream sources and the four
matching MacPorts base source archives. From the project checkout,
`python3 Tools/package_runtime_sources.py --output
<path-to-new-source-archive.tar>` verifies their SHA-256 hashes and the
PortGroups before creating that archive. It expects the archives in
`/private/tmp/networksharer-deps/sources` and `macports-base`, unless
`--dependencies` points to another directory containing those subdirectories.
The script embeds the exact download URLs and expected hashes. For each
MacPorts base archive the hash was checked against GitHub's official Release
asset metadata. Build dependencies, SDK availability, and reproducibility on
all systems are not established by the archive alone.

The distributed runtime files were modified with `install_name_tool` to change
their install names and non-system dynamic-library references from `/opt/local`
to adjacent `@loader_path` files, then given ad hoc signatures. No upstream
source change is implied by that path relocation. The exact component licenses
and copyright notices remain applicable; the complete corresponding source
archive, a way to replace dynamically linked libraries, and any other required
distribution materials must be checked before release. No legal conclusion is
claimed here.

To prepare the same relocatable arm64 runtime components from the signed
MacPorts binary archives without changing the system installation, run:

```sh
python3 Tools/prepare_runtime.py --packages /private/tmp/networksharer-packages \
  --output /private/tmp/networksharer-runtime --download-missing
export NETWORKSHARER_GLIB_PREFIX=/private/tmp/networksharer-runtime/glib
export NETWORKSHARER_PROTO_RUNTIME=/private/tmp/networksharer-runtime/runtime
python3 build_standalone.py
```

The preparation tool checks the pinned SHA-256 of each package and verifies
its MacPorts signature with the included MacPorts public key, extracts only
the needed files into a new output directory, then changes library install
names and signs the copied libraries ad hoc. It does not modify the system
installation. For example, after building a compatible replacement of
`libglib-2.0.0.dylib` with the same ABI, an Apple Silicon user may install it in
a **copy** of the app and re-sign that copy:

```sh
NETWORKSHARER_APP='/Applications/局域网代理共享器.app'
# Copy your compatible replacement to:
# "$NETWORKSHARER_APP/Contents/MacOS/libglib-2.0.0.dylib"
codesign --force --sign - "$NETWORKSHARER_APP/Contents/MacOS/libglib-2.0.0.dylib"
codesign --force --sign - "$NETWORKSHARER_APP"
codesign --verify --deep --strict "$NETWORKSHARER_APP"
```

The replacement must have a compatible ABI and load its non-system dependencies
from paths that exist on the target Mac. Use `otool -L` to inspect those paths;
the preparation tool demonstrates the required `install_name_tool` changes.
The recipient can instead build the application against replacement libraries
by setting the two variables above. These procedures use an ad hoc signature;
they do not provide a Developer ID signature or notarization.

The modified libslirp 4.9.7 source and its copyright notices are included with
the application under `ThirdParty/libslirp`; the applicable notices appear in
its LICENSE, COPYRIGHT and source files.

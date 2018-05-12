# d-cryptonote

`d-cryptonote` is a wrapper of cryptonote C++ library written by:
    - The Monero Project
    - Brian Gladman
    - Oliver Weichhold
    - others...


## build

Use the dub package manager.

The following dependencies are required to build the original cryptonote library:
    - boost-devel
    - stdc++

Available build configurations:

    dub build --config=static   // use a local static library

    dub build --config=shared   // use a shared library

    dub test // run unit tests


## available functions

```d
import cryptonote;

static ubyte[] convertBlob(ubyte[] data, int size);

static ulong decodeAddress(string address);

static ulong decodeIntegratedAddress(string address);

static ubyte[] cryptonightHashSlow(ubyte[] data, int variant);

static ubyte[] cryptonightHashSlowLite(ubyte[] data);

static ubyte[] cryptonightHashFast(ubyte[] data);
```

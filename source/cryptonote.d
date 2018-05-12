/*
Copyright 2018 Eliott Dumeix

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and
associated documentation files (the "Software"), to deal in the Software without restriction,
including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense,
and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so,
subject to the following conditions:
The above copyright notice and this permission notice shall be included in all copies or substantial
portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT
LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/
module cryptonote;

import std.string;
import std.conv;
import std.typecons;
import std.stdio;

version(unittest)
{
    import dunit.toolkit;
    import std.exception: assertThrown;
    import core.exception: AssertError;

    import std.conv: parse;
    import std.array: array;
    import std.range: chunks;
    import std.algorithm: map;

    import std.digest: toHexString;

    ubyte[] hexToBytes(string hexstr)
    {
        return (hexstr.length % 2 ? "0" ~ hexstr : hexstr)
        .chunks(2)
        .map!(twoDigits => twoDigits.parse!ubyte(16))
        .array();
    }
}

// export cryptonote lib to D in private section
// lib must be used through LibCryptonote static class
private
{
    extern (C):
    nothrow:
    @nogc:

    bool convert_blob_export(const ubyte* input, int inputSize, ubyte* output, int *outputSize);

    ulong decode_address_export(const ubyte* input, uint inputSize);

    ulong decode_integrated_address_export(const ubyte* input, uint inputSize);

    void cn_slow_hash_export(const ubyte* input, ubyte* output, uint inputSize, uint variant);

    void cn_slow_hash_lite_export(const ubyte* input, ubyte* output, uint inputSize);

    void cn_fast_hash_export(const ubyte* input, ubyte* output, uint inputSize);
}

const enum BUFFER_SIZE = 256;


static ubyte[] convertBlob(ubyte[] data, int size)
in {
    assert(data != null, "data must not be null");
    assert(data.length > 0, "data must not be empty");
}
do {
    // provide reasonable large output buffer
    ubyte[] outputBuffer = new ubyte[0x100];

    int outputBufferLength = cast(int) outputBuffer.length;
    auto success = false;

    success = convert_blob_export(data.ptr, size, outputBuffer.ptr, &outputBufferLength);

    if (!success)
    {
        // if we get false, the buffer might have been too small
        if (outputBufferLength == 0)
            return null; // nope, other error

        // retry with correctly sized buffer
        outputBuffer = new ubyte[outputBufferLength];

        success = convert_blob_export(data.ptr, size, outputBuffer.ptr, &outputBufferLength);

        if (!success)
            return null; // sorry

        return outputBuffer[0..outputBufferLength];
    }

    return outputBuffer[0..outputBufferLength];
}

unittest // convertBlob
{
    string blob = "0106E5B3AFD505583CF50BCC743D04D831D2B119DC94AD88679E359076EE3F18D258EE138B3B421C0300A401D90101FF9D0106D6D6A88702023C62E43372A58CB588147E20BE53A27083F5C522F33C722B082AB7518C48CDA280B4C4C32102609EC96E2499EE267D70EFEFC49F26E330526D3EF455314B7B5BA268A6045F8C80C0FC82AA0202FE5CC0FA56C4277D1A47827EDCE4725571529D57F33C73ADA481EF84C323F30A8090CAD2C60E02D88BF5E72A611C8B8464CE29E3B1ADBFE1AE163886D9150FE511171CADA98FCB80E08D84DDCB0102441915AAF9FBAF70FF454C701A6AE2BD59BB94DC0B888BF7E5D06274EE9238CA80C0CAF384A302024078526E2132DEF44BDE2806242652F5944E632F7D94290DD6EE5DDA1929F5EE2B016E29F25F07EC2A8DF59F0E118A6C9A4B769B745DC0C729071F6E0399D2585745020800000000012E7F76000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";

    ubyte[] hex = blob.hexToBytes();

    ubyte[] result = convertBlob(hex, 330);

    string s = result.toHexString();

    assertEqual("0106E5B3AFD505583CF50BCC743D04D831D2B119DC94AD88679E359076EE3F18D258EE138B3B421C0300A4487286E262E95B8D2163A0C8B73527E8C9425ADBDC4E532CF0EF4241F9FFBE9E01", s);
}

static ulong decodeAddress(string address)
in {
    assert(address != null, "address must not be null");
    assert(address != "", "addres must not be empty");
}
do {
    ubyte[] data = cast(ubyte[]) address; // string to bytes

    return decode_address_export(data.ptr, cast(uint) data.length);
}

unittest // DecodeAddress
{
    string address = "48nhyWcSey31ngSEhV8j8NPm6B8PistCQJBjjDjmTvRSTWYg6iocAw131vE2JPh3ps33vgQDKLrUx3fcErusYWcMJBxpm1d";
    ulong result = decodeAddress(address);

    assertEqual(18uL, result);
}

static ulong decodeIntegratedAddress(string address)
in {
    assert(address != null, "address must not be null");
    assert(address != "", "addres must not be empty");
}
do {
    ubyte[] data = cast(ubyte[]) address; // string to bytes

    return decode_integrated_address_export(data.ptr, cast(uint) data.length);
}

unittest // decodeIntegratedAddress
{
    string address = "4BrL51JCc9NGQ71kWhnYoDRffsDZy7m1HUU7MRU4nUMXAHNFBEJhkTZV9HdaL4gfuNBxLPc3BeMkLGaPbF5vWtANQsGwTGg55Kq4p3ENE7";
    ulong result = decodeIntegratedAddress(address);

    assertEqual(19uL, result);
}

static ubyte[] cryptonightHashSlow(ubyte[] data, int variant)
in {
    assert(data != null, "data must not be null");
}
do {
    ubyte[] result = new ubyte[32];

    cn_slow_hash_export(data.ptr, result.ptr, cast(uint) data.length, variant);

    return result;
}

unittest // cryptonightHashSlow
{
    ubyte[] blobConverted = "0106A2AAAFD505583CF50BCC743D04D831D2B119DC94AD88679E359076EE3F18D258EE138B3B42580100A4B1E2F4BAF6AB7109071AB59BC52DBA740D1DE99FA0AE0C4AFD6EA9F40C5D87EC01".hexToBytes();
    string result = cryptonightHashSlow(blobConverted, 0).toHexString();

    assertEqual("A845FFBDF83AE9A8FFA504A1011EFBD5ED2294BB9DA591D3B583740568402C00", result);

    assertThrown!AssertError(cryptonightHashSlow(null, 0));

}

static ubyte[] cryptonightHashSlowLite(ubyte[] data)
in {
    assert(data != null, "data must not be null");
}
do {
    ubyte[] result = new ubyte[32];

    cn_slow_hash_lite_export(data.ptr, result.ptr, cast(uint) data.length);

    return result;
}

unittest // cryptonightHashSlowLite
{
    ubyte[] blobConverted = "0106F1ADAFD505583CF50BCC743D04D831D2B119DC94AD88679E359076EE3F18D258EE138B3B42597710C48C6D885E2622F40F82ECD9B9FD538F28DF9B0557E07CD3237A31C76569ADA98001".hexToBytes();
    string result = cryptonightHashSlowLite(blobConverted).toHexString();

    assertEqual("0769CAEE428A232CFFB76FA200F174FF962734F24E7B3BF8D1B0D4E8BA6CEEBF", result);
}

static ubyte[] cryptonightHashFast(ubyte[] data)
in {
    assert(data != null, "data must not be null");
}
do {
    ubyte[] result = new ubyte[32];

    cn_fast_hash_export(data.ptr, result.ptr, cast(uint) data.length);

    return result;
}

unittest // cryptonightHashFast
{
    ubyte[] blobConverted = "0106A2AAAFD505583CF50BCC743D04D831D2B119DC94AD88679E359076EE3F18D258EE138B3B42580100A4B1E2F4BAF6AB7109071AB59BC52DBA740D1DE99FA0AE0C4AFD6EA9F40C5D87EC01".hexToBytes();
    string result = cryptonightHashFast(blobConverted).toHexString();

    assertEqual("DDC0E3A33B605CE39FA2D16A98D7634E33399AB1E4B56B3BDD3414B655FE9A98", result);
}

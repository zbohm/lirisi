const ref = require("ref")
const ffi = require("ffi")
const Struct = require("ref-struct")
const ArrayType = require("ref-array")


const BytesArray = ArrayType(ref.types.byte)

// Define object GoSlice to map to:
// C type struct { void *data; GoInt len; GoInt cap; }
const GoSlice = Struct({
    data: BytesArray,
    len:  "ulonglong",
    cap: "ulonglong"
})

// typedef struct { GoInt len; GoUint8 data[]; } GoBytes;
const GoBytes = Struct({
    len:  "ulonglong",
    data: BytesArray,
})

function uInt64LE(bytes) {
    return bytes.reverse().reduce((a, c, i) => a + c * 2**(56 - i * 8), 0)
}

function toBytes(pointer) {
    const size = uInt64LE(ref.readPointer(pointer['ref.buffer'], 0, 8))
    const buffer = ref.readPointer(pointer['ref.buffer'], 0, size + 8)
    return Array.from(buffer.slice(8))
}

function toSlice(array) {
    const slice = new GoSlice()
    slice.data = BytesArray(Array.from(array))
    slice.len = privateKey.length
    slice.cap = privateKey.length
    return slice
}

// Create private key
function CreatePrivateKey() {
    return toBytes(lib.CreatePrivateKey())
}

// Extract public key from private key
function ExtractPublicKey(privateKey) {
    return toBytes(lib.ExtractPublicKey(toSlice(privateKey)))
}

const lib = ffi.Library("./lirisilib.so", {
    CreatePrivateKey: [GoBytes, []],
    ExtractPublicKey: [GoBytes, [GoSlice]]
})

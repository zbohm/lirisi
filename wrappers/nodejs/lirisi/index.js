const ref = require("ref")
const ffi = require("ffi")
const Struct = require("ref-struct")
const ArrayType = require("ref-array")
const path = require("path")

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
    slice.len = array.length
    slice.cap = array.length
    return slice
}

// Create private key
module.exports.CreatePrivateKey = () => toBytes(lib.CreatePrivateKey())


// Extract public key from private key
module.exports.ExtractPublicKey = (privateKey) => toBytes(lib.ExtractPublicKey(toSlice(privateKey)))

// CreateRingOfPublicKeys creates a ring of public keys.
module.exports.CreateRingOfPublicKeys = (size) => toBytes(lib.CreateRingOfPublicKeys(size))

// CreateRingOfPublicKeys creates a ring of public keys.
module.exports.CreateSignature = (message, pubKeysRing, privKey) =>
    toBytes(lib.CreateSignature(toSlice(message), toSlice(pubKeysRing), toSlice(privKey)))


// Convert signature into format PEM.
module.exports.SignToPEM = (signBytes) => toBytes(lib.SignToPEM(toSlice(signBytes)))

// Convert PEM to signature.
module.exports.PEMtoSign = (signBytes) => toBytes(lib.PEMtoSign(toSlice(signBytes)))

// VerifySignature verify signature.
module.exports.VerifySignature = (message, pubKeysRing, sign) =>
    lib.VerifySignature(toSlice(message), toSlice(pubKeysRing), toSlice(sign))

// GetPubKeyBytesSize is the lenth of bytes serialized public key.
module.exports.GetPubKeyBytesSize = () => lib.GetPubKeyBytesSize()


const lib = ffi.Library(path.join(__dirname, "lirisilib.so"), {
    CreatePrivateKey: [GoBytes, []],
    ExtractPublicKey: [GoBytes, [GoSlice]],
    CreateRingOfPublicKeys: [GoBytes, ["longlong"]],
    CreateSignature: [GoBytes, [GoSlice, GoSlice, GoSlice]],
    VerifySignature: ["longlong", [GoSlice, GoSlice, GoSlice]],
    SignToPEM: [GoBytes, [GoSlice]],
    PEMtoSign: [GoBytes, [GoSlice]],
    GetPubKeyBytesSize: ["longlong", []]
})

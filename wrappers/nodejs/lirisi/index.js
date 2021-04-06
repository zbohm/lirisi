const ref = require("ref")
const ffi = require("ffi")
const Struct = require("ref-struct")
const ArrayType = require("ref-array")
const path = require("path")
const utf8 = require('utf8')

const Success = 0

const ErrorCode = {
	1: "PrivateKeyNotFitPublic",
	2: "InsufficientNumberOfPublicKeys",
	3: "PrivateKeyPositionOutOfRange",
	4: "PrivateKeyNotFoundAmongPublicKeys",
	5: "UnexpectedCurveType",
	6: "UnexpectedHashType",
	7: "IncorrectNumberOfSignatures",
	8: "InvalidKeyImage",
	9: "IncorrectChecksum",
	10: "OIDHasherNotFound",
	11: "OIDCurveNotFound",
	12: "UnsupportedCurveHashCombination",
	13: "PointWasNotFound",
	14: "DecodePEMFailure",
	15: "UnexpectedRestOfSignature",
	16: "Asn1MarshalFailed",
	17: "EncodePEMFailed",
	18: "InvalidPointCoordinates",
	19: "NilPointCoordinates",
	20: "ParseECPrivateKeyFailure",
	21: "Asn1UnmarshalFailed",
	22: "MarshalPKIXPublicKeyFailed",
	23: "ParsePKIXPublicKeyFailed",
}

const BytesArray = ArrayType(ref.types.byte)

const GoBoolean = ref.types.ushort


// Define object GoBytes to map to:
// C type struct { void *data; GoInt len; GoInt cap; }
const GoBytes = Struct({
    data: BytesArray,
    len:  ref.types.ulonglong,
    cap: ref.types.ulonglong,
})

const GoBytesArrayType = ArrayType(GoBytes)

const GoBytesArray = Struct({
    data: GoBytesArrayType,
    len:  ref.types.ulonglong,
    cap: ref.types.ulonglong
})

const GoString = Struct({
    p: BytesArray,
    n: ref.types.int
})

const GoStringArrayType = ArrayType(GoString)

const GoStringsArray = Struct({
    data: GoStringArrayType,
    len:  ref.types.ulonglong,
    cap: ref.types.ulonglong
})

// typedef struct { GoInt len; GoUint8 data[]; } BuffBytes;
const BuffBytes = Struct({
    data: BytesArray,
    len:  ref.types.ulonglong,
})


const intSize = 8


function toBytes(pointer) {
    const status = ref.readUInt64LE(ref.readPointer(pointer['ref.buffer'], 0, intSize))
    if (status != Success) {
        throw new Error(ErrorCode[status])
    }
    const size = ref.readUInt64LE(ref.readPointer(pointer['ref.buffer'], 0, intSize * 2).slice(intSize))
    const buffer = ref.readPointer(pointer['ref.buffer'], 0, intSize * 2 + size)
    return Array.from(buffer.slice(intSize * 2))
}

function toBytesArray(pointer) {
    const status = ref.readUInt64LE(ref.readPointer(pointer['ref.buffer'], 0, intSize))
    if (status != Success) {
        throw new Error(ErrorCode[status])
    }
    const length = ref.readUInt64LE(ref.readPointer(pointer['ref.buffer'], 0, intSize * 2).slice(intSize))

    let from, to, size, buffer, data = []

    from = intSize * 2
    to = intSize * 2

    for (let i=0; i < length; i++) {
        size = ref.readUInt64LE(ref.readPointer(pointer['ref.buffer'], 0, to).slice(from))
        if (i == 0) {
            to += intSize
        }
        to += size
        from += intSize
        buffer = ref.readPointer(pointer['ref.buffer'], 0, to)
        data.push(Array.from(buffer.slice(from)))
        to += intSize
        from += size
    }
    return data
}


function toString(pointer) {
    return Buffer.from(toBytes(pointer)).toString()
}


function goBytes(octests) {
    const slice = new GoBytes()
    slice.data = Array.from(octests)
    slice.len = octests.length
    slice.cap = octests.length
    return slice
}

function goString(string) {
    const slice = new GoString()
    const bytes = Array.from(utf8.encode(string))
    slice.p = bytes
    slice.n = bytes.length
    return slice
}

function goBytesArray(array) {
    const data = []
    for (var i=0; i < array.length; i++) {
        data.push(goBytes(array[i]))
    }
    const slice = new GoBytesArray()
    slice.data = new GoBytesArrayType(data)
    slice.len = data.length
    slice.cap = data.length
    return slice
}

function goStringsArray(texts) {
    const data = []
    for (var i=0; i < texts.length; i++) {
        data.push(goString(texts[i]))
    }
    const slice = new GoStringsArray()
    slice.data = new GoStringArrayType(data)
    slice.len = data.length
    slice.cap = data.length
    return slice
}


module.exports.FoldPublicKeys = (
        pubKeyContens,
        hashName = 'sha3-256',
        outFormat = 'PEM',
        order = 'hashes'
    ) => toBytes(lib.FoldPublicKeys(
        goBytesArray(pubKeyContens),
        goString(hashName),
        goString(outFormat),
        goString(order),
    ))

module.exports.CreateSignature = (
        foldedPublicKeys,
        privateKeyContent,
        message,
        caseIdentifier = '',
        outFormat = 'PEM'
    ) => toBytes(lib.CreateSignature(
        goBytes(foldedPublicKeys),
        goBytes(privateKeyContent),
        goBytes(message),
        goBytes(caseIdentifier),
        goString(outFormat),
    ))

module.exports.VerifySignature = (
        foldedPublicKeys,
        signature,
        message,
        caseIdentifier = '',
    ) => lib.VerifySignature(
        goBytes(foldedPublicKeys),
        goBytes(signature),
        goBytes(message),
        goBytes(caseIdentifier),
    )

module.exports.SignatureKeyImage = (signature, separator = false) => toString(lib.SignatureKeyImage(goBytes(signature), separator))
module.exports.PublicKeysDigest = (foldedPublicKeys, separator = false) => toString(lib.PublicKeysDigest(goBytes(foldedPublicKeys), separator))
module.exports.PublicKeyXYCoordinates = (publicKey) => toBytes(lib.PublicKeyXYCoordinates(goBytes(publicKey)))
module.exports.UnfoldPublicKeys = (foldedPublicKeys, format = 'PEM') => toBytesArray(lib.UnfoldPublicKeys(goBytes(foldedPublicKeys), goString(format)))
module.exports.GeneratePrivateKey = (curveName = 'prime256v1', format = 'PEM') => toBytes(lib.GeneratePrivateKey(goString(curveName), goString(format)))
module.exports.DerivePublicKey = (privateKey, format = 'PEM') => toBytes(lib.DerivePublicKey(goBytes(privateKey), goString(format)))

module.exports.ArrayToString = (array) => Buffer.from(array).toString()
module.exports.ResultMessage = (code) => code === Success ? "Verified OK." : "Verification Failure: " + ErrorCode[code]


const lib = ffi.Library(path.join(__dirname, "lirisilib.so"), {
    FoldPublicKeys: [BuffBytes, [GoBytesArray, GoString, GoString, GoString]],
    CreateSignature: [BuffBytes, [GoBytes, GoBytes, GoBytes, GoBytes, GoString]],
    VerifySignature: [ref.types.int, [GoBytes, GoBytes, GoBytes, GoBytes]],
    SignatureKeyImage: [BuffBytes, [GoBytes, GoBoolean]],
    PublicKeysDigest: [BuffBytes, [GoBytes, GoBoolean]],
    PublicKeyXYCoordinates: [BuffBytes, [GoBytes]],
    UnfoldPublicKeys: [BuffBytes, [GoBytes, GoString]],
    GeneratePrivateKey: [BuffBytes, [GoString, GoString]],
    DerivePublicKey: [BuffBytes, [GoBytes, GoString]],
})

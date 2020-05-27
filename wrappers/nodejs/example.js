/*
npm install

node example.js
*/
const shuffle = require('shuffle-array')
const convertHex = require('convert-hex')
const lirisi = require('lirisi')

// Create your provate key.
const privateKey = lirisi.CreatePrivateKey()
console.log("Your private key:")
console.log(convertHex.bytesToHex(privateKey))
/*
Your private key:
2679fd46ca96602c21affaa48b3d4e13b902bb9494751c0a87271d2373e1364a
*/

// Extract public key.
const publicKey = lirisi.ExtractPublicKey(privateKey)
console.log("\nYour public key:")
console.log(Buffer.from(publicKey).toString("base64"))
/*
Your public key:
BPiG5WjNzwPARnp7oOIbvUl0HPANWIrUsC898xuwYuzlqlBPssGnpm9BUQmgrRm0aAvvOBTYJ4em6Wz76awzLyg=
*/

// Create the ring of fake public keys.
const ring = lirisi.CreateRingOfPublicKeys(9)

// Append your public key.
const ringBytes = ring.concat(publicKey)

// Shuffle ring randomly
const size = lirisi.GetPubKeyBytesSize()
let pubsRing = []
for (let i = 0; i < ringBytes.length / size; i++) {
    const n = i * size
    pubsRing.push(ringBytes.slice(n, n + size))
}
shuffle(pubsRing)
// Concat shuffled keys into one array.
let ringPubs = []
for (let i = 0; i < pubsRing.length; i++) {
    ringPubs = ringPubs.concat(pubsRing[i])
}

// Serialize public keys for save.
let b64Pubs = []
for (let i = 0; i < pubsRing.length; i++) {
    b64Pubs.push(Buffer.from(pubsRing[i]).toString("base64"))
}
console.log("\nRing of public keys:")
console.log(b64Pubs.join("\n"))
/*
Ring of public keys:
BAB0waZBNlIT8n5OgATUJSGeJX6lQxBK+S/WfVsA1UWMDO7yNsbKkdCvFuJYFImfyD0pOv4SWOhlrbkIVslIO+M=
BLp801LIVSIcOMVoEpfb1PfP19JwI+6wfl4Gy/fppwjEy5ISoShL0OyBSL3QxTDKSPx6dVug3fJPU183uYDjLF4=
BDGMfeZKpud/RznARmLdDWo00NoNF7Cxqo7q2LNBHNJxP2YkQiVM0Fb/iXxtKIwapxOAB1FUkk7ElIO52mTg69E=
BPypBiipURq3YXeqkAsDpRQC9+i0mE9iqSzeG86MJ45Z3emIfIiSA119ZnTqemiUJRqg/ei/is9SBJRvpHSFEwA=
BGp6cefHI9nhIHlce4aF98h/4yaq3zQYCwQp+Ff91FNJdD9fbH/JVzJfLZnJ3xV6sXWRy/bmqWFK8giV1bMi/jM=
BC/c7mXhJrP9mrwvcBmk78innrYw5WrhuNV/+Vam+Lglx7VE33xnVlwNzqcHvPuzxjRnp4YQT6SJWnX2PVn7kcU=
BFWqAoa+hoY2bfPZE/TSDBIhIUA+rZYNc8rlnmta1oaANcPdRNXv2QWq3rmBn/RwvYHsHfpXO21qLIUu7mzPLCg=
BJhZiBf2XiIUIP88TcBP0EwYeEuGW0ek4KtT/MIIlTkpm9SomdRWZPLvHnPy2Yvm3wpMo+jucN7CPMRjhuYUIm4=
BPiG5WjNzwPARnp7oOIbvUl0HPANWIrUsC898xuwYuzlqlBPssGnpm9BUQmgrRm0aAvvOBTYJ4em6Wz76awzLyg=
BJd6+bzj43l1dZmkg1ygYSkBRysHOCW+Dx1XH21gADS8bC1bO9qgTcwjE9FyDr7BhJ5AzCZgkce+9nfb6wMK6so=
*/

// Prepare message to sign.
const message = "Hello world!"

// Make signature.
const sign = lirisi.CreateSignature(message, ringPubs, privateKey)
const pem = lirisi.SignToPEM(sign)
console.log("\nSignature in PEM:")
console.log(Buffer.from(pem).toString())
/*
Signature in PEM:
-----BEGIN RING SIGNATURE-----
KeyImage: Xs6oCbGa1pt0wqVjXZQHLqiLXNNJKa/1VNWeEf6oSSFnzGmOWQ6xhQZirle0aMYP77brws5a71CxUhxHzEeFCA==

QklJQm9GN09xQW14bXRhYmRNS2xZMTJVQnk2b2kxelRTU212OVZUVm5oSCtxRWto
Wjh4cGpsa09zWVVHWXE1WHRHakdEKysyNjhMT1d1OVFzVkljUjh4SGhRZ1U5aG5T
N25iTmp0TlNwenAvTk9UbTlFcmliMVlsNHNvK2VJWlU2VXhDanhkclc2c1hWMVp1
aFp4dXpSMDFjQWp1UHY0NC96cm0yeUNXaWJVSXlSVExWd2dONnZHWVdhWGpqNzdh
aGJtNm1OcVE2aTFVMS9BTXRmaGk5N2ZrUzVvYTAvL012UllVWHdwWGxvMTh3RXgw
Y0hFMytCMGh0VS9lOXFxcEtsNWFpVW1xRmp3Y0J5ZUtldXh1UGN3MmQ4bWYxM2p4
TEpmekVNaGp6MTFEWXNaZzNVTWh6c2pUVFRMd015czI3MXM2bFhyM3lIQlAycXl2
L0dVdXliclE2S3FvOVBOdHVVYkxDbW5wdEl5MkNTRTlhbkJjSytjQkdqWkpQYTBn
UDJ1Ym5Kd3diZDRMWnhEcEpzazRlR3RjL2RlNHpiTWdBT3Y1WHlOTkNWQTRvdjND
cWM0MnM3eVNXM3lQellaZG8rSFN0NWFIV0tCTlRzWmJFVlM2K1oyNmdzM3RKVTQ4
WVJDSzg5WDdVdXEzeFFZV2lGeW5weWxvc0Q5Ynh0a0FMOWFWLzVRQkwzYmVHY0xJ
UHBxSGtMSzB5UUFCcFpEbHVlSWFYUzlhQnltOVpkZkU=
-----END RING SIGNATURE-----
*/

const signFromPEM = lirisi.PEMtoSign(pem)

// Verify signature.
const result = lirisi.VerifySignature(message, ringPubs, signFromPEM)
console.log("Result of verification (1):", result)
/*
Result of verification (1): 1
*/

const failed = lirisi.VerifySignature("foo", ringPubs, signFromPEM)
console.log("Invalid verification (0):", failed)
/*
Invalid verification (0): 0
*/

// Get KeyImage - unique private key identifier.
const keyImage = lirisi.GetKeyImage(signFromPEM)
console.log("\nKeyImage:", Buffer.from(keyImage).toString("base64"))
/*
KeyImage: rVCx0N999oGof35UnuNC35RcYfTpEUD7ORupIQDV+yLrpC7CbDMGPPPRzK6HpnjS/apWP5Grb9qWsOuevW1ixw==
*/

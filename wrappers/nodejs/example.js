var Eckles = require('eckles')
const lirisi = require('lirisi')


const main = async () => {
    // Create private key.
    const privatePem = lirisi.GeneratePrivateKey()
    console.log("Curve type prime256v1:\n", lirisi.ArrayToString(privatePem))

    // Create public key.
    const publicPem = lirisi.DerivePublicKey(privatePem)
    console.log(lirisi.ArrayToString(publicPem))

    // Creating public keys as a simulation of keys supplied by other signers.
    const publicKeysPEM = []
    for (let i = 0; i < 9; i++) {
        const pair = await Eckles.generate({format: 'pem'})
        publicKeysPEM.push(pair.public)
    }

    // Create your private and public key.
    const pair = await Eckles.generate({format: 'pem'})
    const privateKeyPEM = pair.private
    const publicKeyPEM = pair.public
    console.log("Eckles.generate:\n", privateKeyPEM, "\n")

    const coordinates = lirisi.PublicKeyXYCoordinates(publicKeyPEM)
    console.log("Puplic key coordinates:\n", Buffer.from(coordinates).toString('hex'), "\n")

    // Add your public key to other public keys.
    publicKeysPEM.push(publicKeyPEM)

    // Create the content of file with public keys.
    const foldedPublicKeys = lirisi.FoldPublicKeys(publicKeysPEM)
    console.log(lirisi.ArrayToString(foldedPublicKeys))

    // Display fingerprint of public keys.
    console.log("Digest:", lirisi.PublicKeysDigest(foldedPublicKeys, true), "\n")

    const message = 'Hello, world!'

    // Make signature.
    const signature = lirisi.CreateSignature(foldedPublicKeys, privateKeyPEM, message)
    console.log(lirisi.ArrayToString(signature))

    // Verify signature.
    const result = lirisi.VerifySignature(foldedPublicKeys, signature, message)
    console.log(lirisi.ResultMessage(result), "\n")

    console.log("KeyImage:", lirisi.SignatureKeyImage(signature, true), "\n")

    const unfoldedPublicKeys = lirisi.UnfoldPublicKeys(foldedPublicKeys)
    for(let i = 0; i < unfoldedPublicKeys.length; i++) {
        console.log(
            'public-key-' + (i + 1).toString().padStart(2, "0") + '.pem\n',
            lirisi.ArrayToString(unfoldedPublicKeys[i])
        )
    }
}

main().catch((e) => {
    console.error(e)
})

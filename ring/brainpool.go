package ring

import (
	"crypto/elliptic"
	"math/big"

	"github.com/keybase/go-crypto/brainpool"
)

// Zinv values for brainpool R type
type Zinv struct {
	Zinv2 *big.Int
	Zinv3 *big.Int
}

// TwistedCurves maps curve names to twisted curves.
var TwistedCurves = map[string]func() elliptic.Curve{
	"brainpoolP256r1": brainpool.P256r1,
	"brainpoolP384r1": brainpool.P384r1,
	"brainpoolP512r1": brainpool.P512r1,
}

// BrainpoolParentCurves maps twisted curves with untwisted parents.
var BrainpoolParentCurves = map[string]func() elliptic.Curve{
	"brainpoolP256r1": brainpool.P256t1,
	"brainpoolP384r1": brainpool.P384t1,
	"brainpoolP512r1": brainpool.P512t1,
}

// BrainpoolZ maps Z values required by GetZinv for function fromTwisted.
var BrainpoolZ = map[string]string{
	"brainpoolP256r1": "3E2D4BD9597B58639AE7AA669CAB9837CF5CF20A2C852D10F655668DFC150EF0",
	"brainpoolP384r1": "41DFE8DD399331F7166A66076734A89CD0D2BCDB7D068E44E1F378F41ECBAE97D2D63DBC87BCCDDCCC5DA39E8589291C",
	"brainpoolP512r1": "12EE58E6764838B69782136F0F2D3BA06E27695716054092E60A80BEDB212B64E585D90BCE13761F85C3F1D2A64E3BE8FEA2220F01EBA5EEB0F35DBD29D922AB",
}

// BrainpoolZinv inverzed Zinv.
var BrainpoolZinv = map[string]Zinv{}

// GetZinv returns values zinv2, zinv3 for given curve.
func GetZinv(curveName string) (*big.Int, *big.Int) {
	if _, found := BrainpoolZinv[curveName]; !found {
		curve := TwistedCurves[curveName]()
		params := curve.Params()
		z, _ := new(big.Int).SetString(BrainpoolZ[curveName], 16)
		zinv := new(big.Int).ModInverse(z, params.P)
		BrainpoolZinv[curveName] = Zinv{
			Zinv2: new(big.Int).Exp(zinv, big.NewInt(2), params.P),
			Zinv3: new(big.Int).Exp(zinv, big.NewInt(3), params.P),
		}
	}
	return BrainpoolZinv[curveName].Zinv2, BrainpoolZinv[curveName].Zinv3
}

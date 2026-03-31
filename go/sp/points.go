package sp

import "github.com/btcsuite/btcd/btcec/v2"

func scalarMultiply(point *btcec.PublicKey,
	scalar *btcec.ModNScalar) btcec.JacobianPoint {

	var pointJacobian btcec.JacobianPoint
	point.AsJacobian(&pointJacobian)

	var result btcec.JacobianPoint
	btcec.ScalarMultNonConst(scalar, &pointJacobian, &result)
	return result
}

func jacobianToPublicKey(point *btcec.JacobianPoint) (*btcec.PublicKey, bool) {
	if point == nil || (point.X.IsZero() && point.Y.IsZero()) {
		return nil, false
	}

	point.ToAffine()
	return btcec.NewPublicKey(&point.X, &point.Y), true
}

func scalarBaseMultiply(scalar *btcec.ModNScalar) btcec.JacobianPoint {
	var result btcec.JacobianPoint
	btcec.ScalarBaseMultNonConst(scalar, &result)
	return result
}

+++
title = "Quantum Device"
date = 2022-06-11

[taxonomies]
tags = ["Julia", "Quantum computing"]
+++

A description of the general problem can be view at the Wikipedia page on [QSD](https://en.wikipedia.org/wiki/Quantum_state_discrimination).  

The below solution seeks to use semi-definite programming to solve the problem where $$X=E_0, C = \frac{1}{2} (\sigma_0-\sigma_1)$$ 

```julia
using ProxSDP, LinearAlgebra, Convex 
X, val = let
	C = [0.35  0.2
	      0.2  -0.35]
	X = Convex.Variable(2, 2)
	Y = Convex.Variable(2, 2)
	c1 = (X⪰0)
	c2 = (Y⪰0)
	Z = X + Y
	# X, Y ⪰ 0; X + Y = I
	constraints = [Z[1,1] == 1, Z[1,2] == 0, Z[2,1] == 0, Z[2,2] == 1, c1, c2]
	p = minimize(tr(C*X), constraints)
	Convex.solve!(p, ProxSDP.Optimizer, verbose=true, silent_solver=false)
	X.value, 1/2 - tr(C*X.value)
end
```
import Lake
open Lake DSL

package ParaxiomPQC where
  leanOptions := #[⟨`autoImplicit, false⟩]

@[default_target]
lean_lib ParaxiomPQC where
  srcDir := "."
  roots := #[`ParaxiomPQC]

require mathlib from git
  "https://github.com/leanprover-community/mathlib4" @ "v4.27.0"

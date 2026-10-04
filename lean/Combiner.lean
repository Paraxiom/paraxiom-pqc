/-!
# Combiner encoding is injective

`src/combiner.rs` hashes

    label || count || for each input: (mechanism id || length || secret) || length || context

This file proves that the encoding is injective: two different (input list, context)
pairs never produce the same byte string. So the only way two different combinations
can collide is a SHA3-256 collision.

Model: bytes are `Nat` symbols; the fixed-width fields (count: 1 byte, mechanism id:
1 byte, lengths: 4 bytes) are each one symbol. Fixed-width fields parse uniquely, so this
abstraction is faithful as long as the Rust side bounds them, which it does (at most 255
inputs, lengths below 2^32). The constant label is a common prefix and does not affect
injectivity. Core Lean only.
-/

namespace Combiner

/-- One input: mechanism identifier, length, then the secret bytes. -/
def encOne (m : Nat) (s : List Nat) : List Nat := m :: s.length :: s

def encAll : List (Nat × List Nat) → List Nat
  | [] => []
  | (m, s) :: rest => encOne m s ++ encAll rest

/-- The full encoding (without the constant label). -/
def encode (inputs : List (Nat × List Nat)) (ctx : List Nat) : List Nat :=
  inputs.length :: (encAll inputs ++ (ctx.length :: ctx))

theorem encAll_append_inj :
    ∀ (a b : List (Nat × List Nat)) (t₁ t₂ : List Nat),
      a.length = b.length → encAll a ++ t₁ = encAll b ++ t₂ → a = b ∧ t₁ = t₂
  | [], [], _, _, _, h => ⟨rfl, by simpa [encAll] using h⟩
  | [], _ :: _, _, _, hl, _ => by simp at hl
  | _ :: _, [], _, _, hl, _ => by simp at hl
  | (m, s) :: ra, (m', s') :: rb, t₁, t₂, hl, h => by
    simp only [encAll, encOne, List.cons_append, List.append_assoc, List.cons.injEq] at h
    obtain ⟨hm, hlen, hrest⟩ := h
    obtain ⟨hs, htail⟩ := List.append_inj hrest hlen
    have hl' : ra.length = rb.length := by simpa using hl
    obtain ⟨hr, ht⟩ := encAll_append_inj ra rb t₁ t₂ hl' htail
    exact ⟨by rw [hm, hs, hr], ht⟩

/-- Different inputs or contexts always give different encodings. -/
theorem encode_injective (a b : List (Nat × List Nat)) (c d : List Nat)
    (h : encode a c = encode b d) : a = b ∧ c = d := by
  simp only [encode, List.cons.injEq] at h
  obtain ⟨hl, hrest⟩ := h
  obtain ⟨hab, htail⟩ := encAll_append_inj a b _ _ hl hrest
  simp only [List.cons.injEq] at htail
  exact ⟨hab, htail.2⟩

end Combiner

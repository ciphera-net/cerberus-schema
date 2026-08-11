// Package cerberus is the wire schema of the Cerberus bot-detection engine: the shape of an
// observation, the shape of a verdict, and the closed grammar a detector uses to ask for evidence.
//
// It is SHAPES ONLY. There is no threshold here, no token list, no allowlist, no honeypot prefix
// and no corpus row — those are properties of a deployment rather than of the method, and one of
// them (the corpus) is customer traffic Ciphera processes on behalf of its customers and could not
// publish under any circumstances.
//
// # What this module is for
//
// A detection engine whose rules write their own queries puts the parts of each rule that carry its
// meaning on the private side of any boundary, where no conformance test can reach them. Five such
// parts turned out to be load-bearing rather than incidental — the window boundary convention, the
// DEDUP UNIT, fail-closed timezone resolution, the arrival-stream union, and whether the scan
// filters on verdict state. Publishing the grammar and a reference implementation of it is what
// makes "this adapter is equivalent" a claim somebody can check instead of a hope.
//
// # Additive-only
//
// The types in this module are an additive-only contract, in the same words the Pulse Public Read
// API uses: a field may be ADDED; none may be REMOVED, RENAMED, or CHANGE TYPE. An enum may gain a
// value; none may lose one or change meaning. TestContractIsAdditiveOnly pins the current surface
// so a removal is a failing test rather than a broken adopter.
//
// # Expect zero adoption
//
// The value of this module is the boundary, not the audience. Ciphera's public repositories run at
// single-digit stars and Tessera has been public since June 2026 with no external contributions. If
// the case for extracting this rested on adoption, the case would fail; it does not.
package cerberus

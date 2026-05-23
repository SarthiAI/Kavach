/**
 * Scenario 08: tiered loan approval with a signed disbursement permit.
 *
 * The story
 * ---------
 * A digital lender splits "underwriting decision" from "moving money
 * to the borrower" across two services:
 *
 *     Underwriting service
 *         Holds the risk policy. Every loan approval runs through a
 *         Kavach gate with three tiers of permission, each with its
 *         own ceiling. When the gate permits, Underwriting signs a
 *         permit token with its ML-DSA-65 key.
 *
 *     Disbursement service
 *         Does not hold any risk rules. It reads the signed permit
 *         off the wire, looks the signer up in a root signed
 *         directory, and verifies the permit. If the verify passes,
 *         it moves funds; if not, it refuses before the ACH rail is
 *         even contacted.
 *
 * The three risk tiers inside Underwriting are:
 *
 *     1. loan_officer: may approve loans up to $50,000.
 *     2. senior_officer: may approve loans up to $250,000.
 *     3. committee_chair: may approve loans up to $1,000,000.
 *
 * On top of that, a regulator style invariant caps any single
 * disbursement at $1,500,000. No single person can approve a loan
 * bigger than that, no matter what role they hold. The chain also
 * rate limits each officer to 20 approvals per hour, which is an
 * abuse ceiling (real throughput is nowhere near that).
 *
 * Seven cases:
 *
 *     A. loan_officer approves a $40,000 consumer loan. Underwriting
 *        permits and signs. Disbursement verifies and pays.
 *     B. loan_officer tries $60,000. Over their tier's cap. Policy
 *        refuses. No signature was even generated.
 *     C. senior_officer takes the same $60,000. Their cap is $250k.
 *        Permits and signs. Disbursement verifies.
 *     D. senior_officer tries $400,000. Over their cap, under the
 *        committee cap, policy refuses.
 *     E. committee_chair approves a $900,000 SMB loan. Permits,
 *        signs, Disbursement verifies.
 *     F. committee_chair tries a $1,600,000 loan. A loose rule that
 *        permits up to $2M lets the policy stage pass, then the
 *        invariant refuses above $1.5M. This pins the property that
 *        the invariant is the final line.
 *     G. Attacker flips the action_name on a legitimate $40k permit
 *        on the wire. The Disbursement service recomputes the
 *        canonical bytes, finds the mismatch, refuses.
 *
 * Run this file directly:
 *
 *   node dist/tier2/08_loan_approval.js
 */

import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  DirectoryTokenVerifier,
  Gate,
  KavachKeyPair,
  PqTokenSigner,
  PublicKeyDirectory,
  type EvaluateOptions,
  type Invariant,
  type PermitTokenInput,
} from 'kavach-sdk';

// ---------------------------------------------------------------------
// Step 1. Policy. Three permit rules, one invariant.
// ---------------------------------------------------------------------

const POLICIES = {
  policies: [
    {
      name: 'loan_officer_small',
      description: 'Loan officers may approve loans up to $50,000',
      effect: 'permit',
      priority: 10,
      conditions: [
        { identity_role: 'loan_officer' },
        { action: 'loan.approve' },
        { param_max: { field: 'amount_usd', max: 50000.0 } },
        { rate_limit: { max: 20, window: '1h' } },
      ],
    },
    {
      name: 'senior_officer_medium',
      description: 'Senior officers may approve loans up to $250,000',
      effect: 'permit',
      priority: 10,
      conditions: [
        { identity_role: 'senior_officer' },
        { action: 'loan.approve' },
        { param_max: { field: 'amount_usd', max: 250000.0 } },
        { rate_limit: { max: 20, window: '1h' } },
      ],
    },
    {
      name: 'committee_chair_large',
      description: 'Committee chairs may approve loans up to $1,000,000',
      effect: 'permit',
      priority: 10,
      conditions: [
        { identity_role: 'committee_chair' },
        { action: 'loan.approve' },
        { param_max: { field: 'amount_usd', max: 1000000.0 } },
        { rate_limit: { max: 20, window: '1h' } },
      ],
    },
  ],
};

// The regulator line. No single disbursement above $1,500,000, no
// matter who signed it off. Also a field a human scan can verify
// quickly: "is this amount over the hard cap? then refuse regardless".
const INVARIANTS: Invariant[] = [
  { name: 'regulator_single_loan_cap', field: 'amount_usd', maxValue: 1500000.0 },
];

function loanCtx(
  principalId: string,
  roles: string[],
  amountUsd: number,
): EvaluateOptions {
  return {
    principalId,
    principalKind: 'user',
    actionName: 'loan.approve',
    roles,
    resource: 'applications/2026-04-21-00347',
    params: { amount_usd: amountUsd },
  };
}

function main(): number {
  console.log('='.repeat(70));
  console.log('Scenario 08: tiered loan approval with a signed disbursement permit');
  console.log('='.repeat(70));
  console.log();
  console.log('We are going to set up Underwriting (signs permits, runs the');
  console.log('risk policy) and Disbursement (verifies the permit, moves');
  console.log('money). Then seven cases including a tier violation, an');
  console.log('invariant breach, and a wire tamper.');
  console.log();

  const results: [string, boolean][] = [];

  // -----------------------------------------------------------------
  // Keypairs.
  // -----------------------------------------------------------------
  console.log('Generating two keypairs.');
  const underwritingKp = KavachKeyPair.generate();
  const rootKp = KavachKeyPair.generate();
  const underwritingBundle = underwritingKp.publicKeys();
  const rootBundle = rootKp.publicKeys();
  console.log(`  underwriting.key_id: ${underwritingKp.id}`);
  console.log(`  root.key_id:         ${rootKp.id}`);
  console.log();

  // -----------------------------------------------------------------
  // Root signed directory loaded into Disbursement.
  // -----------------------------------------------------------------
  console.log('Building the root signed directory.');
  const manifestBytes = rootKp.buildSignedManifest([underwritingBundle]);
  const tmp = mkdtempSync(join(tmpdir(), 'kavach-19-'));
  const manifestPath = join(tmp, 'trusted_signers.json');
  writeFileSync(manifestPath, manifestBytes);
  const directory = PublicKeyDirectory.fromSignedFile(
    manifestPath,
    Buffer.from(rootBundle.mlDsaVerifyingKey),
  );
  const verifier = new DirectoryTokenVerifier(directory, false);
  console.log(`  manifest path:    ${manifestPath}`);
  console.log(`  directory.length: ${directory.length}`);
  console.log();

  // -----------------------------------------------------------------
  // Underwriting's gate.
  // -----------------------------------------------------------------
  console.log("Building Underwriting's gate with its signer attached.");
  const signer = PqTokenSigner.fromKeypairPqOnly(underwritingKp);
  const gate = Gate.fromObject(POLICIES, {
    invariants: INVARIANTS,
    tokenSigner: signer,
  });
  console.log(`  gate.evaluator_count: ${gate.evaluatorCount}`);
  console.log(`  signer.key_id:        ${signer.keyId}`);
  console.log();

  // -----------------------------------------------------------------
  // Case A: small consumer loan, loan officer.
  // -----------------------------------------------------------------
  console.log('-'.repeat(70));
  console.log('Case A: loan officer Meera approves a $40,000 consumer loan.');
  console.log('-'.repeat(70));
  console.log("Role is 'loan_officer', amount is under $50k. The first");
  console.log('rule matches, Underwriting permits and signs. Disbursement');
  console.log('verifies against the directory and accepts. This is the');
  console.log('happy path for everyday retail lending.');
  console.log();

  let v = gate.evaluate(loanCtx('officer-meera', ['loan_officer'], 40000.0));
  console.log(`Underwriting verdict: ${v.kind}`);
  console.log(`Is permit:            ${v.isPermit}`);
  const permitA = v.permitToken;
  let verifyOkA = false;
  if (permitA != null && permitA.signature != null) {
    try {
      verifier.verify(
        {
          tokenId: permitA.tokenId,
          evaluationId: permitA.evaluationId,
          issuedAt: permitA.issuedAt,
          expiresAt: permitA.expiresAt,
          actionName: permitA.actionName,
        },
        Buffer.from(permitA.signature),
      );
      verifyOkA = true;
      console.log('Disbursement.verify(): accepted.');
    } catch (e) {
      const err = e as Error;
      console.log(`Disbursement.verify() raised unexpectedly: ${err.name}: ${err.message}`);
    }
  }
  console.log();

  results.push(['Case A: loan officer $40k permits', v.isPermit]);
  results.push(['Case A: Disbursement verifies', verifyOkA]);
  const caseAPermit = permitA;

  // -----------------------------------------------------------------
  // Case B: loan officer, over their tier.
  // -----------------------------------------------------------------
  console.log('-'.repeat(70));
  console.log('Case B: loan officer Meera tries $60,000.');
  console.log('-'.repeat(70));
  console.log('Her tier caps at $50k. The loan_officer_small rule does not');
  console.log('match because of the param_max. The other two rules require');
  console.log('roles she does not have. No rule matches, default deny. No');
  console.log('signature is ever produced, so no permit leaks to');
  console.log('Disbursement.');
  console.log();

  v = gate.evaluate(loanCtx('officer-meera', ['loan_officer'], 60000.0));
  console.log(`Underwriting verdict: ${v.kind}`);
  console.log(`Is refuse:            ${v.isRefuse}`);
  console.log(`Evaluator:            ${v.evaluator}`);
  console.log(`Code:                 ${v.code}`);
  console.log(`Permit token present: ${v.permitToken != null}`);
  console.log();

  const okB =
    v.isRefuse &&
    v.evaluator === 'policy' &&
    v.code === 'NO_POLICY_MATCH' &&
    v.permitToken == null;
  results.push(['Case B: loan officer $60k refused on tier', okB]);

  // -----------------------------------------------------------------
  // Case C: senior officer, $60k.
  // -----------------------------------------------------------------
  console.log('-'.repeat(70));
  console.log('Case C: senior officer Vikram approves the same $60,000 loan.');
  console.log('-'.repeat(70));
  console.log('The senior_officer_medium rule caps at $250k. $60k is well');
  console.log('under. Permits and signs.');
  console.log();

  v = gate.evaluate(loanCtx('officer-vikram', ['senior_officer'], 60000.0));
  console.log(`Underwriting verdict: ${v.kind}`);
  console.log(`Is permit:            ${v.isPermit}`);
  const permitC = v.permitToken;
  let verifyOkC = false;
  if (permitC != null && permitC.signature != null) {
    try {
      verifier.verify(
        {
          tokenId: permitC.tokenId,
          evaluationId: permitC.evaluationId,
          issuedAt: permitC.issuedAt,
          expiresAt: permitC.expiresAt,
          actionName: permitC.actionName,
        },
        Buffer.from(permitC.signature),
      );
      verifyOkC = true;
      console.log('Disbursement.verify(): accepted.');
    } catch (e) {
      const err = e as Error;
      console.log(`Disbursement.verify() raised unexpectedly: ${err.name}: ${err.message}`);
    }
  }
  console.log();

  results.push(['Case C: senior officer $60k permits', v.isPermit]);
  results.push(['Case C: Disbursement verifies', verifyOkC]);

  // -----------------------------------------------------------------
  // Case D: senior officer over their tier.
  // -----------------------------------------------------------------
  console.log('-'.repeat(70));
  console.log('Case D: senior officer Vikram tries $400,000.');
  console.log('-'.repeat(70));
  console.log('$400k is over the senior tier\'s $250k cap. The committee');
  console.log("rule would accept it ($1M cap) but Vikram doesn't carry");
  console.log('that role. No rule matches, default deny.');
  console.log();

  v = gate.evaluate(loanCtx('officer-vikram', ['senior_officer'], 400000.0));
  console.log(`Underwriting verdict: ${v.kind}`);
  console.log(`Is refuse:            ${v.isRefuse}`);
  console.log(`Evaluator:            ${v.evaluator}`);
  console.log(`Code:                 ${v.code}`);
  console.log();

  const okD = v.isRefuse && v.evaluator === 'policy';
  results.push(['Case D: senior officer $400k refused on tier', okD]);

  // -----------------------------------------------------------------
  // Case E: committee chair, $900k.
  // -----------------------------------------------------------------
  console.log('-'.repeat(70));
  console.log('Case E: committee chair Amara approves a $900,000 SMB loan.');
  console.log('-'.repeat(70));
  console.log('Committee chair caps at $1,000,000. $900k is under. Invariant');
  console.log('is $1.5M, also fine. Permits and signs. Disbursement verifies.');
  console.log();

  v = gate.evaluate(loanCtx('chair-amara', ['committee_chair'], 900000.0));
  console.log(`Underwriting verdict: ${v.kind}`);
  console.log(`Is permit:            ${v.isPermit}`);
  const permitE = v.permitToken;
  let verifyOkE = false;
  if (permitE != null && permitE.signature != null) {
    try {
      verifier.verify(
        {
          tokenId: permitE.tokenId,
          evaluationId: permitE.evaluationId,
          issuedAt: permitE.issuedAt,
          expiresAt: permitE.expiresAt,
          actionName: permitE.actionName,
        },
        Buffer.from(permitE.signature),
      );
      verifyOkE = true;
      console.log('Disbursement.verify(): accepted.');
    } catch (e) {
      const err = e as Error;
      console.log(`Disbursement.verify() raised unexpectedly: ${err.name}: ${err.message}`);
    }
  }
  console.log();

  results.push(['Case E: committee chair $900k permits', v.isPermit]);
  results.push(['Case E: Disbursement verifies', verifyOkE]);

  // -----------------------------------------------------------------
  // Case F: policy permits, invariant refuses.
  // -----------------------------------------------------------------
  console.log('-'.repeat(70));
  console.log('Case F: loose rule permits $1.6M, but the invariant refuses.');
  console.log('-'.repeat(70));
  console.log('We build a separate gate whose committee rule caps at $2,000,000');
  console.log('(a config mistake that somehow made it past review). The same');
  console.log('regulator invariant of $1.5M is wired in. A $1,600,000 loan');
  console.log('would permit at the policy stage but must refuse at the');
  console.log('invariant. This is the safety net property: a too-permissive');
  console.log('policy cannot override a regulator invariant.');
  console.log();

  const LOOSE_POLICIES = {
    policies: [
      {
        name: 'loose_committee_rule',
        description: 'Misconfigured rule (demo only): chairs up to $2M',
        effect: 'permit',
        priority: 10,
        conditions: [
          { identity_role: 'committee_chair' },
          { action: 'loan.approve' },
          { param_max: { field: 'amount_usd', max: 2000000.0 } },
        ],
      },
    ],
  };
  const looseGate = Gate.fromObject(LOOSE_POLICIES, {
    invariants: INVARIANTS,
    tokenSigner: signer,
  });
  v = looseGate.evaluate(loanCtx('chair-amara', ['committee_chair'], 1600000.0));
  console.log(`Verdict kind: ${v.kind}`);
  console.log(`Is refuse:    ${v.isRefuse}`);
  console.log(`Evaluator:    ${v.evaluator}`);
  console.log(`Reason:       ${v.reason}`);
  console.log();

  const okF =
    v.isRefuse &&
    v.evaluator === 'invariants' &&
    (v.reason ?? '').includes('regulator_single_loan_cap');
  results.push(['Case F: loose policy permits, invariant refuses', okF]);

  // -----------------------------------------------------------------
  // Case G: wire tamper, flip the action name on a real permit.
  // -----------------------------------------------------------------
  console.log('-'.repeat(70));
  console.log("Case G: attacker tampers Case A's permit on the wire.");
  console.log('-'.repeat(70));
  console.log('The attacker captures the real $40,000 permit issued to');
  console.log('officer Meera, keeps the signature bytes and every field');
  console.log('other than action_name intact, then relabels the permit');
  console.log("from 'loan.approve' to 'loan.approve_mega' (a made up");
  console.log('privilege). Disbursement recomputes the canonical bytes,');
  console.log('finds that the signature does not cover them, and refuses.');
  console.log('This is what stops an attacker from forwarding a real small');
  console.log('permit as authorisation for a larger or differently named');
  console.log('action.');
  console.log();

  if (caseAPermit == null || caseAPermit.signature == null) {
    console.log('  expected Case A permit for Case G, aborting.');
    return 1;
  }

  const tampered: PermitTokenInput = {
    tokenId: caseAPermit.tokenId,
    evaluationId: caseAPermit.evaluationId,
    issuedAt: caseAPermit.issuedAt,
    expiresAt: caseAPermit.expiresAt,
    actionName: 'loan.approve_mega',
  };
  console.log(`  original action_name: ${caseAPermit.actionName}`);
  console.log(`  tampered action_name: ${tampered.actionName}`);
  let tamperRefused = false;
  let tamperMsg = '';
  try {
    verifier.verify(tampered, Buffer.from(caseAPermit.signature));
  } catch (e) {
    tamperRefused = true;
    tamperMsg = (e as Error).message;
  }
  console.log(`  Disbursement.verify() raised: ${tamperRefused}`);
  console.log(`  message (first 180 chars): ${tamperMsg.slice(0, 180)}`);
  console.log();

  results.push(['Case G: wire tamper refused', tamperRefused]);

  // -----------------------------------------------------------------
  // Summary
  // -----------------------------------------------------------------
  console.log('='.repeat(70));
  console.log('Summary');
  console.log('='.repeat(70));
  const passed = results.filter(([, ok]) => ok).length;
  for (const [label, ok] of results) {
    const mark = ok ? 'PASS' : 'FAIL';
    console.log(`  [${mark}] ${label}`);
  }
  console.log();
  console.log(`${passed}/${results.length} checks passed.`);
  console.log();

  return passed === results.length ? 0 : 1;
}

process.exit(main());

//! INV-19 guard: the icaptcha flow must actually call the service (consume the
//! mock), not short-circuit or make a live call. If a future change let
//! `obtain_proof` skip the network (e.g. a stray `cfg(test)` relaxation, which
//! INV-19/INV-20 warn is inert across crates), the `.assert()` calls below go
//! RED because the mocked endpoints were never hit.

use icaptcha_client::{obtain_proof, Challenge, IcaptchaCfg};

#[test]
fn obtain_proof_consumes_the_mocked_service_and_makes_no_live_call() {
    let mut server = mockito::Server::new();

    // The two endpoints the flow hits, each expected exactly once.
    let challenge = server
        .mock("POST", "/v1/challenge")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            r#"{"challengeId":"c1","type":"anagram","difficulty":1,"prompt":"listen","token":"tok-1"}"#,
        )
        .expect(1)
        .create();

    let answer = server
        .mock("POST", "/v1/answer")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"status":"passed","proof":"PROOF-XYZ"}"#)
        .expect(1)
        .create();

    let cfg = IcaptchaCfg {
        url: server.url(),
        did: "did:key:zTEST".to_string(),
        level: 1,
        api_key: None,
    };

    // "anagram" is not a built-in solvable type, so the flow consults this
    // solver callback. The answer body itself does not matter: the mocked
    // /v1/answer returns "passed" regardless of what is submitted.
    let solve = |_c: &Challenge| Some("silent".to_string());
    let solver: &dyn Fn(&Challenge) -> Option<String> = &solve;

    let proof = obtain_proof(&cfg, Some(solver))
        .expect("obtain_proof should complete against the mocked service");
    assert_eq!(proof, "PROOF-XYZ");

    // INV-19: prove the client actually called the mocked endpoints. Had it made
    // a live call or skipped the network, these would fail (mock never hit).
    challenge.assert();
    answer.assert();
}

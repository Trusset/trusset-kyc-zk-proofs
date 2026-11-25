//! What the 3.1.0 prover refuses before it proves anything: clear-text
//! personal values, a missing or unusable chain block, predicates no circuit
//! establishes, and a subject without exactly one investor-class leaf.

mod common_v31;

use common_v31::*;
use trusset_prover::bundle::dry_run_subject;
use trusset_prover::errors::ErrorCode;
use trusset_prover::job::Job;

fn fixture() -> Job {
    job("/nonexistent")
}

fn refused(job: &Job) -> ErrorCode {
    job.validate().expect_err("job should be refused").code
}

fn dry_codes(job: &Job) -> Vec<ErrorCode> {
    dry_run_subject(job, &job.subjects[0])
        .into_iter()
        .map(|p| p.code)
        .collect()
}

#[test]
fn the_fixture_is_accepted_and_dry_runs_clean() {
    let job = fixture();
    job.validate().unwrap();
    assert!(dry_codes(&job).is_empty());
}

#[test]
fn clear_text_country_or_investor_type_is_refused() {
    for key in ["country", "investorType", "nationality"] {
        let mut job = fixture();
        job.subjects[0].passthrough[key] = serde_json::json!("DEU");
        assert_eq!(refused(&job), ErrorCode::PassthroughRefused, "{}", key);
    }
    let mut job = fixture();
    job.subjects[0].passthrough["softExpiryDays"] = serde_json::json!("365");
    assert_eq!(refused(&job), ErrorCode::PassthroughRefused);
}

#[test]
fn the_chain_block_is_required_and_checked() {
    let mut job = fixture();
    job.chain = None;
    assert_eq!(refused(&job), ErrorCode::ChainInvalid);

    let zero = "0x0000000000000000000000000000000000000000";
    type Mutation = Box<dyn Fn(&mut Job)>;
    let cases: Vec<Mutation> = vec![
        Box::new(|j| j.chain.as_mut().unwrap().hub = zero.into()),
        Box::new(|j| j.chain.as_mut().unwrap().attester = zero.into()),
        Box::new(|j| j.chain.as_mut().unwrap().attester = "0x1234".into()),
        Box::new(|j| j.chain.as_mut().unwrap().chain_id = 0),
        Box::new(|j| j.chain.as_mut().unwrap().key_id = 0),
    ];
    for mutate in cases {
        let mut job = fixture();
        mutate(&mut job);
        assert_eq!(refused(&job), ErrorCode::ChainInvalid);
    }

    let mut dry = fixture();
    dry.chain = None;
    dry.dry_run = true;
    dry.validate()
        .expect("a dry run writes no header and needs no chain");
}

#[test]
fn exactly_one_investor_class_leaf() {
    let mut none = fixture();
    none.subjects[0]
        .leaves
        .retain(|l| l.field != "investorType");
    assert_eq!(refused(&none), ErrorCode::PredicateInvalid);

    let mut two = fixture();
    let mut copy = two.subjects[0]
        .leaves
        .iter()
        .find(|l| l.field == "investorType")
        .unwrap()
        .clone();
    copy.field = "investorType@ATTESTED".into();
    two.subjects[0].leaves.push(copy);
    assert_eq!(refused(&two), ErrorCode::PredicateInvalid);
}

#[test]
fn process_predicates_cannot_name_a_leaf() {
    for name in [
        "KYC_DONE",
        "AML_CLEAR",
        "NOT_US_PERSON",
        "CONTRACT_HOLDER",
        "MADE_UP",
    ] {
        let mut job = fixture();
        job.subjects[0].leaves[0].predicate = Some(name.into());
        assert_eq!(refused(&job), ErrorCode::PredicateInvalid, "{}", name);
    }
}

#[test]
fn a_leaf_without_a_descriptor_is_refused() {
    let mut job = fixture();
    job.subjects[0].leaves[3].descriptor = None;
    job.subjects[0].leaves[3].validity = None;
    assert_eq!(refused(&job), ErrorCode::DescriptorMissing);
}

#[test]
fn predicates_must_match_their_circuit_and_parameters() {
    let mut weak_adult = fixture();
    let leaf = &mut weak_adult.subjects[0].leaves[0];
    leaf.public = serde_json::json!({"min_age_days": 3650u64});
    leaf.params = Some(serde_json::json!({"minAgeDays": 3650u64}));
    leaf.params_hash = hex32(trusset_circuit_age_threshold::Params { min_age_days: 3650 }.hash());
    assert_eq!(dry_codes(&weak_adult), vec![ErrorCode::PredicateInvalid]);

    let mut adult_on_tier = fixture();
    adult_on_tier.subjects[0].leaves[2].predicate = Some("ADULT".into());
    assert!(dry_codes(&adult_on_tier).contains(&ErrorCode::PredicateInvalid));

    let mut eea_on_commitment = fixture();
    eea_on_commitment.subjects[0].leaves[3].predicate = Some("RESIDENCY_ON_FILE".into());
    assert_eq!(
        dry_codes(&eea_on_commitment),
        vec![ErrorCode::PredicateInvalid]
    );
}

#[test]
fn a_non_member_fails_the_eea_leaf() {
    let mut job = fixture();
    job.subjects[0].leaves[1].value = serde_json::json!("CHE");
    assert_eq!(dry_codes(&job), vec![ErrorCode::ListMemberMissing]);
}
